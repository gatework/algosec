# frozen_string_literal: true

require_relative "report"
require_relative "generator"
require_relative "plan"
require_relative "time_verification"

module Algosec
  module Policy
    # 按设备规划一次查询；计划和预览共享同一生成产物及配置基线。
    class Planner
      Batch = Data.define(:script, :plan)
      private_constant :Batch

      def initialize(report)
        raise ArgumentError, "策略规划必须使用查询报告" unless report.is_a?(Report)
        @report = report
      end

      # 保留逐结果的展示结构，名称及命令均来自实际生成产物。
      def perform
        batches.map do |batch|
          first = batch.script.entries.first.result
          states = batch.script.entries.map { |entry| policy_state(entry) }.uniq
          { device_id: first.device_id, device_name: first.device_name, vendor: first.vendor,
            policy_contents: batch.script.entries.map { |entry| content(entry) },
            policy_state: states.one? ? states.first : :part_exist }
        end
      end

      # 每台设备只有一份完整批次，保持设备首次出现顺序。
      def plans = batches.map(&:plan)

      private

      def batches
        return @batches if @batches
        raise Error, "不能根据失败的查询生成策略：#{@report.comment}" unless @report.success?
        unless @report.complete?
          raise Error.new("查询未完整评估需求，不能生成部分策略", code: :incomplete_query)
        end

        @batches = @report.results.group_by(&:device_id).map do |_device_id, results|
          snapshot = results.first.snapshot
          unless results.all? { |result| result.snapshot.equal?(snapshot) }
            raise Error.new("同设备规划不能混用不同配置快照", code: :mixed_snapshots)
          end
          script = results.first.definition.build_generator(results.first).render(results)
          intents = script.entries.flat_map(&:intents)
          targets = results.map do |result|
            ChangeSet::Target.new(traffic_set: result.traffic_set, action: result.decision == :permit ? "allow" : "deny",
              from_zone: result.from_zone, to_zone: result.to_zone, effective_window: result.schedule)
          end
          at = results.filter_map(&:evaluated_at).min || Time.current
          change_set = ChangeSet.new(snapshot: snapshot, intents: intents, targets: targets, at: at)
          issues = script.entries.flat_map(&:issues)
          effects = results.flat_map do |result|
            required = []
            required << :time if result.schedule
            if result.rule&.nat? || result.snapshot.nat_rules.any? || result.actions&.values&.any? { |members| (members.keys & %i[nat_sources nat_destinations]).any? } ||
                Result::DIMENSIONS.any? { |dimension| result.public_send(dimension).values.any? { |entry| entry[:nat] || entry[:translated_port] } }
              required << :nat
            end
            required
          end.uniq | change_set.required_effects
          effect_proofs = {}
          if effects.include?(:time)
            effect_proofs[:time] = TimeVerification.new(change_set: change_set)
            issues.concat(effect_proofs[:time].issues)
          end
          if effects.include?(:nat)
            begin
              effect_proofs[:nat] = Nat::Generation.proof(snapshot: snapshot, entries: script.entries, change_set: change_set)
              issues.concat(effect_proofs[:nat].issues)
            rescue Error, ArgumentError => error
              issues << Finding.new(check: :nat_effect_proof, rule_id: nil, status: :unknown, severity: :critical,
                message: error.message, evidence: { code: error.is_a?(Error) ? error.code : :unsupported_nat_proof })
            end
          end
          plan = Plan.new(operation: :configure, snapshot: snapshot, change_set: change_set,
            issues: issues, required_effects: effects, effect_proofs: effect_proofs, changes: results.map { |result| change(result) }, commands: script.text)
          Batch.new(script: script, plan: plan)
        end.freeze
      end

      def change(result)
        { operation: result.type, rule_id: result.rule&.rule_id,
          from_zone: result.from_zone, to_zone: result.to_zone,
          sources: result.sources.keys, destinations: result.destinations.keys,
          services: result.services.keys,
          schedule: result.schedule && { start_at: result.schedule.start_at.iso8601, end_at: result.schedule.end_at.iso8601, time_zone: "UTC" },
          actions: result.actions, conflicting_rules: conflicting_rules(result) }
      end

      def policy_state(entry)
        # 复用已有策略时仍可能新增 NAT，不能把 :ignore 等同于无变更。
        return :part_exist if entry.result.type == :ignore && !entry.text.empty?
        { ignore: :all_exist, modify: :part_exist, new: :non_exist }.fetch(entry.result.type)
      end

      def content(entry)
        result = entry.result
        generated = { content: entry.text }
        unless result.type == :ignore && entry.text.empty?
          entry.references.each { |dimension, names| generated[dimension] = names.sort.join(",") }
        end
        existing = result.existing ? Value.copy(result.existing).merge(content: result.rule.config) : {}
        { sources: Value.copy(result.sources), destinations: Value.copy(result.destinations),
          services: Value.copy(result.services), new: generated, existing: existing,
          conflicting_rules: conflicting_rules(result) }
      end

      def conflicting_rules(result)
        result.conflicting_rules.map { |rule| { **rule.locator, name: rule.name, action: rule.action, content: rule.config } }
      end
    end
  end
end
