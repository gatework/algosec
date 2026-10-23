# frozen_string_literal: true

require_relative "generator"
require_relative "plan"
require_relative "time_verification"
require_relative "nat/verification"

module Algosec
  module Policy
    # 将明确选择的同链规则收敛到最前一条，整批证明所有流量行为保持不变。
    class Convergence
      def initialize(snapshot, at: Time.current, proof_limit: TrafficSet::DEFAULT_LIMIT)
        raise ArgumentError, "收敛需要配置快照" unless snapshot.is_a?(Snapshot)
        raise ArgumentError, "证明预算必须为正整数" unless proof_limit.is_a?(Integer) && proof_limit.positive?
        @snapshot, @at, @proof_limit = snapshot, at.dup.freeze, proof_limit
      end

      def perform(rule_ids:)
        selected = select_rules(rule_ids)
        changes = []
        begin
          @snapshot.require_complete!
          @snapshot.catalog.seal!
          @snapshot.builtin_services.each(&:seal!)
          validate_group!(selected)
          selected = RuleOrder.new(@snapshot.behavior, require_number: true).resolve(selected)
          survivor, *removed = selected
          traffic = selected.map { |rule| traffic(rule) }
          union = traffic.reduce(TrafficSet.new([], limit: @proof_limit), :|)
          changes = [ { operation: :converge, rule_id: survivor.rule_id,
            removed_rule_ids: removed.map(&:rule_id), traffic: ChangeSet.traffic_document(union) } ]
          results = union.cover?(traffic.first) && traffic.first.cover?(union) ? [] : [ merge_result(survivor, union) ]
          generated = @snapshot.definition.generator.new(snapshot: @snapshot).render(results, remove_rules: removed)
          change_set = ChangeSet.new(snapshot: @snapshot, intents: generated.entries.flat_map(&:intents),
            targets: [], at: @at, proof_limit: @proof_limit)
          proof = change_set.verify
          effects = {}
          issues = generated.entries.flat_map(&:issues)
          if proof.verified? && issues.empty?
            effects[:time] = TimeVerification.new(change_set: change_set) if change_set.required_effects.include?(:time)
            effects[:nat] = Nat::Verification.unchanged(change_set: change_set) if change_set.required_effects.include?(:nat)
            issues.concat(effects.values.flat_map(&:issues))
          end
          Plan.new(operation: :converge, snapshot: @snapshot, changes: changes, commands: generated.text,
            issues: issues, change_set: change_set, proof: proof, effect_proofs: effects)
        rescue Error, ArgumentError => error
          code = error.is_a?(TrafficSet::LimitExceeded) ? :proof_budget_exceeded : (error.respond_to?(:code) ? error.code : :unsupported_convergence)
          Plan.new(operation: :converge, snapshot: @snapshot, changes: changes, commands: nil,
            issues: [ Finding.new(check: :convergence, rule_id: nil, status: :unknown, severity: :critical,
              message: error.message, evidence: { code: code }) ])
        end
      end
      alias plan perform

      private

      def select_rules(ids)
        unless ids.is_a?(Array) && ids.all? { |id| id.is_a?(String) } && ids.uniq.size >= 2 && ids.uniq.size == ids.size
          raise ArgumentError, "收敛需要至少两条不同的明确规则身份"
        end
        indexed = @snapshot.rules.group_by(&:rule_id)
        ids.map do |id|
          matches = indexed[id]
          raise ArgumentError, "规则不存在或身份不唯一：#{id}" unless matches&.one?
          matches.first
        end
      end

      def validate_group!(rules)
        scopes = rules.map { |rule| [ @snapshot.behavior.rule_chain(rule), @snapshot.behavior.rule_scope(rule) ] }
        raise Error.new("收敛规则必须属于同一执行链和作用域", code: :incompatible_scope) unless scopes.uniq.one?
        raise Error.new("收敛规则的动作、日志或其他语义条件不同", code: :incompatible_metadata) unless rules.map { |rule| metadata(rule) }.uniq.one?
        raise Error.new("内嵌 NAT 规则需要单独处理转换依赖", code: :nat_dependency) if rules.any?(&:nat?)
      end

      def metadata(rule)
        comparison = ChangeSet::DeclarationComparison.new(@snapshot, @snapshot)
        [ rule.action, rule.log, rule.log_enabled, rule.status, rule.applications, rule.source_users,
          rule.service_selection, rule.semantic_conditions, rule.from_interface, rule.dst_interfaces,
          rule.vendor_data, rule.schedule_name, rule.schedule && comparison.declaration_digest(rule.schedule) ]
      end

      # 只暂时移除时间谓词以构造潜在并集，实际候选保留原条件并交给时间证明。
      def traffic(rule)
        untimed = rule.with(schedule: nil, schedule_name: nil,
          conditions: rule.semantic_conditions.except("starts_at", "expires_at"), unparsed_commands_metadata: rule.unparsed_commands_metadata).seal!
        predicate = Evaluation::Predicate.new(@snapshot, untimed, at: @at, domains: {},
          application: nil, source_user: nil, application_definitions: {})
        partitions = predicate.partitions(TrafficSet.universe(limit: @proof_limit))
        unless partitions.any? && partitions.all? { |part| part.status == :matched }
          raise Error.new("规则含有尚未证明的完整匹配条件", code: :unsupported_conditions)
        end
        partitions.reduce(TrafficSet.new([], limit: @proof_limit)) { |all, part| all | part.traffic_set }
      end

      # 生成器只接收已证明为一个原生规则可表示的精确并集；交叉配对不能投影成乘积。
      def merge_result(survivor, union)
        maps = generation_maps(union)
        product = Request::Traffic.from_maps(maps)
        unless union.cover?(product) && product.cover?(union)
          raise Error.new("所选规则的精确并集不能用同一规则表示", code: :non_rectangular_union)
        end
        pairs = @snapshot.behavior.proof_zone_pairs(survivor)
        unless pairs.one? && pairs.first.all? { |zones| zones&.one? && zones.first.downcase != "any" }
          raise Error.new("原生成员追加需要唯一的实际区域对", code: :unsupported_generation_scope)
        end
        from, to = pairs.first.map(&:first)
        original = Ranges.projection(survivor)
        additions = maps.to_h do |dimension, values|
          values = values.reject do |value, _|
            set = dimension == :services ? Ranges.service(value) : IPAddr.parse(value)
            original.fetch(dimension).cover?(set)
          end
          [ dimension, values.transform_values { nil } ]
        end
        Result.new(device_id: @snapshot.device_id, device_name: "device-#{@snapshot.device_id}",
          vendor: @snapshot.vendor, from_zone: from, to_zone: to, snapshot: @snapshot,
          rule: survivor, type: :modify, hit: :source, **maps, actions: { add: additions }, evaluated_at: @at)
      end

      def generation_maps(union)
        universe = { sources: { "0.0.0.0/0" => {} }, destinations: { "0.0.0.0/0" => {} }, services: { "any" => {} } }
        Request::Traffic.slices(union, universe).each_with_object(Result::DIMENSIONS.to_h { |dimension| [ dimension, {} ] }) do |slice, maps|
          slice.each { |dimension, values| maps.fetch(dimension).merge!(values) }
        end
      end
    end
  end
end
