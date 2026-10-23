# frozen_string_literal: true

require_relative "plan"
require_relative "request/traffic"
require_relative "rule_matcher"
require_relative "generator"
require_relative "time_verification"
require_relative "nat/verification"

module Algosec
  module Policy
    # 迁移源端真正生效的流量分区；目标原生落位与范围外行为由同一变更集证明。
    class Migration
      def initialize(source:, target:, zones:, device_name: "migration", source_zone_pairs: nil, at: Time.current)
        unless source.is_a?(Snapshot) && target.is_a?(Snapshot) && zones.is_a?(Hash)
          raise ArgumentError, "迁移需要源、目标配置快照及区域映射"
        end
        @source, @target, @at = source, target, at.dup.freeze
        @zones = Value.immutable(zones.to_h do |from, to|
          [ Value.text(from, label: "源区域"), Value.text(to, label: "目标区域") ]
        end)
        unless source_zone_pairs.nil? || (source_zone_pairs.is_a?(Array) && source_zone_pairs.any? && source_zone_pairs.all? { |pair| pair.is_a?(Array) && pair.size == 2 && pair.all? { |zone| zone.is_a?(String) && !zone.empty? } })
          raise ArgumentError, "源迁移范围必须为明确的区域对数组"
        end
        @source_zone_pairs = source_zone_pairs && Value.immutable(source_zone_pairs.uniq)
        @device_name = Value.text(device_name, label: "目标设备名")
      end

      def perform
        changes, issues, effects = [], [], {}
        commands = change_set = proof = nil
        begin
          [ @source, @target ].each(&:require_complete!)
          validate_context!
          rules = ordinary_rules
          raise Error.new("源配置没有可迁移的普通策略", code: :no_migratable_policy) if rules.empty?
          rules = scoped_rules(rules)
          rules.each do |rule|
            begin
              validate_rule!(rule)
              changes << { source_rule_id: rule.rule_id, action: rule.action, decision: decision(rule),
                log: rule.log, log_enabled: rule.log_enabled, source_zone_pairs: source_pairs(rule),
                scope_requested: !@source_zone_pairs.nil?, results: [] }
            rescue Error, ArgumentError => error
              issues << issue(rule.rule_id, error)
            end
          end
          if issues.empty?
            results, targets = translate(rules, changes)
            results.reverse! if policy.fetch(:placement) == :prepend
            generated = @target.definition.generator.new(snapshot: @target).render(results)
            commands = generated.text
            issues.concat(generated.entries.flat_map(&:issues))
            change_set = ChangeSet.new(snapshot: @target, intents: generated.entries.flat_map(&:intents), targets: targets, at: @at)
            proof = change_set.verify
            if egress_scope_changed?(proof, targets)
              issues << issue(nil, Error.new("目标入口策略无法保持所要求的出口区域范围", code: :unsupported_zone_scope))
            end
            if proof.verified? && issues.empty?
              effects[:time] = TimeVerification.new(change_set: change_set) if change_set.required_effects.include?(:time)
              effects[:nat] = Nat::Verification.unchanged(change_set: change_set, require_untranslated: true) if change_set.required_effects.include?(:nat)
              issues.concat(effects.values.flat_map(&:issues))
            end
          end
        rescue Error, ArgumentError => error
          issues << issue(nil, error)
        end
        Plan.new(operation: :migrate, snapshot: @target, source: @source, changes: changes, issues: issues,
          commands: commands, change_set: change_set, proof: proof, effect_proofs: effects)
      end

      private

      def policy = @target.definition.generator.declarations.fetch(:command_policy).options

      def egress_scope_changed?(proof, targets)
        behavior = @target.behavior
        proof.differences.any? do |difference|
          difference.kind == :outside_target && targets.any? do |target|
            behavior.proof_context(target.context) == behavior.proof_context(difference.context) &&
              !target.covers_context?(difference.context, behavior: behavior) &&
              !(target.traffic_set & difference.traffic_set).empty?
          end
        end
      end

      def validate_context!
        unless @zones.values.uniq.size == @zones.size
          raise Error.new("多个源区域不能隐式合并到同一目标区域", code: :ambiguous_zone_mapping)
        end
        unless @source.nat_rules.empty? && @source.rules.none?(&:nat?)
          raise Error.new("源 NAT 需要专用原始流量与转换关系迁移", code: :unsupported_nat_migration)
        end
        unless @target.definition.generator.declarations.key?(:command_policy)
          raise Error.new("目标厂商未声明策略动作及插入顺序", code: :unsupported_migration)
        end
      end

      # PAN 原生默认规则属于规则库基线，不作为普通用户策略扩大迁移范围。
      def ordinary_rules
        @source.rules.reject { |rule| @source.behavior.terminal_rule?(rule) }
          .sort_by { |rule| [ rule.rule_number || 0, rule.rule_id ] }
      end

      # 范围属于整次迁移；不同原生 ACL 可以分别覆盖调用者请求的不同区域对。
      def scoped_rules(rules)
        return rules unless @source_zone_pairs
        bindings = rules.to_h { |rule| [ rule, source_pairs(rule) ] }
        if (@source_zone_pairs - bindings.values.flatten(1)).any?
          raise Error.new("请求迁移范围没有对应的源策略区域绑定", code: :missing_migration_scope)
        end
        bindings.filter_map { |rule, pairs| rule if pairs.any? }
      end

      def validate_rule!(rule)
        raise Error.new("禁用或过期规则需先明确清理", code: :inactive_rule) if rule.disabled? || rule.expired?(at: @at)
        raise Error.new("规则开始时间需要原生映射", code: :unsupported_start_time) if rule.starts_at
        raise Error.new("规则到期时间需要原生映射", code: :unsupported_expiry) if rule.expires_at
        decision(rule)
        if rule.log || rule.log_enabled != policy[:logging_default]
          raise Error.new("目标没有等价的日志状态生成能力", code: :unsupported_logging)
        end
        if rule.schedule_name && !rule.schedule
          raise Error.new("源时间计划未完整解析", code: :unsupported_schedule)
        end
        if rule.schedule && (rule.schedule.kind != :once || !rule.schedule.resolved?)
          raise Error.new("仅支持完整的一次性时间计划迁移", code: :unsupported_schedule)
        end
        source_pairs(rule).each { |pair| pair.each { |zone| mapped_zone(zone) } }
      end

      # selector 是生成器原生命令键；匹配只依据规范动作，drop/reject/reset 不降级为 deny。
      def decision(rule)
        selector = policy.fetch(:actions).find { |_key, native| Elements::SecurityRule::ACTIONS[native] == rule.action }&.first
        raise Error.new("目标无法等价表达动作 #{rule.action || rule.native_action}", code: :unsupported_action) unless selector
        selector
      end

      def source_pairs(rule)
        pairs = @source.behavior.proof_zone_pairs(rule).flat_map do |from, to|
          unless from&.any?
            raise Error.new("源规则缺少明确区域", code: :missing_zone_mapping)
          end
          raise Error.new("区域组合超出证明预算", code: :proof_budget_exceeded) if from.size * (to&.size || 1) > TrafficSet::DEFAULT_LIMIT
          from.flat_map do |left|
            # 入站 ACL 不约束出站区域，只有调用者的明确范围才能限定这次条件迁移。
            if @source.behavior.proof_context(from_zone: left, to_zone: left)[:to_zone].nil?
              raise Error.new("入口策略迁移需要显式 source_zone_pairs 范围", code: :missing_migration_scope) unless @source_zone_pairs
              @source_zone_pairs.select { |source, _destination| source == left }
            else
              raise Error.new("源规则缺少明确区域", code: :missing_zone_mapping) unless to&.any?
              to.filter_map { |right| [ left, right ] if @source.behavior.rule_in_zones?(rule, from_zone: left, to_zone: right) }
            end
          end
        end.uniq
        return pairs & @source_zone_pairs if @source_zone_pairs
        raise Error.new("源规则没有可证明的区域绑定", code: :missing_zone_mapping) if pairs.empty?
        pairs
      end

      def mapped_zone(zone)
        raise Error.new("通配区域需要专用映射", code: :unsupported_zone) if zone.casecmp?("any")
        mapped = @zones[zone]
        raise Error.new("区域 #{zone} 缺少映射", code: :missing_zone_mapping) unless mapped
        raise Error.new("目标区域 #{mapped} 不存在", code: :missing_target_zone) unless @target.catalog.find(Elements::Zone, name: mapped)
        mapped
      end

      # 时间只在源投影中暂时移除；原生生成和目标证明均保留原窗口。
      def translate(rules, changes)
        projections = rules.to_h { |rule| [ rule.rule_id, rule.with(schedule: nil, schedule_name: nil).seal! ] }
        catalog = Elements::Catalog.new(@source.catalog.map { |element| projections.fetch(element.respond_to?(:rule_id) ? element.rule_id : nil, element) },
          vendor: @source.vendor, device_id: @source.device_id).seal!
        source = @source.with_catalog(catalog)
        contexts = rules.flat_map { |rule| source_pairs(rule) }.uniq
        raise Error.new("区域上下文超出证明预算", code: :proof_budget_exceeded) if contexts.size > TrafficSet::DEFAULT_LIMIT
        results, targets = [], []
        contexts.each do |from, to|
          selected = rules.select { |rule| source_pairs(rule).include?([ from, to ]) }
          ordered = RuleOrder.new(@source.behavior, require_number: true).resolve(selected)
          traffic = ordered.to_h { |rule| [ rule.rule_id, potential(source, projections.fetch(rule.rule_id)) ] }
          validate_temporal_overlap!(ordered, traffic)
          scope = traffic.values.reduce(TrafficSet.new, :|)
          evaluation = Evaluation.new(source, at: @at).perform(scope, from_zone: from, to_zone: to)
          unless evaluation.complete?
            raise Error.new("源有效分区含未知条件：#{evaluation.partitions.filter_map(&:reason).uniq.join('；')}", code: :unsupported_conditions)
          end
          evaluation.partitions.each do |partition|
            original = selected.find { |rule| rule.rule_id == partition.rule&.rule_id }
            raise Error.new("源有效分区缺少明确策略来源", code: :unsupported_source_default) unless original
            mapped = [ mapped_zone(from), mapped_zone(to) ]
            targets << ChangeSet::Target.new(traffic_set: partition.traffic_set, action: partition.action,
              from_zone: mapped.first, to_zone: mapped.last, effective_window: original.schedule,
              metadata: { log: original.log, log_enabled: original.log_enabled })
            generated = generation_results(partition.traffic_set, original, *mapped)
            results.concat(generated)
            changes.find { |change| change[:source_rule_id] == original.rule_id }[:results].concat(generated.map { |result| result_document(result) })
          end
        end
        [ results, targets ]
      rescue RuleOrder::Unproven => error
        raise Error.new(error.message, code: :unknown_order)
      end

      def potential(source, rule)
        partitions = Evaluation::Predicate.new(source, rule, at: @at, domains: {}, application: nil, source_user: nil,
          application_definitions: {}).partitions(TrafficSet.universe)
        unless partitions.any? && partitions.all? { |part| part.status == :matched }
          raise Error.new("源规则含尚未证明的完整匹配条件", code: :unsupported_conditions)
        end
        partitions.reduce(TrafficSet.new) { |all, part| all | part.traffic_set }
      end

      # 不同时间窗的先后规则需要额外时间差分；不能把当前未生效规则永久减去。
      def validate_temporal_overlap!(rules, traffic)
        rules.each_with_index do |earlier, index|
          next unless earlier.schedule
          rules.drop(index + 1).each do |later|
            next if earlier.schedule.window == later.schedule&.window
            next if (traffic.fetch(earlier.rule_id) & traffic.fetch(later.rule_id)).empty?
            raise Error.new("重叠流量具有不同源时间窗口，尚无精确迁移表达", code: :unsupported_temporal_overlap)
          end
        end
      end

      def generation_results(traffic, rule, from, to)
        universe = { sources: { "0.0.0.0/0" => {} }, destinations: { "0.0.0.0/0" => {} }, services: { "any" => {} } }
        slices = Request::Traffic.slices(traffic, universe)
        combined = slices.each_with_object(Result::DIMENSIONS.to_h { |dimension| [ dimension, {} ] }) do |slice, maps|
          slice.each { |dimension, values| maps.fetch(dimension).merge!(values) }
        end
        product = Request::Traffic.from_maps(combined)
        slices = [ combined ] if traffic.cover?(product) && product.cover?(traffic)
        matcher = RuleMatcher.new(@target, at: @at)
        slices.map do |maps|
          names = maps.to_h { |dimension, entries| [ dimension, matcher.names_for(dimension, entries, dimension == :sources ? from : to) ] }
          Result.new(device_id: @target.device_id, device_name: @device_name, vendor: @target.vendor,
            from_zone: from, to_zone: to, type: :new, hit: :source, **maps, schedule: rule.schedule,
            decision: decision(rule), source_rule_id: rule.rule_id, actions: { new: names }, snapshot: @target, evaluated_at: @at)
        end
      end

      def result_document(result)
        { from_zone: result.from_zone, to_zone: result.to_zone, sources: result.sources.keys,
          destinations: result.destinations.keys, services: result.services.keys,
          schedule: result.schedule && { start_at: result.schedule.start_at.iso8601, end_at: result.schedule.end_at.iso8601 } }
      end

      def issue(id, error)
        code = error.is_a?(TrafficSet::LimitExceeded) ? :proof_budget_exceeded : (error.respond_to?(:code) ? error.code : :unsupported_migration)
        Finding.new(check: :migration, rule_id: id, status: :unknown, severity: :critical,
          message: error.message, evidence: { code: code })
      end
    end
  end
end
