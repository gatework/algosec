# frozen_string_literal: true

require_relative "analysis"
require_relative "plan"
require_relative "rule_coverage"
require_relative "usage_observation"
require_relative "time_verification"
require_relative "nat/verification"

module Algosec
  module Policy
    # 无效规则判定和显式选择后的回收计划；共享对象及 NAT 不随规则删除。
    class Reclaimer < Analysis
      check :disabled, severity: :info, message: "规则已禁用", remediation: :remove_rule do |view|
        view.disabled?
      end
      check :expired, severity: :info, message: "规则的时间计划已过期", remediation: :remove_rule do |view|
        view.expired?
      end
      check :covered, message: "规则被前序规则完全覆盖", using: :covered, remediation: :remove_rule
      check :unused, severity: :info, message: "完整观测窗口内未命中，需单独审批行为变更", using: :unused

      def initialize(snapshot, at: Time.current, facts: {}, usage_observations: [], usage_window: nil, proof_limit: TrafficSet::DEFAULT_LIMIT)
        super(snapshot, at: at, facts: facts)
        unless usage_observations.is_a?(Array) && usage_observations.all? { |item| item.is_a?(UsageObservation) }
          raise ArgumentError, "使用证据必须是 UsageObservation 数组"
        end
        unless usage_observations.map(&:rule_identity).uniq.size == usage_observations.size
          raise ArgumentError, "同一规则只能提供一份当前使用证据"
        end
        raise ArgumentError, "证明预算必须为正整数" unless proof_limit.is_a?(Integer) && proof_limit.positive?
        if usage_window
          unless usage_window.is_a?(Hash) && usage_window.keys.sort == %i[window_end window_start] &&
              usage_window.values.all? { |time| time.is_a?(Time) || time.is_a?(ActiveSupport::TimeWithZone) } &&
              usage_window[:window_start] < usage_window[:window_end] && usage_window[:window_end] <= at
            raise ArgumentError, "使用证据需要完整的历史观测窗口"
          end
        elsif !usage_observations.empty?
          raise ArgumentError, "使用证据缺少要求的观测窗口"
        end
        @observations, @usage_window = usage_observations.dup.freeze, Value.immutable(usage_window)
        @proof_limit = proof_limit
        @coverage = RuleCoverage.new(snapshot, at: at, proof_limit: proof_limit)
      end

      # 重新分析当前快照，防止用户选择后规则已改变；未解决项阻止整份脚本发布。
      def plan(rule_ids:)
        unless rule_ids.is_a?(Array) && rule_ids.all? { |id| id.is_a?(String) }
          raise ArgumentError, "回收需要明确的规则身份数组"
        end
        assessment = perform
        unless @snapshot.complete?
          return Plan.new(operation: :reclaim, snapshot: @snapshot, changes: [], issues: assessment.unknowns)
        end
        rules = @snapshot.rules.to_h { |rule| [ @snapshot.signature(rule), rule ] }
        selected = rule_ids.uniq.map { |id| rules.fetch(id) { raise ArgumentError, "规则不存在：#{id}" } }
        changes, issues = [], []
        selected.each do |rule|
          id = @snapshot.signature(rule)
          reasons = assessment.violations.select { |finding| finding.rule_id == id && finding.remediation == :remove_rule }
          if reasons.empty?
            issues << issue(id, "当前规则没有可回收的判定依据", :not_reclaimable)
          elsif nat_reference?(rule)
            issues << issue(id, "规则仍关联 NAT，需单独处理依赖", :nat_dependency)
          else
            changes << { rule_id: id, operation: :remove_rule, reasons: reasons.map { |finding| { check: finding.check, evidence: finding.evidence } } }
          end
        end
        commands = ""
        if issues.empty? && !selected.empty?
          begin
            commands = @snapshot.definition.generator.new(snapshot: @snapshot).generate_operation(:remove_rule, selected)
          rescue Error, ArgumentError => error
            issues << issue(nil, error.message, error.respond_to?(:code) ? error.code : :unsupported_operation)
          end
        end
        intents = selected.map { |rule| ChangeSet::Intent.delete(rule_id: rule.rule_id) }
        change_set = ChangeSet.new(snapshot: @snapshot, intents: intents, targets: [], at: @at, proof_limit: @proof_limit)
        proof = change_set.verify
        effects = {}
        if proof.verified? && issues.empty?
          effects[:time] = TimeVerification.new(change_set: change_set) if change_set.required_effects.include?(:time)
          effects[:nat] = Nat::Verification.unchanged(change_set: change_set) if change_set.required_effects.include?(:nat)
        end
        Plan.new(operation: :reclaim, snapshot: @snapshot, changes: changes, issues: issues, commands: commands,
          change_set: change_set, proof: proof, effect_proofs: effects)
      end

      private

      # 同一求值器证明联合覆盖，删除计划另行验证整个批次及所有未来时间段。
      def covered(view, _context)
        return false unless view.enabled?
        view.unknown!("配置缺少规则执行顺序", :unknown_order) unless view.rule_number
        @coverage.call(view.rule)
      end

      def unused(view, _context)
        return false unless @usage_window
        matching = @observations.select { |observation| observation.rule_identity == view.rule.identity }
        return false if matching.empty?
        observation = matching.find { |item| item.unused_for?(rule_identity: view.rule.identity, **@usage_window) }
        return { observation: observation.to_h, requested_window: @usage_window.transform_values { |time| time.iso8601(9) } } if observation
        return false if matching.any? { |item| item.hits.positive? }
        view.unknown!("零命中证据不完整、计数已重置或窗口不足", :incomplete_usage)
      end

      # 内嵌 NAT 和用于转换匹配的 ACL 都是独立依赖，不能隐式拆除。
      def nat_reference?(rule)
        return true if rule.nat?
        (@snapshot.static_nats + @snapshot.dynamic_nats).any? do |nat|
          (nat.respond_to?(:match_rule) && nat.match_rule.equal?(rule)) ||
            (nat.respond_to?(:policy_id) && nat.policy_id && nat.policy_id == rule.native_rule_id) ||
            (nat.respond_to?(:acl_name) && nat.acl_name && nat.acl_name == rule.rule_set)
        end
      end

      def issue(id, message, code)
        Finding.new(check: :reclaim, rule_id: id, status: :unknown, severity: :critical,
                    message: message, evidence: { code: code })
      end
    end
  end
end
