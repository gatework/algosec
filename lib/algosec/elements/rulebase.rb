# frozen_string_literal: true

require_relative "scope"
require_relative "security_rule"
require_relative "rule_binding"
require_relative "../policy/rule_order"

module Algosec
  module Elements
    # 同一执行上下文中的显式规则先行；默认动作只处理没有规则命中的流量。
    class Rulebase
      attr_reader :scope, :native_bindings, :from_zone, :to_zone, :rule_set

      def initialize(rules:, scope:, behavior:, from_zone:, to_zone:, native_bindings: [], rule_set: nil)
        unless rules.is_a?(Array) && rules.all? { |rule| rule.is_a?(SecurityRule) }
          raise ArgumentError, "Rulebase requires SecurityRule objects"
        end
        raise ArgumentError, "Rulebase scope must be a Scope" unless scope.is_a?(Scope)
        unless native_bindings.is_a?(Array) && native_bindings.all? { |binding| binding.is_a?(RuleBinding) }
          raise ArgumentError, "Rulebase bindings must be RuleBinding objects"
        end
        unless rule_set.nil? || rule_set.is_a?(String)
          raise ArgumentError, "Rulebase rule set must be text"
        end
        @rule_set = rule_set&.dup&.freeze
        @rules, @scope, @behavior = rules.dup.freeze, scope, behavior
        @from_zone, @to_zone = [ from_zone, to_zone ].map do |zone|
          raise ArgumentError, "Rulebase zones must be text" unless zone.is_a?(String)
          zone.dup.freeze
        end
        @native_bindings = native_bindings.dup.freeze
        freeze
      end

      def ordered_rules(at: nil)
        candidates = @rules.reject { |rule| known_inactive?(rule, at: at) }
                           .select { |rule| @behavior.rule_in_zones?(rule, from_zone: from_zone, to_zone: to_zone) }
        raise Policy::RuleOrder::Unproven.new(:chains) if candidates.map(&:scope).uniq.size > 1
        Policy::RuleOrder.new(@behavior).resolve(candidates).freeze
      end

      def default_action = @behavior.rulebase_default_action(from_zone: from_zone, to_zone: to_zone, rule_set: rule_set, scope: scope)

      # 调用方负责完整地址、服务、时间与应用谓词；未知谓词不能跳到默认允许。
      def first_match(at: nil)
        raise ArgumentError, "A complete match predicate is required" unless block_given?
        ordered_rules(at: at).find do |rule|
          matched = yield rule
          unless matched == true || matched == false
            raise Policy::Error.new("规则 #{rule.rule_id} 的完整匹配条件未知", code: :conditional_policy)
          end
          matched
        end
      end

      def action_for(at: nil, &predicate)
        rule = first_match(at: at, &predicate)
        rule ? rule.action : default_action
      end

      private

      # 未知状态、命令或时间语义不能用旧投影排除；已证明不执行的规则不参与顺序证明。
      def known_inactive?(rule, at:)
        return false unless rule.status_known? && !rule.unparsed_commands?
        return true if rule.disabled?
        return false unless at
        return false if (rule.schedule_name && !rule.schedule) || (rule.schedule && !rule.schedule.resolved?)
        !rule.active?(at: at)
      end
    end
  end
end
