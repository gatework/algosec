# frozen_string_literal: true

require_relative "value"

module Algosec
  module Policy
    # 只证明同一执行链和唯一顺序，不推断覆盖、动作或迁移区域语义。
    class RuleOrder
      class Unproven < Error
        attr_reader :reason

        def initialize(reason)
          @reason = reason
          super(reason == :chains ? "需要指定规则链" : "规则执行顺序尚未完整解析", code: :unknown_order)
        end
      end

      # 单条规则的首条命中无需编号；迁移仍要求每条规则有明确位置。
      def initialize(behavior, require_number: false)
        @behavior, @require_number = behavior, require_number
      end

      def resolve(rules)
        raise Unproven.new(:chains) if rules.map { |rule| @behavior.rule_chain(rule) }.uniq.size > 1

        ordered = rules.map { |rule| [ rule, @behavior.rule_number(rule) ] }
        numbers = ordered.map(&:last)
        if (@require_number || rules.size > 1) && (numbers.any?(&:nil?) || numbers.uniq.size != numbers.size)
          raise Unproven.new(:numbers)
        end
        ordered.sort_by { |_rule, number| number || 0 }.map(&:first)
      end
    end
  end
end
