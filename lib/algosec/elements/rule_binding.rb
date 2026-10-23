# frozen_string_literal: true

require_relative "base"

module Algosec
  module Elements
    # 规则链在一个有向区域对上的应用；空规则链也保留绑定证据。
    class RuleBinding < Base
      ELEMENT_TYPE = :rule_binding
      attr_reader :rule_type, :rule_set, :from_zone, :to_zone

      def initialize(rule_type:, rule_set:, from_zone:, to_zone:, **context)
        @rule_type = symbol(rule_type, label: "Rule type")
        raise ArgumentError, "Rule type must be object or acl" unless %i[object acl].include?(@rule_type)
        @rule_set, @from_zone, @to_zone = [ rule_set, from_zone, to_zone ].map do |value|
          unless value.is_a?(String) && !value.empty? && !value.match?(/[\x00-\x1f\x7f]/)
            raise ArgumentError, "Rule binding requires nonempty single-line names"
          end
          text(value)
        end
        super(**context)
      end

      protected

      def identity_parts = [ rule_type, rule_set, from_zone, to_zone ]
    end
  end
end
