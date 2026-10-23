# frozen_string_literal: true

require "time"
require "active_support"
require "active_support/time"
require_relative "value"
require_relative "../elements/scope"

module Algosec
  module Policy
    # 完整身份与连续时间窗内的使用证据；候选判断不表示批准删除规则。
    class UsageObservation
      attr_reader :rule_identity, :window_start, :window_end, :hits, :counter_reset, :complete

      def initialize(rule_identity:, window_start:, window_end:, hits:, counter_reset:, complete:)
        raise ArgumentError, "Expected a canonical SecurityRule identity" unless canonical_identity?(rule_identity)
        raise ArgumentError, "Hits must be a nonnegative Integer" unless hits.is_a?(Integer) && hits >= 0
        unless [ counter_reset, complete ].all? { |value| value.equal?(true) || value.equal?(false) }
          raise ArgumentError, "Counter reset and completeness must be booleans"
        end
        @rule_identity = Value.immutable(rule_identity)
        @window_start, @window_end = interval(window_start, window_end)
        @hits, @counter_reset, @complete = hits, counter_reset, complete
        freeze
      end

      # 未完成、重置、命中或覆盖不足的观测均不能证明指定时间窗内未使用。
      def unused_for?(rule_identity:, window_start:, window_end:)
        required_start, required_end = interval(window_start, window_end)
        complete && !counter_reset && hits.zero? && canonical_identity?(rule_identity) &&
          self.rule_identity == rule_identity && self.window_start <= required_start && self.window_end >= required_end
      end

      # 显式展开 Scope，避免 JSON 把领域身份降为原生规则编号或展示文本。
      def to_h
        Value.freeze({
          rule_identity: [ *rule_identity.first(2), rule_identity[2].to_h, *rule_identity.drop(3) ],
          window_start: window_start.iso8601(9), window_end: window_end.iso8601(9),
          hits: hits, counter_reset: counter_reset, complete: complete
        })
      end

      def as_json(*) = to_h

      private

      def canonical_identity?(value)
        value.is_a?(Array) && value.size >= 4 && value[0] == :security_rule &&
          value[1].is_a?(Symbol) && value[2].is_a?(Elements::Scope) &&
          value.drop(3).all? { |field| field.is_a?(String) }
      end

      # 统一为复制冻结的 UTC 时刻，保留跨时区相等性并隔离可变 Time。
      def interval(start, finish)
        values = [ start, finish ].map do |value|
          unless value.is_a?(Time) || value.is_a?(ActiveSupport::TimeWithZone)
            raise ArgumentError, "Observation window endpoints must be times"
          end
          value.to_time.getutc.freeze
        end
        raise ArgumentError, "Observation window must be nonempty" unless values[0] < values[1]
        values
      end
    end
  end
end
