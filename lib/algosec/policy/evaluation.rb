# frozen_string_literal: true

require_relative "snapshot"
require_relative "traffic_set"

module Algosec
  module Policy
    # 首条命中只消费尚未判定的精确流量；未知规则保留潜在命中区域及原始证据。
    class Evaluation
      Partition = Data.define(:traffic_set, :action, :status, :rule, :reason, :default) do
        def default? = default
        def decision = { "allow" => :permit, "deny" => :deny, "drop" => :deny }[action]
      end

      def initialize(snapshot, at: Time.current, domains: {}, application_definitions: {})
        @snapshot, @at, @domains = snapshot, at.dup.freeze, domains
        unless application_definitions.is_a?(Hash) && application_definitions.all? do |name, definition|
          name.is_a?(String) && !name.empty? && (definition.is_a?(Elements::ServiceObject) || definition.is_a?(Elements::ServiceGroup))
        end
          raise ArgumentError, "Application definitions must map exact names to ServiceObject or ServiceGroup"
        end
        @application_definitions = application_definitions.dup.freeze
      end

      def perform(traffic, from_zone:, to_zone:, rule_set: nil, application: nil, source_user: nil)
        if traffic.is_a?(Packet)
          application = packet_context(traffic.application, application)
          source_user = packet_context(traffic.source_user, source_user)
          numeric = Packet.new(**Packet::ATTRIBUTES.reject { |key| %i[application source_user].include?(key) }.to_h { |key| [ key, traffic.public_send(key) ] })
          traffic = TrafficSet.from_packet(numeric)
        end
        raise ArgumentError, "Evaluation requires a Packet or TrafficSet" unless traffic.is_a?(TrafficSet)
        [ application, source_user ].each do |value|
          raise ArgumentError, "Evaluation context must be nonempty text" unless value.nil? || (value.is_a?(String) && !value.strip.empty?)
        end
        return unresolved(traffic, "配置解析不完整") unless @snapshot.complete?

        rulebase = @snapshot.rulebase(from_zone: from_zone, to_zone: to_zone, rule_set: rule_set)
        ordered = rulebase.ordered_rules(at: @at)
        remaining, partitions, count = traffic, [], 0
        ordered.each do |rule|
          break if remaining.empty?
          predicate = Predicate.new(@snapshot, rule, at: @at, domains: @domains,
            application: application, source_user: source_user, application_definitions: @application_definitions)
          predicate.partitions(remaining).each do |partition|
            count += partition.traffic_set.regions.size
            raise TrafficSet::LimitExceeded, "Evaluation exceeds #{traffic.limit} regions" if count > traffic.limit
            partitions << partition
            remaining -= partition.traffic_set
          end
        end
        unless remaining.empty?
          action = rulebase.default_action
          count += remaining.regions.size
          raise TrafficSet::LimitExceeded, "Evaluation exceeds #{traffic.limit} regions" if count > traffic.limit
          partitions << Partition.new(traffic_set: remaining, action: action, status: action ? :matched : :unmatched,
            rule: nil, reason: action ? nil : "没有可证明的默认动作", default: true)
          remaining = TrafficSet.new([], limit: traffic.limit) if action
        end
        Result.new(partitions: partitions, remaining: remaining, at: @at)
      rescue RuleOrder::Unproven => error
        unresolved(traffic, error.message)
      end

      private

      def packet_context(actual, supplied)
        raise ArgumentError, "Conflicting packet and evaluation context" if actual && supplied && actual != supplied
        actual || supplied
      end

      def unresolved(traffic, reason)
        partitions = traffic.empty? ? [] : [ Partition.new(traffic_set: traffic, action: nil, status: :unknown, rule: nil, reason: reason.dup.freeze, default: false) ]
        Result.new(partitions: partitions, remaining: traffic, at: @at, proven: false)
      end
    end
  end
end

require_relative "evaluation/result"
require_relative "evaluation/predicate"
