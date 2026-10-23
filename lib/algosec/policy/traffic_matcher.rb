# frozen_string_literal: true

require_relative "evaluation"

module Algosec
  module Policy
    # 旧查询字段只作展示适配；首条命中与未知语义由 Evaluation 统一实现。
    class TrafficMatcher
      Match = Data.define(:status, :decision, :rule, :reason, :at) do
        def name = rule&.name
        def display_name = rule&.display_name
        def rule_id = rule&.rule_id
        def sequence = rule&.rule_number

        def action
          return unless %i[matched conditional].include?(status)
          rule ? rule.action : { permit: "allow", deny: "deny" }[decision]
        end
      end

      def initialize(snapshot, at: Time.current, domains: {}, application_definitions: {})
        @at = at
        @evaluation = Evaluation.new(snapshot, at: at, domains: domains, application_definitions: application_definitions)
      end

      def perform(source:, destination:, protocol:, source_port:, destination_port:, from_zone:, to_zone:, rule_set: nil, application: nil, source_user: nil)
        raise ArgumentError, "Traffic matching requires a concrete protocol" if %w[any ip all].include?(protocol.to_s.downcase)
        addresses = [ source, destination ].map do |value|
          ip = ::IPAddr.new(value)
          raise ArgumentError, "Traffic matching requires a single source and destination IP" unless ip.to_range.begin == ip.to_range.end
          ip.to_s
        end
        ports = [ source_port, destination_port ].map do |value|
          set = IPAddr.ports(value.to_s)
          raise ArgumentError, "Traffic matching requires single ports" unless set.cardinality == 1
          set.min
        end
        packet = Packet.new(source: addresses[0], destination: addresses[1], protocol: IPAddr.protocol_number(protocol),
          source_port: ports[0], destination_port: ports[1], application: application, source_user: source_user)
        evaluated = @evaluation.perform(packet, from_zone: from_zone, to_zone: to_zone, rule_set: rule_set)
        part = evaluated.partitions.fetch(0)
        Match.new(status: part.status, decision: part.decision, rule: part.rule, reason: part.reason, at: @at)
      end
    end
  end
end
