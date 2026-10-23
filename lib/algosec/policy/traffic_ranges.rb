# frozen_string_literal: true

require_relative "evaluation"

module Algosec
  module Policy
    # 精确集合评估后再输出平面区间；展开前检查整个结果的笛卡尔积预算。
    class TrafficRanges
      MAX_SEGMENTS = 4096

      def initialize(snapshot, at: Time.current, domains: {}, application_definitions: {})
        @evaluation = Evaluation.new(snapshot, at: at, domains: domains, application_definitions: application_definitions)
      end

      def perform(source:, destination:, source_port:, destination_port:, protocol:, from_zone:, to_zone:, rule_set: nil,
                  limit: MAX_SEGMENTS, family: :ipv4, application: nil, source_user: nil)
        raise ArgumentError, "Limit must be a positive integer" unless limit.is_a?(Integer) && limit.positive?
        limit = [ limit, MAX_SEGMENTS ].min
        number = IPAddr.protocol_number(protocol)
        protocols = %w[any ip all].include?(protocol.to_s.downcase) ? Set.new(0..255) : Set.new(number..number)
        query = TrafficSet.new([ { family: family, source_addresses: source, destination_addresses: destination,
          protocols: protocols, source_ports: source_port, destination_ports: destination_port } ], limit: limit)
        result = @evaluation.perform(query, from_zone: from_zone, to_zone: to_zone, rule_set: rule_set, application: application, source_user: source_user)
        count = result.partitions.sum do |part|
          part.traffic_set.sum { |region| TrafficSet::DIMENSIONS.map { |dimension| region.public_send(dimension).size }.inject(1, :*) }
        end
        raise ArgumentError, "query_too_complex" if count > limit

        rows = result.partitions.flat_map do |part|
          part.traffic_set.flat_map do |region|
            dimensions = TrafficSet::DIMENSIONS.map { |dimension| region.public_send(dimension).ranges }
            dimensions[0].product(*dimensions.drop(1)).map do |src, dst, proto, sport, dport|
              label = protocols.cardinality == 1 ? protocol.to_s : port_label(proto)
              [ [ proto.begin, src.begin, dst.begin, sport.begin, dport.begin ],
                { source: address_label(src, region.family), destination: address_label(dst, region.family),
                  source_port: port_label(sport), destination_port: port_label(dport), protocol: label,
                  status: part.status, decision: part.decision, action: part.action, rule_id: part.rule&.rule_id, name: part.rule&.name, reason: part.reason } ]
            end
          end
        end
        rows.sort_by(&:first).map(&:last)
      rescue TrafficSet::LimitExceeded
        raise ArgumentError, "query_too_complex"
      end

      private

      def address_label(range, family)
        return range.begin == range.end ? IPAddr.from_i(range.begin) : IPAddr.format_range(range) if family == :ipv4
        first, last = [ range.begin, range.end ].map { |value| ::IPAddr.new(value, Socket::AF_INET6).to_s }
        first == last ? first : "#{first}-#{last}"
      end

      def port_label(range) = range.begin == range.end ? range.begin.to_s : "#{range.begin}-#{range.end}"
    end
  end
end
