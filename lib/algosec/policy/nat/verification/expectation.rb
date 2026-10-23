# frozen_string_literal: true

require_relative "../verification"

module Algosec
  module Policy
    module Nat
      class Verification
        # 与 Nat::Resolver 完全相同的原始流量查询，分配类型必须来自显式批准值。
        class Expectation
          attr_reader :address, :options

          def initialize(address:, zone:, direction:, peers:, allocation:, services: nil, source_port: nil, mapped_source_port: nil, flow: {})
            @address = Value.text(address).freeze
            IPAddr.parse(address)
            direction = Value.symbol(direction)
            raise ArgumentError, "Invalid NAT direction" unless %i[source destination].include?(direction)
            flow = Value.hash(flow)
            raise ArgumentError, "Unknown original flow fields" unless (flow.keys - %i[original_dst from_zone to_zone vrf to_zone_stage]).empty?
            allocation = Value.hash(allocation)
            raise ArgumentError, "Unknown allocation fields" unless (allocation.keys - %i[type address interface direction pool_name option]).empty?
            allocation[:type] = Value.symbol(allocation.fetch(:type))
            raise ArgumentError, "Invalid allocation type" unless %i[static dynamic].include?(allocation[:type])
            IPAddr.parse(allocation[:address]) if allocation[:address]
            raise ArgumentError, "NAT peers must be an address hash" unless peers.is_a?(Hash) && !peers.empty?
            Ranges.addresses(peers.keys)
            raise ArgumentError, "NAT services must be a hash" unless services.nil? || services.is_a?(Hash)
            services = services&.to_h do |key, entry|
              entry = Value.hash(entry)
              raise ArgumentError, "Unknown NAT service fields" unless (entry.keys - %i[origin translated_port]).empty?
              entry.each_value { |value| Value.text(value) }
              key = Value.text(key)
              [ key, entry[:origin] ].compact.each do |value|
                IPAddr.service(value)
              end
              IPAddr.ports(entry[:translated_port]) if entry[:translated_port]
              [ key, entry ]
            end
            Nat::ServiceQuery.coerce(services)
            flow.each { |key, value| Value.text(value) unless value.nil? || key == :to_zone_stage }
            IPAddr.parse(flow[:original_dst]) if flow[:original_dst]
            if direction == :destination && !flow[:original_dst] && !allocation[:address]
              raise ArgumentError, "Destination NAT requires an original destination address"
            end
            flow[:to_zone_stage] = Value.symbol(flow[:to_zone_stage]) if flow[:to_zone_stage]
            raise ArgumentError, "Unknown NAT zone stage" unless [ nil, :original, :security ].include?(flow[:to_zone_stage])
            allocation[:direction] = Value.symbol(allocation[:direction]) if allocation[:direction]
            raise ArgumentError, "Invalid allocation direction" unless [ nil, :source, :destination ].include?(allocation[:direction])
            allocation.except(:type, :direction).each_value { |value| Value.text(value) unless value.nil? }
            zone = Value.text(zone)
            [ source_port, mapped_source_port ].compact.each { |value| IPAddr.ports(Value.text(value)) }
            peers = peers.keys.to_h { |key| [ Value.text(key), {} ] }
            @options = Value.immutable(zone: zone, direction: direction, peers: peers, services: services,
              source_port: source_port, mapped_source_port: mapped_source_port, flow: flow, allocation: allocation)
            freeze
          end

          def self.from_h(document) = new(**Value.hash(document))

          def direction = options.fetch(:direction)
          def allocation = options.fetch(:allocation)
          def flow = options.fetch(:flow)
          def to_h = { address: address, **options }

          # 未限制的区域只有在批准范围本身也未限制时才能作为全集使用。
          def context
            { from_zone: flow[:from_zone] || (options[:zone] if direction == :destination),
              to_zone: flow[:to_zone] || (options[:zone] if direction == :source), vrf: flow[:vrf] }
          end

          def original_sources = direction == :source ? IPAddr.parse(address) : Ranges.addresses(options.fetch(:peers).keys)
          def original_destinations
            direction == :source ? Ranges.addresses(options.fetch(:peers).keys) : IPAddr.parse(flow[:original_dst] || allocation.fetch(:address))
          end

          def traffic
            services = options[:services]
            ranges = services.nil? || services.empty? ? ANY_SERVICE : Ranges.services(services.map { |name, entry| entry.fetch(:origin, name) })
            Nat::Verification.traffic(original_sources, original_destinations, ranges, options[:source_port])
          end
        end
      end
    end
  end
end
