# frozen_string_literal: true

require_relative "../base"

module Algosec
  module Elements
    module Nat
      # NAT 选择使用转换前条件；原始组和关联规则仍属于同一份对象图。
      class OriginalPacket
        attr_reader :source_addresses, :destination_addresses, :services, :source_zones,
                    :destination_zones, :protocol, :source_port, :destination_port,
                    :interface, :vrf, :match_rule

        def initialize(source_addresses: nil, destination_addresses: nil, services: nil,
                       source_zones: nil, destination_zones: nil, protocol: nil, source_port: nil,
                       destination_port: nil, interface: nil, vrf: nil, match_rule: nil)
          [ source_addresses, destination_addresses, services ].each do |set|
            raise ArgumentError, "Packet ranges must be Sets" unless set.nil? || set.is_a?(Set)
          end
          @source_addresses, @destination_addresses, @services = source_addresses, destination_addresses, services
          @source_zones, @destination_zones = immutable_names(source_zones), immutable_names(destination_zones)
          @protocol, @source_port, @destination_port, @interface, @vrf =
            [ protocol, source_port, destination_port, interface, vrf ].map { |value| value&.to_s&.dup&.freeze }
          @match_rule = match_rule
          freeze
        end

        # 缓存显式遍历值成员，保留共享规则引用并恢复嵌套容器的冻结状态。
        def to_h
          { source_addresses: source_addresses, destination_addresses: destination_addresses, services: services,
            source_zones: source_zones, destination_zones: destination_zones, protocol: protocol,
            source_port: source_port, destination_port: destination_port, interface: interface, vrf: vrf, match_rule: match_rule }
        end

        private

        def immutable_names(values)
          return nil if values.nil?
          raise ArgumentError, "Packet zones must be an array" unless values.is_a?(Array)
          values.map do |value|
            raise ArgumentError, "Packet zones must contain names" unless value.is_a?(String) || value.is_a?(Symbol)
            value.to_s.dup.freeze
          end.uniq.freeze
        end
      end
    end
  end
end
