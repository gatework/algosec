# frozen_string_literal: true

require_relative "base"

module Algosec
  module Elements
    # 表示动态 NAT 地址池，并把设备格式的地址段转换为统一集合。
    class NatPool < Base
      ELEMENT_TYPE = :nat_pool
      attr_reader :ip, :set, :zone, :interface, :direction, :port, :mode, :id, :alias_name, :arp_reply

      # 规范化地址池属性，校验设备约束并汇总所有地址段。
      def initialize(name:, ip:, zone: nil, interface: nil, direction: nil,
                     port: nil, mode: nil, id: nil, alias_name: nil, arp_reply: nil, **context)
        @zone, @interface, @mode, @id, @alias_name = [ zone, interface, mode, id, alias_name ].map { |value| text(value, optional: true) }
        unless arp_reply.nil? || arp_reply == true || arp_reply == false
          raise ArgumentError, "ARP reply must be true, false or nil"
        end
        @arp_reply = arp_reply
        @direction = direction.nil? ? nil : symbol(direction, label: "NAT direction")
        @port = port.nil? ? nil : integer(port)
        raise ArgumentError, "Port exceeds 65535" if @port && @port > IPAddr::PORT_MAX
        super(name: name, **context)
        element_definition.validate_nat_pool(self)
        @direction ||= element_definition.default_nat_pool_direction
        unless @direction.nil? || %i[source destination bidirectional].include?(@direction)
          raise ArgumentError, "Invalid NAT direction"
        end
        @ip = (ip.is_a?(Array) ? ip : [ ip ]).map { |segment| text(segment).strip.freeze }.freeze
        @set = @ip.reduce(Set.new) { |result, segment| result | parse_segment(segment) }
      end

      private

      # 解析单个主机、网段或两个端点组成的设备地址段。
      def parse_segment(segment)
        match = /\A([^\s-]+)(?:\s*-\s*|\s+)([^\s-]+)\z/.match(segment)
        return IPAddr.parse(segment) unless match
        first, last = IPAddr.parse(match[1]), IPAddr.parse(match[2])
        low, high = first.min, last.max
        low, high = last.min, first.max if low > high
        Set.new(low..high)
      end
    end
  end
end
