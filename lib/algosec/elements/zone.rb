# frozen_string_literal: true

require_relative "interface"

module Algosec
  module Elements
    # 表示安全区域，并累计其接口的可达地址范围。
    class Zone < Base
      ELEMENT_TYPE = :zone
      attr_reader :acl_name, :vrf, :mode, :set

      # 校验区域属性，建立种子范围，并登记接口依赖。
      def initialize(name:, acl_name: nil, vrf: nil, mode: :routed, interfaces: [], reachable: nil, **context)
        @acl_name, @vrf = [ acl_name, vrf ].map { |value| text(value, optional: true) }
        @mode = symbol(mode, label: "Zone mode")
        raise ArgumentError, "Zone mode must be routed or transparent" unless %i[routed transparent].include?(@mode)
        super(name: name, **context)
        @vrf ||= element_definition.default_vrf
        element_definition.validate_zone(self)
        raise ArgumentError, "Interfaces must be an array" unless interfaces.is_a?(Array)
        @interfaces = {}
        @seed_set = reachable.nil? ? Set.new : address_set(reachable)
        @set = @seed_set
        interfaces.each { |interface| add_interface(interface) }
      end

      def dependencies = @interfaces.values.freeze

      # 返回接口映射的只读副本。
      def interfaces = @interfaces.dup.freeze

      # 加入接口并把接口范围累计到区域集合。
      def add_interface(interface)
        validate_interface!(interface)
        return replace_interface(interface) if @interfaces.key?(interface.identity)
        combined = set | interface.network_set
        @interfaces[interface.identity] = interface
        @set = combined
        self
      end

      # 替换接口后按当前接口映射重新计算区域集合。
      def replace_interface(interface)
        validate_interface!(interface)
        candidate = @interfaces.merge(interface.identity => interface)
        combined = projected_set(candidate)
        @interfaces, @set = candidate, combined
        self
      end

      # 在接口依赖变化后重建区域集合。
      def rebuild!
        @set = projected_set(@interfaces)
        self
      end

      def ipv6_set = interfaces.values.reduce(Set.new) { |result, interface| result | interface.ipv6_set }

      # 将区域范围转换为设备配置使用的地址区间文本。
      def ip_ranges
        set.map { |range| "#{IPAddr.from_i(range.begin)}-#{IPAddr.from_i(range.end)}".freeze }.freeze
      end

      # 声明种子独立于路由派生范围。
      def seed_reachable = @seed_set

      protected

      def seal_owned_values!
        @interfaces.freeze
        super
      end

      private

      # 校验接口类型并检查设备归属。
      def validate_interface!(interface)
        raise ArgumentError, "Expected an Interface" unless interface.is_a?(Interface)
        same_device!(interface)
      end

      # 从接口投影和种子范围生成区域当前集合。
      def projected_set(interfaces)
        interfaces.values.reduce(@seed_set) { |result, interface| result | interface.network_set }
      end
    end
  end
end
