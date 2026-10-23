# frozen_string_literal: true

require_relative "base"
require_relative "address_group"
require_relative "service_group"
require "active_support/core_ext/hash/keys"

module Algosec
  module Elements
    # 保存静态或策略路由的匹配范围及下一跳元数据。
    class Route < Base
      ELEMENT_TYPE = :route
      attr_reader :subnet, :kind, :source, :source_interface,
                  :destination_interface, :next_hop, :zone, :distance, :priority, :vrf,
                  :destination_vrf, :extra_conf, :sources, :destinations, :services

      # 规范化目的网络和源范围，并按设备定义补齐默认 VRF。
      def initialize(subnet: nil, kind: :static, source: nil, source_set: nil,
                     source_interface: nil, destination_interface: nil, next_hop: nil, zone: nil,
                     distance: 10, priority: 0, vrf: nil, destination_vrf: nil,
                     sources: nil, destinations: nil, services: nil, extra_conf: {}, **context)
        raise ArgumentError, "Route extra_conf must be an object" unless extra_conf.is_a?(Hash)
        @extra_conf = immutable_metadata(extra_conf.deep_stringify_keys)
        { sources: [ sources, AddressGroup ], destinations: [ destinations, AddressGroup ], services: [ services, ServiceGroup ] }.each do |role, (object, type)|
          raise ArgumentError, "Expected #{type.name} for #{role}" unless object.nil? || object.is_a?(type)
        end
        @sources, @destinations, @services = sources, destinations, services
        @kind = symbol(kind, label: "Route kind")
        raise ArgumentError, "Route kind must be static or policy" unless %i[static policy].include?(@kind)
        @subnet = subnet.nil? ? nil : IPAddr.network_cidr(text(subnet)).freeze
        raise ArgumentError, "Static route destination is required" if @kind == :static && @subnet.nil?
        @set = @subnet.nil? ? nil : IPAddr.parse(@subnet)
        @source, @source_interface, @destination_interface = [ source, source_interface, destination_interface ].map { |value| text(value, optional: true) }
        @next_hop, @zone = [ next_hop, zone ].map { |value| text(value, optional: true) }
        @distance, @priority = integer(distance), integer(priority)
        @vrf, @destination_vrf = [ vrf, destination_vrf ].map { |value| text(value, optional: true) }
        @vrf ||= definition_for(context).default_vrf
        @destination_vrf ||= definition_for(context).default_destination_vrf
        @source_set = if sources
                        nil
        elsif source_set
                        address_set(source_set)
        elsif definition_for(context).unresolved_route_source?
                        nil
        elsif policy? && @source
                        IPAddr.parse(@source)
        else
                        Set.new(0..IPAddr::IPV4_MAX)
        end
        super(**context)
        dependencies.each { |object| same_device!(object) }
      end

      # 策略路由的地址与服务依赖参与引用计数和 DNS 缓存失效。
      def dependencies = [ sources, destinations, services ].compact.freeze

      def source_set = sources ? (sources.set if sources.resolved?) : @source_set

      # 返回三态匹配，未知绑定或用户条件不得退化为普通静态路由。
      def policy_match(source:, destination:, source_interface: nil, source_zone: nil, vrf: nil, protocol: nil, source_port: nil, destination_port: nil)
        return :miss if extra_conf["disabled"] == true
        source_target, destination_target = address_set(source), address_set(destination)
        source_ranges = source_set
        destination_ranges = destinations ? (destinations.set if destinations.resolved?) : @set
        unknown = source_ranges.nil? || (destinations && destination_ranges.nil?)
        # 先检查所有已知条件；部分重叠或缺失引用不能掩盖其他维度的确定不匹配。
        [ [ source_ranges, source_target ], [ destination_ranges, destination_target ] ].each do |ranges, target|
          next unless ranges
          return :miss unless ranges.overlap?(target)
          unknown ||= !ranges.cover?(target)
        end
        pbr = extra_conf["pbr"]
        unless pbr
          if self.source_interface
            return :miss if source_interface && self.source_interface != source_interface
            unknown ||= source_interface.nil?
          end
          return unknown ? :unknown : :match
        end

        bindings = pbr.fetch("bindings")
        return :miss if bindings.empty?
        values = { "interface" => source_interface, "zone" => source_zone, "vrouter" => vrf }
        matches = bindings.map do |binding|
          value = values[binding.fetch("type")]
          value.nil? ? :unknown : (value == binding.fetch("name") ? :match : :miss)
        end
        return :miss if matches.all? { |state| state == :miss }
        unknown ||= !matches.include?(:match) || !destination_ranges || !next_hop || !destination_interface || !pbr.fetch("conditions", {}).empty?
        if services&.resolved?
          if services.unique_leaves.flat_map(&:terms).any? { |term| term[:uuid] || term[:timeout] }
            if protocol && destination_port
              return :miss unless services.set.overlap?(IPAddr.service("#{protocol}/#{destination_port}"))
            end
            return :unknown
          end
          unless pbr.fetch("services").all? { |name| name.casecmp?("any") }
            if [ protocol, source_port, destination_port ].any?(&:nil?)
              unknown = true
            else
              return :miss unless services.matches?(protocol: protocol.to_s, source_port: source_port.to_s, destination_port: destination_port.to_s)
            end
          end
        else
          unknown = true
        end
        unknown ? :unknown : :match
      end

      # 前缀只从规范 subnet 派生，不保存第二份掩码。
      def prefix = subnet && IPAddr.new(subnet).prefix

      # 判断路由是否为策略路由。
      def policy? = kind == :policy

      # 排序由设备定义解释，调用方无需识别源路由与顺序匹配规则。
      def policy_rank(index) = element_definition.policy_route_rank(self, index)

      # 返回目的范围；未指定目的网络的策略路由不能作为目的匹配。
      def set = @set || raise(ArgumentError, "Route destination is unspecified")

      # 判断路由目的是否覆盖给定地址范围。
      def covers?(destination) = set.cover?(address_set(destination))

      # 判断给定源范围是否被策略路由的源范围覆盖。
      def matches_source?(value)
        raise ArgumentError, "Policy route source is unresolved" unless source_set
        source_set.cover?(address_set(value))
      end

      protected

      # 由设备定义决定静态或策略路由的身份字段。
      def identity_parts = element_definition.route_identity(self)
    end
  end
end
