# frozen_string_literal: true

require_relative "route"
require_relative "../ipv6"

module Algosec
  module Elements
    # 表示三层接口及其 VLAN、路由可达范围的累计投影。
    class Interface < Base
      ELEMENT_TYPE = :interface
      attr_reader :ipaddr, :mode, :zone, :vrf, :access_mode, :set, :aggregate, :ipv6_addresses

      # 规范化接口属性，先保存种子可达范围，再登记路由。
      def initialize(name:, ipaddr: nil, mode: :layer2, zone: nil, vrf: nil,
                     access_mode: nil, vlans: [], routes: [], reachable: nil, aggregate: nil, ipv6_addresses: [], **context)
        @ipv6_addresses = ipv6_addresses.map { |value| IPv6.canonical(value, host: true).freeze }.uniq.freeze
        @aggregate = text(aggregate, optional: true)
        @ipaddr = ipaddr.nil? ? nil : IPAddr.host_cidr(ipaddr).freeze
        @mode = symbol(mode, label: "Interface mode")
        raise ArgumentError, "Interface mode must be layer2 or layer3" unless %i[layer2 layer3].include?(@mode)
        @zone, @vrf = [ zone, vrf ].map { |value| text(value, optional: true) }
        @access_mode = text(access_mode, optional: true)
        super(name: name, **context)
        @vrf ||= element_definition.default_vrf
        self.access_mode = @access_mode || (mode.to_sym == :layer3 ? "route" : element_definition.default_access_mode)
        raise ArgumentError, "VLANs and routes must be arrays" unless vlans.is_a?(Array) && routes.is_a?(Array)
        @vlans = vlans.map { |value| text(value) }.uniq
        @vlan_interfaces, @routes = {}, {}
        @seed_set = reachable.nil? ? Set.new : address_set(reachable)
        @set = @seed_set
        routes.each { |route| add_route(route) }
      end

      # VLAN 和路由即使不单独登记在目录中，也属于接口发布图。
      def dependencies = (@routes.values + @vlan_interfaces.values).freeze

      # 返回路由映射的只读副本。
      def routes = @routes.dup.freeze

      # 返回 VLAN 名称的只读副本。
      def vlans = @vlans.dup.freeze

      # 根据三层接口地址计算直连网段。
      def connected_set
        connected = ipaddr ? IPAddr.parse(ipaddr) : Set.new
        routes.values.select { |route| route.extra_conf["connected"] }.reduce(connected) { |set, route| set | route.set }
      end

      # 保留显式种子和 VLAN 范围，默认路由及策略条件不声明区域网段。
      def network_set
        networks = routes.values.reject { |route| route.policy? || route.prefix == 0 }.reduce(@seed_set | connected_set) do |result, route|
          route.subnet ? result | route.set : result
        end
        @vlan_interfaces.values.reduce(networks) { |result, interface| result | interface.network_set }
      end

      def ipv6_set = Set.new(*ipv6_addresses.flat_map { |value| IPv6.parse(value).ranges })

      # 接口地址的主机部分，不包含直连网段中的其他地址。
      def host = ipaddr && IPAddr.host(ipaddr)

      # 规范化访问模式；该值由设备连接策略读取。
      def access_mode=(value)
        value = text(value, optional: true)
        unless value.nil? || %w[route access trunk].include?(value)
          raise ArgumentError, "Interface access mode must be route, access or trunk"
        end
        if (mode == :layer3 && value != "route") || (mode == :layer2 && value == "route")
          raise ArgumentError, "Interface access mode conflicts with layer mode"
        end
        @access_mode = value
      end

      # 新增路由并把路由范围累计到接口可达集合。
      def add_route(route)
        validate_route!(route)
        # 只有源条件的策略路由可定位出口，但不能声明目的可达范围。
        combined = route.subnet ? set | route.set : set
        @routes[route.identity] = route
        @set = combined
        self
      end

      # 替换路由后按当前路由和 VLAN 重新计算可达集合。
      def replace_route(route)
        validate_route!(route)
        candidate = @routes.merge(route.identity => route)
        combined = projected_set(candidate)
        @routes, @set = candidate, combined
        self
      end

      # 登记 VLAN 接口，同时拒绝设备不一致和循环嵌套。
      def add_vlan(interface)
        raise ArgumentError, "Expected a VLAN interface" unless interface.is_a?(Interface)
        same_device!(interface)
        raise ArgumentError, "Cyclic VLAN interface" if interface.contains_interface?(self)
        candidate = @vlan_interfaces.merge(interface.identity => interface)
        combined = if @vlan_interfaces.key?(interface.identity)
          projected_set(@routes, vlan_interfaces: candidate)
        else
          set | interface.set
        end
        @vlans << interface.name unless @vlans.include?(interface.name)
        @vlan_interfaces = candidate
        @set = combined
        self
      end

      # 在依赖对象变化后重建接口可达集合。
      def rebuild!
        @set = projected_set(@routes)
        self
      end

      # 声明种子独立于路由派生范围。
      def seed_reachable = @seed_set

      def vlan_interfaces = @vlan_interfaces.dup.freeze

      protected

      def seal_owned_values!
        @vlans.freeze
        @routes.freeze
        @vlan_interfaces.freeze
        super
      end

      # 深度判断 VLAN 关系是否包含指定接口。
      def contains_interface?(interface)
        equal?(interface) || @vlan_interfaces.values.any? { |child| child.contains_interface?(interface) }
      end

      private

      # 校验路由类型并检查设备归属。
      def validate_route!(route)
        raise ArgumentError, "Expected a Route" unless route.is_a?(Route)
        same_device!(route)
      end

      # 从路由和 VLAN 投影中重建接口范围。
      def projected_set(routes, vlan_interfaces: @vlan_interfaces)
        (routes.values + vlan_interfaces.values).reduce(@seed_set) do |result, object|
          object.is_a?(Route) && object.subnet.nil? ? result : result | object.set
        end
      end
    end
  end
end
