# frozen_string_literal: true

require_relative "route"

module Algosec
  module Elements
    # 策略路由检查地址、入口及服务条件；静态路由按最长目的前缀匹配。
    class RoutingTable
      include Enumerable

      class ConditionalRoute < StandardError; end

      # 建立路由表并在加入路由时校验设备范围。
      def initialize(routes = [])
        raise ArgumentError, "Routes must be an array" unless routes.is_a?(Array)
        @routes = {}
        @vendor = @device_id = nil
        routes.each { |route| add(route) }
      end

      # 加入路由并清除按类型排序的缓存。
      def add(route)
        raise ArgumentError, "Expected a Route" unless route.is_a?(Route)
        if @vendor && @vendor != route.vendor
          raise ArgumentError, "Routing table spans different vendors"
        end
        if @device_id && route.device_id && @device_id != route.device_id
          raise ArgumentError, "Routing table spans different devices"
        end
        @vendor ||= route.vendor
        @device_id ||= route.device_id
        @routes[route.identity] = route
        @static_routes = nil
        self
      end

      # 遍历路由表；没有代码块时返回枚举器。
      def each(&block) = block ? @routes.each_value(&block) : enum_for(__method__)

      # 先查匹配的策略路由，再按最长前缀查静态路由。
      def lookup(source:, destination:, vrf: nil, source_interface: nil, source_zone: nil, protocol: nil, source_port: nil, destination_port: nil)
        source = ranges(source)
        destination = ranges(destination)
        vrf = vrf&.to_s
        states = select(&:policy?).each_with_object({}) do |route, matches|
          next unless vrf_match?(route, vrf)
          state = route.policy_match(source: source, destination: destination, source_interface: source_interface,
                                     source_zone: source_zone, vrf: vrf, protocol: protocol,
                                     source_port: source_port, destination_port: destination_port)
          matches[route] = state unless state == :miss
        end
        if vrf.nil?
          candidates = states.keys + reject(&:policy?).select { |route| route.set.overlap?(destination) }
          raise ConditionalRoute, "Traffic matches multiple VRFs; specify a VRF" if candidates.map(&:vrf).uniq.size > 1
        end
        groups = policy_groups(states.keys, source_interface: source_interface, source_zone: source_zone, vrf: vrf)
        groups.each do |_rank, routes|
          routes.each do |route|
            if states.fetch(route) == :unknown
              raise ConditionalRoute, "Policy route #{route.name || route.identity_fields.join('/')} requires complete match context"
            end
          end
          return unique_route(routes)
        end
        lookup_static(destination: destination, vrf: vrf)
      end

      # 静态路由统一按前缀、距离和优先级选择；未知 VRF 不任意跨域推断。
      def lookup_static(destination:, vrf: nil, external_zone: nil)
        destination = ranges(destination)
        vrf = vrf&.to_s
        external_zone = external_zone&.to_s
        @static_routes ||= reject(&:policy?).sort_by { |route| static_rank(route) }.freeze
        candidates = @static_routes.select do |route|
          (vrf_match?(route, vrf) || (external_zone && route.zone == external_zone)) && route.set.overlap?(destination)
        end
        if vrf.nil? && candidates.map(&:vrf).uniq.size > 1
          raise ConditionalRoute, "Destination matches multiple VRFs; specify a VRF"
        end
        return if candidates.empty?

        best = candidates.take_while { |route| static_rank(route) == static_rank(candidates.first) }
        # 更优路由只覆盖部分查询时，不能把整个范围交给后续宽泛路由。
        unless best.all? { |route| route.covers?(destination) }
          raise ConditionalRoute, "Destination range spans different routes; query smaller ranges"
        end
        unique_route(best)
      end

      private

      def static_rank(route) = [ -(route.prefix || 32), route.distance, route.priority ]

      # 绑定层级优先；同层级使用元素提供的策略顺序。
      def policy_groups(routes, source_interface:, source_zone:, vrf:)
        values = { "interface" => source_interface, "zone" => source_zone, "vrouter" => vrf }
        routes.each_with_index.group_by do |route, index|
          bindings = route.extra_conf.dig("pbr", "bindings")
          ranks = Array(bindings).filter_map do |binding|
            value = values[binding.fetch("type")]
            %w[interface zone vrouter].index(binding.fetch("type")) if value.nil? || value == binding.fetch("name")
          end
          [ bindings ? ranks.min || 3 : 0, *route.policy_rank(index) ]
        end.sort_by(&:first).map { |rank, entries| [ rank, entries.map(&:first) ] }
      end

      # 查询返回一条确定路径；等代价候选不能按目录插入顺序任取出口。
      def unique_route(routes)
        paths = routes.map do |route|
          # 直连路由的次地址只是地址来源，不是另一条转发网关。
          hop = route.extra_conf["connected"] ? nil : route.next_hop
          [ route.vrf, route.destination_vrf, route.destination_interface, hop, route.zone ]
        end
        raise ConditionalRoute, "Equal-cost routes have different forwarding paths" if paths.uniq.size > 1
        routes.first
      end

      # 判断路由是否属于请求的 VRF；未指定 VRF 时允许所有范围。
      def vrf_match?(route, vrf)
        vrf.nil? || route.vrf == vrf
      end

      # 将地址输入统一成集合，供策略和静态路由使用同一匹配逻辑。
      def ranges(value)
        return value if value.is_a?(Set)
        return value.to_set if value.is_a?(IPAddr)
        IPAddr.parse(value)
      end
    end
  end
end
