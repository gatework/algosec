# frozen_string_literal: true

require_relative "ranges"
require_relative "value"
require_relative "definition"

module Algosec
  module Policy
    # 地址归属与转发出口分开查询；网络范围保留各自的路由域。
    class NetworkLocator
      attr_reader :devices

      # 数据由上层调用方取得；这里仅构建当前请求的范围索引。
      def initialize(networks, definition: nil)
        raise ArgumentError, "网络记录必须是数组" unless networks.is_a?(Array)
        @definition = definition && Definition.resolve(:generic, explicit: definition).last
        @devices, @ranges = {}, {}
        networks.each do |network_record|
          network = Value.hash(network_record)
          device_id = network.fetch(:device_id)
          raise ArgumentError, "设备编号必须为正整数" unless device_id.is_a?(Integer) && device_id.positive?
          vendor, = Definition.resolve(network.fetch(:vendor), explicit: @definition)
          device_info = { device_id: device_id, device_name: Value.text(network.fetch(:device_name)),
                          vendor: vendor, nat_mode: network.fetch(:nat_mode, 0) }
          raise ArgumentError, "NAT 模式必须是 0、1 或 2" unless [ 0, 1, 2 ].include?(device_info[:nat_mode])
          raise ArgumentError, "设备 #{device_id} 的网络元数据不一致" if @devices[device_id] && @devices[device_id] != device_info
          @devices[device_id] = Value.immutable(device_info)
          protected_zone = network.fetch(:protected)
          raise ArgumentError, "保护区域状态必须是布尔值" unless [ true, false ].include?(protected_zone)
          zone = Value.text(network.fetch(:zone), label: "安全域")
          vrf = network[:vrf].nil? ? nil : Value.text(network[:vrf], label: "路由域")
          mode = network[:mode].nil? ? nil : Value.symbol(network[:mode], label: "区域模式")
          raise ArgumentError, "区域模式必须是 routed 或 transparent" if mode && !%i[routed transparent].include?(mode)
          address_type = Value.symbol(network.fetch(:address_type, :main), label: "地址类型")
          raise ArgumentError, "地址类型必须是 main、private 或 extra" unless %i[main private extra].include?(address_type)
          address_set = network[:set] || IPAddr.parse(network.fetch(:address))
          unless address_set.is_a?(Set) && !address_set.empty? && address_set.max <= IPAddr::IPV4_MAX
            raise ArgumentError, "区域地址范围必须是非空 IPv4 集合"
          end
          key = [ device_id, protected_zone, zone, address_type, vrf, mode ]
          @ranges[key] = @ranges.fetch(key, Set.new) | address_set
        end
        @devices = @devices.sort.to_h.freeze
        @ranges.freeze
      end

      # 返回匹配地址的全部设备区域和地址类型候选。
      def matches(address, device_id:, protected:, snapshot: nil)
        candidates(address, device_id: device_id, protected: protected, snapshot: snapshot)
      end

      # 快照加载前只检查范围相交，保留后续按实际 VRF 合并分段的机会。
      def overlap?(address, device_id:, protected:)
        raise ArgumentError, "保护区域状态必须是布尔值" unless [ true, false ].include?(protected)
        target = IPAddr.parse(address)
        @ranges.any? do |(range_device_id, range_protected, *), address_set|
          range_device_id == device_id && range_protected == protected && address_set.overlap?(target)
        end
      end

      # 归属只声明地址所在的区域；不能把唯一归属当成转发路径。
      def locate(address, device_id:, protected:, snapshot: nil)
        locations = matches(address, device_id: device_id, protected: protected, snapshot: snapshot)
        return locations.first if locations.size <= 1
        raise Error.new("设备 #{device_id} 的地址 #{address} 需要路由消歧", code: :ambiguous_zone) unless snapshot
        selected = route(address, snapshot: snapshot)
        domain = selected && (protected ? snapshot.egress_vrf(selected) : selected.vrf)
        locations = locations.select { |item| selected && item[:zone] == selected.zone && item[:vrf] == domain }
        unique_location(locations, address, device_id, required: true)
      end

      # 入站入口来自源地址所在区域，不能用内部 VRF 的回程路由证明。
      def ingress(address, snapshot:)
        locations = candidates(address, device_id: snapshot.device_id, protected: false, snapshot: snapshot, ingress: true)
        vrfs = locations.map { |item| item[:vrf] }.uniq
        if locations.size > 1 && vrfs.one? && vrfs.first && locations.none? { |item| item[:mode] == :transparent }
          # 同一已知路由域内用最长前缀区分直连网段和默认出口，不借用目的域。
          selected = route(address, snapshot: snapshot, vrf: vrfs.first)
          locations = locations.select do |item|
            selected && item[:zone] == selected.zone && snapshot.egress_vrf(selected) == item[:vrf]
          end
          return unique_location(locations, address, snapshot.device_id, required: true)
        end
        unique_location(locations, address, snapshot.device_id)
      end

      # 有三层路由时始终查表，再检查网络投影；单个候选也不能绕过 VRF。
      def egress(address, snapshot:, source: nil, vrf: nil, source_zone: nil, transparent: false)
        if transparent || snapshot.routes.empty?
          locations = candidates(address, device_id: snapshot.device_id, protected: false, snapshot: snapshot, ingress: true)
          locations = locations.select { |item| item[:vrf] == vrf } unless transparent
          return unique_location(locations, address, snapshot.device_id)
        end

        selected = route(address, snapshot: snapshot, source: source, vrf: vrf, source_zone: source_zone,
                          external_zone: source ? nil : "exrouter")
        return unless selected
        # exrouter 只表示本设备不评估该路径，不构成跨 VRF 可达证明。
        return { zone: "exrouter", address_type: :extra, vrf: selected.vrf } if selected.zone == "exrouter"

        locations = candidates(address, device_id: snapshot.device_id, protected: false, snapshot: snapshot, route: selected)
        location = unique_location(locations, address, snapshot.device_id)
        location&.merge(vrf: snapshot.egress_vrf(selected))
      end

      # 选路不提前过滤区域；源路由即使未限制目的范围也必须参与判断。
      def route(address, snapshot:, source: nil, vrf: nil, source_interface: nil, source_zone: nil,
                protocol: nil, source_port: nil, destination_port: nil, external_zone: nil)
        snapshot.require_complete!
        target = IPAddr.parse(address)
        table = Elements::RoutingTable.new(snapshot.routes)
        # 没有源上下文时只查静态路由，仍共用部分命中不能回退的范围证明。
        if source
          table.lookup(source: source, destination: target, vrf: vrf,
                       source_interface: source_interface, source_zone: source_zone, protocol: protocol,
                       source_port: source_port, destination_port: destination_port)
        else
          table.lookup_static(destination: target, vrf: vrf, external_zone: external_zone)
        end
      rescue Elements::RoutingTable::ConditionalRoute => error
        raise Error.new(error.message, code: :conditional_route)
      end

      # 区域筛选是选路结果的投影；外部路由例外仅用于排除本设备。
      def route_zone(address, snapshot:, zones:, source: nil, vrf: nil, **context)
        selected = route(address, snapshot: snapshot, source: source, vrf: vrf, external_zone: "exrouter", **context)
        selected.zone if selected && (zones.include?(selected.zone) || (!source && vrf && selected.zone == "exrouter"))
      end

      private

      # 先补齐旧人工记录的上下文再合并范围，避免同域两段被误判为不覆盖。
      # 路由投影的 VRF 是查表域；入站归属改由出口区域的物理上下文确定。
      def candidates(address, device_id:, protected:, snapshot:, route: nil, ingress: false)
        raise ArgumentError, "保护区域状态必须是布尔值" unless [ true, false ].include?(protected)
        snapshot&.require_complete!

        target = IPAddr.parse(address)
        ranges = {}
        @ranges.each do |(range_device_id, range_protected, zone, address_type, vrf, mode), address_set|
          next unless range_device_id == device_id && range_protected == protected && address_set.overlap?(target)
          next if route && (zone != route.zone || (vrf && vrf != route.vrf))

          scope = snapshot&.catalog&.find(Elements::Zone, name: zone)
          mode = scope.mode if scope
          mode ||= :routed if vrf
          if mode == :transparent
            vrf = nil
          elsif scope && (protected || ingress || vrf.nil?)
            physical_vrf = snapshot.vrf(zone)
            if protected && vrf && vrf != physical_vrf
              raise Error.new("安全域 #{zone} 的路由域与保护网络声明不一致", code: :conditional_route)
            end
            vrf = physical_vrf if ingress
            vrf ||= (route && snapshot.egress_vrf(route) == physical_vrf) ? route.vrf : physical_vrf
          end
          next if route && vrf != route.vrf

          key = { zone: zone, address_type: address_type, vrf: vrf, mode: mode }
          ranges[key] = ranges.fetch(key, Set.new) | address_set
        end
        ranges.filter_map { |location, set| location if set.cover?(target) }
              .sort_by { |row| [ row[:zone], row[:address_type].to_s, row[:vrf].to_s, row[:mode].to_s ] }
      end

      def unique_location(locations, address, device_id, required: false)
        return locations.first if locations.one? || (locations.empty? && !required)

        raise Error.new("无法确定地址 #{address} 在设备 #{device_id} 的区域，请检查范围和路由", code: :ambiguous_zone)
      end
    end
  end
end
