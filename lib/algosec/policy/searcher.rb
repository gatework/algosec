# frozen_string_literal: true

require "active_support/core_ext/hash/except"
require "active_support/time"
require_relative "request"
require_relative "report"
require_relative "rule_matcher"
require_relative "nat/translator"
require_relative "network_locator"
require_relative "evaluation"

module Algosec
  module Policy
    class Searcher
      # 快照参数接收“设备编号到 Snapshot”的映射，或调用方提供的加载函数。
      # 数据来源和数据库连接均归调用方，查询对象没有跨请求缓存。
      #
      # 建立一次查询所需的网络索引、快照加载器和时钟。
      def initialize(networks:, snapshots:, clock: -> { Time.current }, definition: nil)
        @networks, @snapshots, @clock, @definition = networks, snapshots, clock, definition
      end

      # 捕获查询异常并返回失败报告。
      def perform(request)
        perform!(request)
      rescue => error
        Report.new(error: error)
      end

      # 解析请求，定位源目的设备和区域，构造分组后交给规则匹配器。
      def perform!(request)
        request = Request.new(**Value.hash(request)) unless request.is_a?(Request)
        network_locator = NetworkLocator.new(@networks, definition: @definition)
        snapshot_cache = {}
        load_snapshot = lambda do |device_id|
          snapshot_cache.fetch(device_id) do
            snapshot = @snapshots.respond_to?(:call) ? @snapshots.call(device_id) : @snapshots.fetch(device_id)
            unless snapshot.is_a?(Snapshot) && snapshot.device_id == device_id && snapshot.vendor == network_locator.devices.fetch(device_id)[:vendor]
              raise Error, "设备 #{device_id} 的配置快照不匹配"
            end
            snapshot.require_complete!
            snapshot_cache[device_id] = snapshot
          end
        end
        locations = { sources: {}, destinations: {} }
        locations.each do |dimension, entries|
          request.public_send(dimension).each_key do |address|
            entries[address] = network_locator.devices.each_key.each_with_object({}) do |device_id, device_locations|
              next unless network_locator.overlap?(address, device_id: device_id, protected: true)
              location = network_locator.locate(address, device_id: device_id, protected: true, snapshot: load_snapshot.call(device_id))
              device_locations[device_id] = location if location
            end
          end
        end
        unless locations.values.any? { |entries| entries.values.any? { |device_locations| !device_locations.empty? } }
          raise Error.new("输入地址均未命中防火墙", code: :no_firewall)
        end
        groups, skipped = [], []
        expected = request.sources.keys.product(request.destinations.keys, request.services.keys).to_h { |combination| [ combination, [] ] }
        request.sources.each do |source, source_entry|
          request.destinations.each do |destination, destination_entry|
            source_locations = locations[:sources].fetch(source)
            destination_locations = locations[:destinations].fetch(destination)
            devices = (source_locations.keys | destination_locations.keys).sort
            record_skip(skipped, source, destination, request.services, nil, :unmatched) if devices.empty?
            devices.each do |device_id|
              source_location, destination_location = source_locations[device_id], destination_locations[device_id]
              snapshot = load_snapshot.call(device_id)
              sources = local_entry(source, source_entry, source_location, snapshot)
              destinations = local_entry(destination, destination_entry, destination_location, snapshot)
              unless source_location
                sources[:main] = remote_main_address(source, source_entry, source_locations, destinations,
                                                     network_locator, load_snapshot, direction: :source, services: request.services)
              end
              unless destination_location
                destinations[:main] = remote_main_address(destination, destination_entry, destination_locations, sources,
                                                          network_locator, load_snapshot, direction: :destination, services: request.services)
              end
              group = build_group(network_locator.devices.fetch(device_id), snapshot, network_locator, sources, destinations,
                                  source_location, destination_location, request.services)
              if group
                groups << group
                request.services.each_key { |service| expected.fetch([ source, destination, service ]) << device_id }
              else
                record_skip(skipped, source, destination, request.services, device_id, :outside)
              end
            end
          end
        end
        if request.services.values.any? { |record| record[:translated_port] } &&
           groups.none? { |group| group[:destinations].values.any? { |entry| entry[:nat] } }
          raise Error.new("端口转换请求没有对应的目标 NAT", code: :nat_missing)
        end
        at = @clock.call
        results = combine(groups).flat_map { |group| load_snapshot.call(group[:device_id]).behavior.divide(group) }.map do |group|
          current = load_snapshot.call(group[:device_id])
          same_zone_coverage(current, group, at: at, schedule: request.schedule) ||
            RuleMatcher.new(current, at: at).match(group, schedule: request.schedule)
        end
        Report.new(results: results, skipped: skipped, expected: expected)
      end

      # 地址归属查询不加载配置、不猜测重叠区域；未匹配用 nil 明确表达。
      def device_info(addresses)
        raise ArgumentError, "地址必须是数组" unless addresses.is_a?(Array)

        network_locator = NetworkLocator.new(@networks, definition: @definition)
        addresses.flat_map do |address|
          address_text = IPAddr.format_range(IPAddr.parse(address).first)
          matches = network_locator.devices.filter_map do |device_id, device|
            zones = network_locator.matches(address_text, device_id: device_id, protected: true)
            device.merge(address: address_text, zone: zones.first[:zone]) if zones.one?
          end
          matches.empty? ? [ { address: address_text, device_id: nil, zone: nil } ] : matches
        end
      end

      private

      # 同区仍经过显式规则；只有完整、无时间与 NAT 限制的允许分区才无需新增策略。
      def same_zone_coverage(snapshot, group, at:, schedule:)
        return unless group[:from_zone] == group[:to_zone] && schedule.nil?
        return if snapshot.behavior.policy_embeds_nat?
        return if %i[sources destinations].any? { |dimension| group.fetch(dimension).values.any? { |entry| entry[:nat] || entry[:action] } }
        rules = snapshot.rules.select { |rule| snapshot.behavior.rule_in_zones?(rule, **group.slice(:from_zone, :to_zone)) }
        return if rules.any? { |rule| rule.starts_at || rule.expires_at || rule.schedule_name || rule.schedule }
        source, destination = %i[sources destinations].map { |dimension| Ranges.addresses(group.fetch(dimension).keys) }
        regions = group.fetch(:services).keys.map do |service|
          protocol, ports = service.split("/", 2)
          number = IPAddr.protocol_number(protocol)
          { family: :ipv4, source_addresses: source, destination_addresses: destination,
            protocols: protocol == "any" ? Set.new(0..255) : Set.new(number..number), source_ports: Set.new(0..65535),
            destination_ports: IPAddr.ports(ports || Elements::Definition::ANY_PORTS) }
        end
        result = Evaluation.new(snapshot, at: at).perform(TrafficSet.new(regions), **group.slice(:from_zone, :to_zone))
        if result.partitions.any? { |part| %i[unknown conditional].include?(part.status) }
          raise Error.new("同区规则含有不能确定的匹配条件", code: :conditional_policy)
        end
        return unless result.complete? && result.partitions.all? { |part| part.action == "allow" }
        Result.new(**group.slice(:device_id, :device_name, :vendor, :nat_mode, :from_zone, :to_zone, :hit, :sources, :destinations, :services),
          type: :ignore, snapshot: snapshot)
      end

      # 保留每个未评估的原始组合及其设备，不把跳过解释为已有覆盖。
      def record_skip(skipped, source, destination, services, device_id, reason)
        services.each_key do |service|
          skipped << { device_id: device_id, source: source, destination: destination, service: service, reason: reason }
        end
      end

      # 复制单个地址记录，并标记其在当前设备中的本地类型。
      def local_entry(address, request_entry, location, snapshot)
        entry = Value.copy(request_entry)
        entry[location ? location[:address_type] : :main] = address
        snapshot.behavior.augment_local_entry(address, entry, location)
        entry
      end

      # 每个源目标组合独立推导远端主地址，避免多出口之间覆盖 NAT 映射。
      def remote_main_address(address, request_entry, locations, peer, network_locator, load_snapshot, direction:, services:)
        return address if locations.empty?
        values = locations.map do |device_id, location|
          next address if location[:address_type] == :main
          snapshot = load_snapshot.call(device_id)
          peer_address = peer[:main] || peer[:origin]
          zone = if direction == :source
                   scope = local_scope(snapshot, location, location[:zone])
                   outgoing_zone(network_locator, snapshot, peer_address, source: address, scope: scope)
          else
                   incoming_zone(network_locator, snapshot, peer_address)
          end
          next address if zone[:address_type] == :extra || zone[:zone] == "exrouter"
          flow = if direction == :source
                   { from_zone: location[:zone], to_zone: zone[:zone], vrf: scope[:vrf] }
          else
                   scope = local_scope(snapshot, zone, zone[:zone])
                   { from_zone: zone[:zone], to_zone: location[:zone], vrf: scope[:vrf], original_dst: request_entry.dig(:nat, :address) }
          end
          nat = Nat::Resolver.new(snapshot).find(address, zone: zone[:zone], peers: { peer_address => peer }, direction: direction,
                                               services: services, flow: snapshot.behavior.nat_query_flow(flow), allocation: request_entry[:nat])
          nat&.fetch(:address) || request_entry.dig(:nat, :address) || address
        end.uniq
        if values.size > 1
          raise Error.new("地址 #{address} 在不同设备上对应不同的主地址", code: :ambiguous_nat)
        end
        values.first
      end

      # 计算一个源目的组合的真实区域、地址映射和策略服务集合。
      def build_group(device, snapshot, network_locator, source_entry, destination_entry, source_location, destination_location, services)
        hit = source_location ? :source : :destination
        from_zone = source_entry[:resolved_zone] || source_location&.fetch(:zone)
        to_zone = destination_entry[:resolved_zone] || destination_location&.fetch(:zone)
        from_scope = local_scope(snapshot, source_location, from_zone) if source_location && destination_location
        to_scope = local_scope(snapshot, destination_location, to_zone) if destination_location
        if source_location && !destination_location
          from_scope, outgoing = source_path(network_locator, snapshot, source_entry, destination_entry, source_location, mode: device[:nat_mode])
          return if outgoing[:address_type] == :extra || outgoing[:zone] == "exrouter"
          from_zone = from_scope[:zone]
          to_zone = outgoing[:zone]
        elsif destination_location && !source_location
          incoming = incoming_zone(network_locator, snapshot, source_entry[:main] || source_entry[:origin])
          return if incoming[:address_type] == :extra || incoming[:zone] == "exrouter"
          from_zone = incoming[:zone]
          from_scope = local_scope(snapshot, incoming, from_zone)
        end
        translator = Nat::Translator.build(snapshot)
        shared = { mode: device[:nat_mode], hit: hit, services: services, same_device: !!(source_location && destination_location) }
        shared[:flow] = snapshot.behavior.nat_query_flow(
          { from_zone: from_zone, to_zone: to_zone, vrf: from_scope&.fetch(:vrf),
            original_dst: destination_entry[:main] || destination_entry.dig(:nat, :address) })
        sources, real_from = translator.map({ source_entry[:origin] => source_entry }, side: :source, zone: to_zone,
                                            peers: { destination_entry[:main] || destination_entry[:origin] => destination_entry }, **shared)
        if real_from
          resolved = local_scope(snapshot, source_location, real_from)
          if !destination_location && resolved[:vrf] != from_scope[:vrf]
            raise Error.new("NAT 改变源路由域，缺少完整的跨域转换上下文", code: :conditional_nat)
          end
          from_scope = resolved
        end
        shared[:flow] = shared[:flow].merge(from_zone: real_from || from_zone, vrf: from_scope&.fetch(:vrf))
        peer_source = source_entry[:main] || source_entry[:origin]
        if device[:nat_mode] != 0 && snapshot.behavior.nat_policy_rules
          peer_source = sources.values.first[:private] || peer_source
        end
        destinations, real_to = translator.map({ destination_entry[:origin] => destination_entry }, side: :destination, zone: from_zone,
                                               peers: { peer_source => source_entry }, **shared)
        to_scope = local_scope(snapshot, destination_location, real_to) if real_to
        if device[:nat_mode] != 0 && snapshot.behavior.nat_policy_rules
          skipped_sides = if shared[:same_device]
                            %i[source destination]
          elsif hit == :destination
                            [ :source ]
          elsif device[:nat_mode] == 1
                            [ :destination ]
          else
                            []
          end
          original_dst = shared[:flow][:original_dst] || destinations.values.first.dig(:nat, :address) ||
                         destination_entry[:main] || destination_entry[:origin]
          mappings = { source: sources.values.first, destination: destinations.values.first }.transform_values do |entry|
            entry[:nat] unless entry[:action] == :new_nat
          end
          Nat::Resolver.new(snapshot).guard_unchanged!(source: peer_source, destination: original_dst, directions: skipped_sides,
            services: services, mappings: mappings,
            flow: shared[:flow].merge(from_zone: real_from || from_zone, to_zone: real_to || to_zone, vrf: from_scope&.fetch(:vrf)))
        end
        if destination_location
          # 策略地址可能保留 NAT 前的值，选路使用转换器记录的真实目标。
          validate_path!(network_locator, snapshot, sources.values.first, destinations.values.first, from_scope, to_scope)
        elsif real_from || sources.values.first[:private]
          # 还原源地址后策略路由可能改变，原主地址的出口证明不能继续沿用。
          confirmed = outgoing_zone(network_locator, snapshot, destination_entry[:main] || destination_entry[:origin],
                                    source: sources.values.first[:private] || source_entry[:origin], scope: from_scope)
          unless confirmed[:zone] == (real_to || to_zone) && confirmed[:address_type] != :extra
            raise Error.new("NAT 还原后的出口与转换时的区域不一致", code: :conditional_nat)
          end
        end
        device.merge(from_zone: real_from || from_zone, to_zone: real_to || to_zone, hit: hit,
                     sources: sources, destinations: destinations, services: policy_services(snapshot, services, destinations))
      end

      # 主地址先证明唯一的真实源，再决定入口域及出口；不能按可达性猜选 NAT。
      # 路径只读取原记录，避免预填 private 后让转换器误入“分配源 NAT”分支。
      def source_path(network_locator, snapshot, source, destination, location, mode:)
        source_addr = source[:private] || source[:origin]
        source_zone = source[:resolved_zone] || location[:zone]
        if mode != 0 && !source[:private]
          source_addr, real_zone = Nat::Resolver.new(snapshot).reverse(source[:origin], direction: :source)
          unless source_addr
            raise Error.new("无法确定主地址 #{source[:origin]} 的真实源地址", code: :nat_missing)
          end
          source_zone = real_zone || source_zone
        end
        scope = local_scope(snapshot, location, source_zone)
        outgoing = outgoing_zone(network_locator, snapshot, destination[:main] || destination[:origin], source: source_addr, scope: scope)
        [ scope, outgoing ]
      end

      # 请求服务描述转换前端口；匹配转换后端口的厂商使用内部端口，原始信息留给 NAT 生成。
      def policy_services(snapshot, services, destinations)
        local_nat = destinations.values.any? { |entry| entry[:nat] }
        after_nat = local_nat && snapshot.behavior.matches_translated_service?
        services.each_with_object({}) do |(value, request_service), mapped_services|
          service_entry = Value.copy(request_service)
          service_entry.delete(:translated_port) unless local_nat
          key = (after_nat && service_entry[:translated_port]) ? "#{value.split("/", 2).first}/#{service_entry[:translated_port]}" : value
          if mapped_services.key?(key) && mapped_services[key] != service_entry
            raise Error.new("多个外部服务映射到 #{key}，需要分别查询", code: :ambiguous_nat)
          end
          mapped_services[key] = service_entry
        end
      end

      # 查找非保护网络的出口区域，找不到时报告不可达错误。
      def outgoing_zone(network_locator, snapshot, address, source:, scope:)
        location = network_locator.egress(address, snapshot: snapshot, source: source, vrf: scope[:vrf],
                                           source_zone: scope[:zone], transparent: scope[:mode] == :transparent)
        return location if location
        raise Error.new("地址 #{address} 与设备 #{snapshot.device_id} 无连接，请检查区域及路由", code: :unreachable)
      end

      def incoming_zone(network_locator, snapshot, address)
        location = network_locator.ingress(address, snapshot: snapshot)
        return location if location
        raise Error.new("无法确定地址 #{address} 进入设备 #{snapshot.device_id} 的区域", code: :unreachable)
      end

      # 解析后的区域优先；人工透明区域可仅存在于网络声明，Global 别名须先还原。
      def local_scope(snapshot, location, zone)
        declared = location && location[:zone] == zone ? location : {}
        scope = snapshot.catalog.find(Elements::Zone, name: zone)
        mode = scope&.mode || declared[:mode]
        return { zone: zone, mode: mode, vrf: nil } if mode == :transparent

        vrf = scope ? snapshot.vrf(zone) : declared[:vrf]
        if vrf.nil? || (scope && declared[:vrf] && declared[:vrf] != vrf)
          raise Error.new("安全域 #{zone} 的路由域缺失或与网络声明不一致", code: :conditional_route)
        end
        { zone: zone, mode: :routed, vrf: vrf }
      end

      # 双端本地及入站流量都在入口 VRF 正向查真实目的，不以同设备或同区替代路径。
      def validate_path!(network_locator, snapshot, source, destination, from_scope, to_scope)
        return if [ from_scope, to_scope ].any? { |scope| scope[:mode] == :transparent }

        if snapshot.routes.empty?
          return if from_scope[:vrf] == to_scope[:vrf]
        else
          route = network_locator.route(destination[:private] || destination[:origin], snapshot: snapshot,
                                         source: source[:private] || source[:main] || source[:origin],
                                         source_zone: from_scope[:zone], vrf: from_scope[:vrf])
          return if route && route.zone == to_scope[:zone] && snapshot.egress_vrf(route) == to_scope[:vrf]
        end
        raise Error.new("设备 #{snapshot.device_id} 无法证明从 #{from_scope[:zone]} 到 #{to_scope[:zone]} 的转发路径", code: :unreachable)
      end

      # 仅合并一个不同维度；保留源目标组合，不通过分别求并集产生额外组合。
      def combine(groups)
        combined = []
        groups.each do |group|
          existing = combined.find do |candidate|
            next false unless candidate.except(:sources, :destinations) == group.except(:sources, :destinations)
            candidate[:sources] == group[:sources] || candidate[:destinations] == group[:destinations]
          end
          if existing
            existing[:sources] = existing[:sources].merge(group[:sources])
            existing[:destinations] = existing[:destinations].merge(group[:destinations])
          else
            combined << Value.copy(group)
          end
        end
        combined
      end
    end
  end
end
