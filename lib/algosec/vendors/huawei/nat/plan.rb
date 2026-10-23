# frozen_string_literal: true

require_relative "../../../vendors"
require_relative "../../../policy/ranges"

module Algosec
  module Vendors
    module Huawei
      module Nat
        # 把同批分配编译为不互相遮挡的 NAT 规则；不分配设备名称或发射命令。
        class Plan
          Rule = Data.define(:owner, :from_zone, :to_zone, :ranges, :source, :destination) do
            def key
              { from_zone: from_zone.downcase, to_zone: to_zone.downcase, ranges: ranges,
                source: source, destination: destination }
            end
          end
          ANY_ADDRESS = Set.new(0..IPAddr::IPV4_MAX)
          ANY_SERVICE = Set.new(0..IPAddr::SERVICE_MAX)
          DIMENSIONS = %i[sources destinations services].freeze
          private_constant :Rule, :ANY_ADDRESS, :ANY_SERVICE, :DIMENSIONS

          attr_reader :rules

          def initialize(results)
            @static = Hash.new { |entries, owner| entries[owner] = [] }
            sources, destinations = [], []
            results.each do |result|
              actions = result.actions || {}
              keys = result.type == :modify ? %i[new add] : [ :new ]
              keys.each do |key|
                action = actions.fetch(key, {})
                sources.concat(allocations(result, action.fetch(:nat_sources, {}), :source))
                destinations.concat(allocations(result, action.fetch(:nat_destinations, {}), :destination))
              end
            end
            sources = unique_rules(sources)
            destinations = unique_rules(destinations)
            validate_allocations!(sources)
            validate_allocations!(destinations)
            @rules = destinations.flat_map { |destination| combine(destination, sources) } + sources
            validate_static_overlap!
            @rules.freeze
          end

          def rules_for(result) = rules.select { |rule| rule.owner.equal?(result) }

          def static_for(result) = @static.fetch(result, [])

          # 跨 render 的旧命令不能重新切分；重叠且转换不同必须合成一次批次再设计。
          def validate_prior!(previous)
            claims.each do |current|
              next if previous.include?(current)

              previous.each do |prior|
                next unless overlap?(current, prior)
                next if current.values_at(:source, :destination) == prior.values_at(:source, :destination)

                conflict!("新旧生成批次存在不同的 NAT 转换，请合并需求后重新设计")
              end
            end
          end

          def claims = rules.map(&:key) + static_claims

          private

          def allocations(result, records, direction)
            raise Algosec::Policy::Error, "NAT 记录必须是 Hash" unless records.is_a?(Hash)
            values = records.sort.map(&:last)
            values.each do |record|
              nat = record[:nat]
              unless nat && %i[static dynamic].include?(nat[:type])
                raise Algosec::Policy::Error, "NAT 类型必须是 static 或 dynamic"
              end
              IPAddr.parse(record.fetch(:real_ip))
              IPAddr.parse(nat.fetch(:address)) if nat[:address] || nat[:type] == :static || direction == :destination
              if nat[:direction] && nat[:direction].to_s != direction.to_s
                conflict!("NAT 分配方向与所在地址维度不一致")
              end
              if nat[:option] && (!nat[:option].is_a?(String) || !/\A[sd]*\z/.match?(nat[:option]))
                conflict!("Huawei NAT option 只能包含 s 或 d")
              end
            end
            static, dynamic = values.partition { |record| record[:nat][:type] == :static }
            @static[result].concat(static.map { |record| [ record, direction ] })
            dynamic.group_by { |record| [ record[:nat].except(:rule), record[:rule_set] ] }.values.flat_map do |group|
              allocation(result, group, direction)
            end
          end

          def allocation(result, records, direction)
            nat = records.first.fetch(:nat)
            if nat[:rule]
              conflict!("已有 NAT 不能当作新建分配再次生成")
            end
            if (result.sources.values + result.destinations.values).any? { |entry| entry.dig(:nat, :rule) }
              conflict!("新建 NAT 与请求中已有映射的组合需要明确修改原规则")
            end
            real = Algosec::Policy::Ranges.addresses(records.map { |record| record.fetch(:real_ip) })
            options = nat[:option].to_s
            sources = direction == :source ? real : options.include?("s") ? original_addresses(result, :sources) : ANY_ADDRESS
            destinations = direction == :destination ? IPAddr.parse(nat.fetch(:address)) : options.include?("d") ? original_addresses(result, :destinations) : ANY_ADDRESS
            target = direction == :destination ? real : nat[:address] && IPAddr.parse(nat[:address])
            action = { target: target, interface: nat[:interface], pool_name: nat[:pool_name] }.freeze
            if !target && action[:pool_name]
              conflict!("Easy-IP 分配不能同时指定地址池")
            end
            ports = direction == :destination ? destination_services(result) : [ [ ANY_SERVICE, nil ] ]
            ports.map do |services, port|
              Rule.new(owner: result, from_zone: result.from_zone, to_zone: result.to_zone,
                ranges: { sources: sources, destinations: destinations, services: services }.freeze,
                source: direction == :source ? action : nil,
                destination: direction == :destination ? action.merge(port: port).freeze : nil)
            end
          end

          # 安全策略使用目的转换后的地址；NAT 必须还原到报文的原始匹配地址。
          def original_addresses(result, dimension)
            values = result.public_send(dimension).map do |value, entry|
              if dimension == :sources
                entry[:private] || entry[:main] || entry[:origin] || value
              else
                entry[:main] || entry.dig(:nat, :address) || entry[:origin] || value
              end
            end
            Algosec::Policy::Ranges.addresses(values)
          end

          def destination_services(result)
            return [ [ ANY_SERVICE, nil ] ] unless result.services.values.any? { |entry| entry[:translated_port] }

            result.services.map do |value, entry|
              original = entry.fetch(:origin, value)
              protocol, ports = original.split("/", 2)
              before = IPAddr.ports(ports) if ports
              after = IPAddr.ports(entry[:translated_port] || value.split("/", 2).last) if ports
              unless [ IPAddr::TCP, IPAddr::UDP ].include?(IPAddr.protocol_number(protocol)) && before&.cardinality == 1 && after&.cardinality == 1 && after.min.positive?
                raise Algosec::Policy::Error.new("Huawei 端口转换需要 TCP/UDP 单端口及非零目标端口", code: :unsupported_port_nat)
              end
              [ Algosec::Policy::Ranges.service(original), after.min ]
            end.uniq
          end

          def unique_rules(rules) = rules.uniq(&:key)

          def validate_allocations!(rules)
            rules.combination(2) do |left, right|
              next unless overlap?(left.key, right.key)
              next if left.source == right.source && left.destination == right.destination

              conflict!("同一原始流量对应不同的同方向 NAT 分配")
            end
          end

          # 逐步从目的规则扣除已组合区域，剩余规则与双向规则不相交。
          def combine(destination, sources)
            remaining, combined = [ destination ], []
            sources.each do |source|
              remaining = remaining.flat_map do |part|
                overlap = intersection(part.key, source.key)
                next part unless overlap

                combined << part.with(ranges: overlap, source: source.source)
                subtract(part.ranges, overlap).map { |ranges| part.with(ranges: ranges) }
              end
            end
            combined + remaining
          end

          def intersection(left, right)
            return unless %i[from_zone to_zone].all? { |zone| left[zone].nil? || right[zone].nil? || left[zone] == right[zone] }

            ranges = DIMENSIONS.to_h { |dimension| [ dimension, left[:ranges].fetch(dimension) & right[:ranges].fetch(dimension) ] }
            ranges.freeze unless ranges.values.any?(&:empty?)
          end

          def overlap?(left, right) = !intersection(left, right).nil?

          def subtract(ranges, overlap)
            remaining, core = [], ranges
            DIMENSIONS.each do |dimension|
              difference = core.fetch(dimension) - overlap.fetch(dimension)
              remaining << core.merge(dimension => difference).freeze unless difference.empty?
              core = core.merge(dimension => overlap.fetch(dimension))
            end
            remaining
          end

          # 静态服务器映射的两侧作用仍独立，不能悄悄参与原生策略组合。
          def static_claims
            @static.flat_map do |owner, records|
              records.flat_map do |record, direction|
                real = IPAddr.parse(record.fetch(:real_ip))
                mapped = IPAddr.parse(record.fetch(:nat).fetch(:address))
                zone = direction == :source ? owner.to_zone : owner.from_zone
                [ { from_zone: nil, to_zone: zone.downcase, ranges: { sources: real, destinations: ANY_ADDRESS, services: ANY_SERVICE }, source: { static: mapped }, destination: nil },
                  { from_zone: zone.downcase, to_zone: nil, ranges: { sources: ANY_ADDRESS, destinations: mapped, services: ANY_SERVICE }, source: nil, destination: { static: real } } ]
              end
            end
          end

          def validate_static_overlap!
            rules.each do |rule|
              static_claims.each do |server|
                scope = server.merge(from_zone: server[:from_zone] || rule.from_zone.downcase, to_zone: server[:to_zone] || rule.to_zone.downcase)
                conflict!("服务器映射与策略 NAT 的组合转换尚未建模") if overlap?(rule.key, scope)
              end
            end
          end

          def conflict!(message)
            raise Algosec::Policy::Error.new(message, code: :nat_scope_conflict)
          end
        end
      end
    end
  end
end
