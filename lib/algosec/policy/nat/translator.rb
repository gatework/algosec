# frozen_string_literal: true

require_relative "resolver"

module Algosec
  module Policy
    module Nat
      # 将请求换算为策略匹配地址；厂商子类只实现其转换语义。
      class Translator
        def self.build(snapshot) = snapshot.behavior.nat_translator.new(snapshot)

        # 保存快照、NAT 解析器和设备地址转换选项。
        def initialize(snapshot)
          @snapshot, @nat, @options = snapshot, Nat::Resolver.new(snapshot), snapshot.behavior.address_mapping
        end

        # 每次调用独立复制记录；同一地址在不同设备或区域不会共享 NAT 修改。
        def map(addresses, side:, mode:, hit:, zone:, peers:, services:, same_device: false, flow: {})
          context = { side: side, mode: mode, hit: hit, zone: zone, peers: peers, services: services, same_device: same_device,
                      flow: Value.immutable(@snapshot.behavior.nat_query_flow(flow)) }
          real_zones = []
          mapped_entries = addresses.each_with_object({}) do |(address, request_entry), output|
            address_entry = Value.copy(request_entry)
            context[:real_zone] = nil
            mapped_address = map_address(address, address_entry, context)
            raise Error.new("无法确定地址 #{address} 的策略匹配地址", code: :nat_missing) unless mapped_address
            if output.key?(mapped_address) && output[mapped_address] != address_entry
              raise Error.new("多个地址在 #{mapped_address} 上具有不同的 NAT 条件", code: :ambiguous_nat)
            end
            output[mapped_address] = address_entry
            real_zones << context[:real_zone] if context[:real_zone]
          end
          raise Error, "同组地址对应多个内部区域" if real_zones.uniq.size > 1
          [ mapped_entries, real_zones.first ]
        end

        private

        # 根据查询方向、命中维度和设备模式选择主地址或 NAT 映射路径。
        def map_address(address, address_entry, context)
          main = address_entry[:main] || address_entry[:origin]
          return (@options[:plain] == :fallback) ? main : address_entry[@options[:plain]] if context[:mode] == 0
          case [ context[:hit], context[:side] ]
          when [ :source, :source ]
            if address_entry[:private]
              same_device = context[:same_device] || (@options[:infer_same_device] && @nat.private_peers?(context[:peers]))
              map_source(address, address_entry, context) unless same_device
            else
              direction = context[:same_device] ? nil : :source
              zone = context[:same_device] ? nil : context[:zone]
              address_entry[:private], context[:real_zone] = @nat.reverse(address, zone: zone, direction: direction)
            end
            address_entry[:private]
          when [ :source, :destination ]
            if context[:same_device]
              address_entry[:private], context[:real_zone] = @nat.reverse(address) unless address_entry[:private]
              address_entry[:private]
            elsif context[:mode] == 1
              main
            else
              map_peer(address, address_entry, context)
            end
          when [ :destination, :source ] then main
          when [ :destination, :destination ] then map_destination(address, address_entry, context)
          end
        end

        # 解析源地址已有 NAT，否则创建所需的动态或静态 NAT 条件。
        def map_source(address, address_entry, context)
          existing_nat = find_nat(address_entry[:private], address_entry, context, direction: :source)
          allocation = address_entry[:nat]
          if existing_nat && (existing_nat[:type] == :static || allocation.nil? || @nat.terminal?(existing_nat))
            address_entry[:nat] = existing_nat
            return
          end
          if allocation && allocation[:type] == :static && @options[:source_pools]
            @nat.pools(address_entry[:private], zone: context[:zone]).each do |nat|
              if @nat.policy_uses?(address, direction: :source, nat: nat)
                allocation[:type], allocation[:option] = :dynamic, "sd"
              end
            end
          end
          address_entry[:nat] ||= { type: :dynamic }
          address_entry[:nat][:type] = :dynamic unless allocation || @options[:keep_source]
          address_entry[:nat][:direction] = :source if @options[:source_direction]
          address_entry[:nat][:option] ||= "sd" if @options[:rule_sets] && address_entry[:nat][:type] == :dynamic
          address_entry[:action], address_entry[:real_ip] = :new_nat, address_entry[:private]
          address_entry[:rule_set] = @nat.rule_set(:source, zone: context[:zone], type: address_entry[:nat][:type]) if @options[:rule_sets]
          source_interface = @options[:source_interface]
          address_entry[:nat][:interface] ||= @nat.interface(context[:zone]) if source_interface == true || (source_interface == :static && address_entry[:nat][:type] == :static)
        end

        # 解析目标地址 NAT，必要时校验调用方提供的分配信息。
        def map_peer(address, address_entry, context)
          existing_nat = find_nat(address, address_entry, context, direction: :destination)
          main = address_entry[:main] || address_entry[:origin]
          if existing_nat
            address_entry[:nat] = existing_nat
            return @options[:rule_sets] ? main : existing_nat[:address]
          end
          validate_allocation!(address, address_entry, zone: context[:zone])
          if @options[:rule_sets] && address_entry[:nat][:type] != :static
            raise Error.new("区域 #{context[:zone]} 的目标 #{address} 需要静态 NAT 分配", code: :nat_missing)
          end
          address_entry[:action], address_entry[:real_ip] = :new_nat, main
          address_entry[:rule_set] = @nat.rule_set(:destination, zone: context[:zone], type: address_entry[:nat][:type]) if @options[:rule_sets]
          address_entry[:nat][:interface] ||= @nat.interface(context[:zone]) if @options[:peer_interface]
          @options[:rule_sets] ? main : address_entry[:nat][:address]
        end

        # 处理目标维度的私网还原、NAT 查找和新分配记录。
        def map_destination(address, address_entry, context)
          private_target = @options[:private_destination]
          if private_target && !address_entry[:private]
            address_entry[:private], context[:real_zone] = @nat.reverse(address, zone: context[:zone])
          elsif !private_target
            return address_entry[:origin] if !@options[:always_destination] && @nat.private_peers?(context[:peers])
            if address_entry[:main] == address_entry[:origin]
              address_entry[:private], context[:real_zone] = @nat.reverse(address_entry[:main], zone: context[:zone]) unless address_entry[:private]
              address_entry[:real_ip] = address_entry[:private]
            end
          end
          existing_nat = find_nat(address_entry[:private] || address, address_entry, context, direction: :destination)
          if existing_nat
            address_entry[:nat] = existing_nat
            return private_target ? address_entry[:private] : existing_nat[:address]
          end
          validate_allocation!(address, address_entry, zone: context[:zone])
          nat = address_entry[:nat]
          if nat[:type] == :static && (private_target || @options[:destination_pools])
            @nat.pools(address_entry[:private] || address, zone: context[:zone]).each do |pool|
              if @nat.policy_uses?(address, direction: :source, nat: pool)
                nat[:type], nat[:option] = :dynamic, "sd"
              end
            end
          end
          nat[:direction] = :destination if @options[:destination_direction]
          address_entry[:action], address_entry[:real_ip] = :new_nat, address_entry[:private] || address
          address_entry[:rule_set] = @nat.rule_set(:destination, zone: context[:zone], type: nat[:type]) if @options[:rule_sets]
          interface = @options[:destination_interface]
          nat[:interface] ||= @nat.interface(context[:zone]) if interface == :all || (interface == :static && nat[:type] == :static)
          private_target ? address_entry[:private] : nat[:address]
        end

        # 两侧区域和明确的公网目的随查询传递；分配意图不能覆盖已有终结规则。
        def find_nat(address, address_entry, context, direction:)
          flow = context[:flow].dup
          if direction == :destination
            flow[:original_dst] ||= address_entry[:main] || address_entry.dig(:nat, :address)
            flow[:to_zone] = context[:real_zone] if context[:real_zone]
          end
          @nat.find(address, zone: context[:zone], peers: context[:peers], direction: direction,
                    services: context[:services], flow: flow, allocation: address_entry[:nat])
        end

        # 检查 NAT 分配完整性，并拒绝已经占用的静态地址。
        def validate_allocation!(address, address_entry, zone:)
          nat = address_entry[:nat]
          unless nat && %i[static dynamic].include?(nat[:type]) && nat[:address]
            raise Error.new("地址 #{address} 没有对应的 NAT 地址，请先分配", code: :nat_missing)
          end
          if nat[:type] == :static && @nat.used?(nat[:address], zone: zone)
            raise Error.new("NAT 地址 #{nat[:address]} 已被使用，请重新分配", code: :nat_in_use)
          end
        end
      end
    end
  end
end
