# frozen_string_literal: true

require_relative "../../policy"

module Algosec
  module Vendors
    module Huawei
      # 提供 Huawei 地址方向、私网对端和大小写不敏感区域行为。
      class Policy < Algosec::Policy::Behavior
        ADDRESS_MAPPING = { plain: :origin, infer_same_device: true, private_destination: true,
                            source_direction: true, destination_direction: true }.freeze
        # Huawei 不从策略自动推断私网对端。
        def infer_private_peers? = false

        def matches_translated_service? = true

        # Server-map 先于策略 NAT，同层映射不能依靠类型或名称排序任选一条。
        def nat_groups
          servers = snapshot.active_dynamic_nats.select { |nat| nat.rule_set == "nat-server" }
          [ snapshot.active_static_nats + servers ]
        end

        # 整条策略使用原生顺序，不按所查询的转换方向分别选择。
        def nat_policy_rules
          policies = snapshot.active_dynamic_nats.reject { |nat| nat.rule_set == "nat-server" }
          orders = policies.map(&:nat_order)
          valid = policies.all? do |nat|
            priority = { source: 1, destination: 0, bidirectional: 0 }[nat.direction]
            nat.nat_order&.size == 2 && nat.nat_order.first == priority
          end
          unless valid && orders.uniq.size == orders.size
            raise Algosec::Policy::Error.new("Huawei NAT 策略执行顺序尚未完整解析", code: :conditional_nat)
          end
          policies.sort_by(&:nat_order)
        end

        # 未提供区域时只允许无区域限制的完整命中；未知出口仍是潜在命中。
        def nat_flow_matches?(nat, flow:, relation:)
          conditions = nat.extra_conf["match"]
          unless conditions
            raise Algosec::Policy::Error.new("Huawei NAT 缺少原生匹配条件", code: :conditional_nat)
          end
          return false unless nat_zone_matches?(nat.from_zone, flow[:from_zone], relation: relation)

          limited_zone = conditions["to_zone"] && !conditions["to_zone"].casecmp?("any")
          route = nat_route(nat, flow) if conditions["interface"] || (nat.destination_targets && limited_zone)
          to_zone = nat.destination_targets ? route&.zone : flow[:to_zone]
          return false unless nat_zone_matches?(conditions["to_zone"], to_zone, relation: relation)
          return true unless conditions["interface"]
          return relation == :overlap? unless route&.destination_interface

          route.destination_interface == conditions["interface"]
        end

        # Easy-IP 的解析投影必须与本次流量的最终出口一致；失败后不能换下一条规则。
        def validate_nat_target!(nat, flow:)
          return unless nat.extra_conf["source_mode"] == "easy-ip"

          route = nat_route(nat, flow)
          unless route && route.destination_interface == nat.interface && snapshot.egress_vrf(route) == nat.vrf
            raise Algosec::Policy::Error.new("Huawei Easy-IP 无法证明所选规则的出口地址", code: :conditional_nat)
          end
        end

        def static_nat_zone?(nat, zone) = nat.mapped_zone.nil? || zone_matches?([ nat.mapped_zone ], zone)

        def reverse_nat_zone?(nat, zone) = static_nat_zone?(nat, zone)

        def dynamic_nat_zone?(nat, zone, direction:)
          actual = direction == :source ? nat.to_zone : nat.from_zone
          actual.nil? || zone_matches?([ actual ], zone)
        end

        # 接口条件独立于区域：同一区域的另一出口不能复用该条策略 NAT。
        def nat_acl_matches?(nat, sources:, destinations:, services:, relation:)
          return true unless nat.rule_set == "nat-policy" && nat.interface
          return relation == :overlap? unless sources && destinations

          route = Algosec::Elements::RoutingTable.new(snapshot.routes).lookup(source: sources, destination: destinations, vrf: nat.vrf)
          return relation == :overlap? unless route&.destination_interface
          route.destination_interface == nat.interface
        rescue Algosec::Elements::RoutingTable::ConditionalRoute
          relation == :overlap?
        end

        protected

        def nat_zone_matches?(actual, requested, relation:)
          return true if actual.nil? || actual.casecmp?("any")
          return relation == :overlap? unless requested

          zone_matches?([ actual ], requested)
        end

        # 选路发生在目的转换之后、源转换之前，入口 VRF 不从输出接口倒推。
        def nat_route(nat, flow)
          destination = nat.destination_targets || flow[:destination]
          return unless flow[:source] && destination && flow[:from_zone]

          vrf = flow[:vrf] || snapshot.vrf(flow[:from_zone])
          return unless vrf

          Algosec::Elements::RoutingTable.new(snapshot.routes).lookup(
            source: flow[:source], destination: destination, vrf: vrf, source_zone: flow[:from_zone])
        rescue Algosec::Elements::RoutingTable::ConditionalRoute
          nil
        end

        # 设备区域名称大小写不影响匹配结果。
        def zone_equal?(actual, requested) = actual.casecmp?(requested)
      end
    end
  end
end
