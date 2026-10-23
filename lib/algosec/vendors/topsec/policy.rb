# frozen_string_literal: true

require_relative "../../policy"

module Algosec
  module Vendors
    module Topsec
      # 提供 Topsec VLAN 区域、地址方向和策略候选行为。
      class Policy < Algosec::Policy::Behavior
        ADDRESS_MAPPING = { plain: :origin, infer_same_device: true, private_destination: true,
                            source_direction: true, destination_direction: true }.freeze

        def infer_private_peers? = false

        def matches_translated_service? = true

        # 将显式区域与 VLAN 推导区域合并后判断规则是否可复用。
        def candidate?(rule, from_zone:, to_zone:)
          rule.action == "allow" && rule_in_zones?(rule, from_zone: from_zone, to_zone: to_zone)
        end

        def rule_in_zones?(rule, from_zone:, to_zone:)
          from = vlan_zones(rule.from_vlans) + Array(rule.from_zones)
          to = vlan_zones(rule.to_vlans) + Array(rule.to_zones)
          (from.empty? || from.include?(nil) || from.include?(from_zone)) &&
            (to.empty? || to.include?(nil) || to.include?(to_zone))
        end

        def unresolved_network_conditions?(rule)
          rule.from_interface || !rule.dst_interfaces.empty? ||
            unresolved_vlan?(rule.from_vlans) || unresolved_vlan?(rule.to_vlans)
        end

        private

        # nil 保留未知区域，不能据此排除可能优先命中的规则。
        def vlan_zones(vlans)
          (vlans || {}).keys.map { |name| snapshot.catalog.find(Algosec::Elements::Interface, name: name)&.zone }
        end

        # 未登记或未绑定区域的 VLAN 不能被当作没有区域限制。
        def unresolved_vlan?(vlans)
          vlan_zones(vlans).include?(nil)
        end
      end
    end
  end
end
