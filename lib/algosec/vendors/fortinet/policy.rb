# frozen_string_literal: true

require_relative "../../policy"

module Algosec
  module Vendors
    module Fortinet
      # 提供 FortiOS 策略内嵌 NAT 和精确策略候选行为。
      class Policy < Algosec::Policy::Behavior
        ADDRESS_MAPPING = { plain: :origin, infer_same_device: true, source_interface: :static, destination_interface: :all }.freeze

        def policy_embeds_nat? = true

        def nat_policy_id(nat) = nat.policy_id || nat.name

        def static_nat_source?(nat) = nat.source_nat_enabled == true

        def static_nat_zone?(nat, zone) = nat.mapped_zone == "any" || nat.mapped_zone == zone

        # 只接受动作、源区域和目标区域都匹配的策略。
        def candidate?(rule, from_zone:, to_zone:)
          exact_candidate?(rule, action: "allow", from_zone: from_zone, to_zone: to_zone)
        end

        # 保留原始接口字段；只在接口选择与整个区域等价时消除额外匹配条件。
        def unresolved_network_conditions?(rule)
          !rule.from_vlans.empty? || !rule.to_vlans.empty? ||
            !interfaces_cover_zones?(Array(rule.from_interface), rule.from_zones) ||
            !interfaces_cover_zones?(rule.dst_interfaces, rule.to_zones)
        end

        private

        def interfaces_cover_zones?(names, zones)
          return true if names.empty?
          return false if zones.nil? || zones.empty? || zones.include?("any")
          zones.all? do |name|
            zone = snapshot.catalog.find(Algosec::Elements::Zone, name: name)
            zone && !zone.interfaces.empty? && (zone.interfaces.values.map(&:name) - names).empty?
          end
        end
      end
    end
  end
end
