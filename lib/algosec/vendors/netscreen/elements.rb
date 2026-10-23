# frozen_string_literal: true

require_relative "../../elements/definition"

module Algosec
  module Vendors
    module Netscreen
      # ScreenOS 的作用域、Global 地址和策略身份约定。
      class Elements < Algosec::Elements::Definition
        identity :address, :zone, :name
        identity :address_group, :zone, :name
        identity :rule, :native_rule_id
        defaults scoped_addresses?: true
        defaults schedule_requires_start?: true
        defaults static_nat_set_mode: :explicit
        defaults static_nat_any_destination?: true
        defaults default_vrf: "trust-vr"

        class << self
          def nat_stage(nat)
            return :mip if nat.is_a?(Algosec::Elements::StaticNat)
            return :policy if nat.policy_id
            :vip if nat.direction == :destination && nat.destination_ip
          end

          # ScreenOS 源地址路由按最长源前缀，再按管理距离和 metric 选择。
          def policy_route_rank(route, index) = [ route.source_set&.cardinality || IPAddr::IPV4_MAX + 1, route.distance, route.priority ]

          def dynamic_nat_identity(object) = object.policy_id.nil? ? [ object.destination_ip, object.destination_port, object.protocol ] : [ object.policy_id ]

          def address_zones(zone) = [ zone, "Global" ].uniq

          def service_ports(protocol, source, destination) = [ source, destination ]

          def rule_action(action) = action

          def schedule_format(value) = "%m/%d/%Y %H:%M"

          def validate_rule(rule, action:)
            if rule.from_zones.nil? || rule.to_zones.nil?
              raise ArgumentError, "Netscreen rules require both zones"
            end
            raise ArgumentError, "An action is required" if action.nil?
          end

          def validate_static_nat(nat)
            require_mapped_zone(nat)
            require_real_zone(nat)
            raise ArgumentError, "Netscreen static NAT requires a mask" if nat.mask.nil?
            super
          end

          def validate_dynamic_nat(nat)
            require_direction(nat)
            require_source_zone(nat)
            raise ArgumentError, "A destination zone is required" if nat.to_zone.nil?
          end
        end
      end
    end
  end
end
