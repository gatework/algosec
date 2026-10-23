# frozen_string_literal: true

require_relative "../../elements/definition"

module Algosec
  module Vendors
    module Srx
      # SRX 的区域、VRF、应用和 NAT 身份约定。
      class Elements < Algosec::Elements::Definition
        identity :address, :zone, :name
        identity :address_group, :zone, :name
        identity :static_nat, :rule_set, :name
        identity :dynamic_nat, :rule_set, :name
        defaults scoped_addresses?: true
        defaults default_vrf: "default"
        defaults default_term: " "
        defaults schedule_requires_start?: true
        defaults default_nat_pool_direction: :source
        defaults static_nat_set_mode: :explicit
        defaults static_nat_any_destination?: true
        defaults dynamic_nat_empty_match?: true

        class << self
          # SRX 静态、目的、源转换各有规则集；不合并为单一策略序列。
          def nat_stage(nat) = nat.is_a?(Algosec::Elements::StaticNat) ? :static : nat.direction

          def address_zones(zone) = [ zone, "global" ].uniq

          def service_protocol(protocol, uuid) = uuid.nil? ? protocol : "ms-rpc-#{protocol.delete_prefix("ms-rpc-")}"

          def rule_action(action) = action

          def rule_identity(object)
            zones = [ object.from_zones, object.to_zones ]
            raise ArgumentError, "SRX rules require one zone per side" unless zones.all? { |values| values&.size == 1 }
            [ *zones.map(&:first), object.name ]
          end

          def validate_schedule(start_at, end_at)
            raise ArgumentError, "SRX schedules require both start and end" unless start_at && end_at
          end

          def schedule_components(value, reference_time:)
            match = /\A(?:(\d{4})-)?(?:(\d{2})-(\d{2})\.)?(\d{1,2}):(\d{1,2})\z/.match(value)
            return nil unless match
            { year: (match[1] || reference_time.year).to_i, mon: (match[2] || reference_time.month).to_i,
              mday: (match[3] || reference_time.day).to_i, hour: match[4].to_i, min: match[5].to_i }
          end

          def validate_zone(zone)
            raise ArgumentError, "SRX zones require a VRF" if zone.vrf.nil?
          end

          def validate_static_nat(nat)
            require_mapped_zone(nat)
            super
          end

          def validate_dynamic_nat(nat)
            require_direction(nat)
            require_source_zone(nat)
          end
        end
      end
    end
  end
end
