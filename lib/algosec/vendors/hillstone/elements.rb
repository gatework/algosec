# frozen_string_literal: true

require_relative "../../elements/definition"

module Algosec
  module Vendors
    module Hillstone
      # StoneOS 的规则身份、时间和 NAT 集合约定。
      class Elements < Algosec::Elements::Definition
        identity :rule, :native_rule_id
        identity :static_nat, :id
        defaults static_nat_set_mode: :empty, mixed_schedules?: true

        class << self
          def nat_source_translation_mode(nat, pool: nil)
            return super if nat.is_a?(Algosec::Elements::StaticNat) || nat.nat_type.nil?
            return :unknown unless nat.nat_type == "dynamicport"
            nat.direction == :destination ? :none : :dynamic_ip_and_port
          end

          def rule_vendor_fields
            { "aggregate_type" => String, "aggregate_rule_id" => String, "aggregate_status" => String }
          end

          def rule_container?(rule) = rule.vendor_data["aggregate_type"] == "container"

          def rule_group_disabled?(rule) = rule.vendor_data["aggregate_status"] == "disable"

          # StoneOS 导出的绝对计划有时带秒，有时只到分钟。
          def schedule_components(value, reference_time:)
            [ "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M" ].lazy
                                                   .map { |format| Date._strptime(value, format) }
                                                   .find { |parts| parts && !parts.key?(:leftover) }
          end

          def validate_dynamic_nat(nat) = require_direction(nat)
        end
      end
    end
  end
end
