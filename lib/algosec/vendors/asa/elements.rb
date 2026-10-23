# frozen_string_literal: true

require_relative "../../elements/definition"

module Algosec
  module Vendors
    module Asa
      # ASA 的身份字段、默认动作和对象校验约定。
      class Elements < Algosec::Elements::Definition
        identity :rule, :rule_set, :rule_number
        defaults default_dynamic_nat_direction: :source
        defaults dynamic_nat_empty_match?: true
        defaults static_nat_set_mode: :explicit
        defaults static_nat_any_destination?: true

        class << self
          # 原生 Section 1/2/3 独立于源/目的转换方向。
          def nat_stage(nat) = { 1 => :before_auto, 2 => :auto, 3 => :after_auto }[nat.nat_order&.first]

          def static_nat_identity(nat) = nat.id ? [ nat.id ] : super

          def dynamic_nat_identity(nat) = nat.id ? [ nat.id ] : [ nat.from_zone, nat.name, nat.acl_name ]

          def address_identity(object) = [ object.name ]

          def service_ports(protocol, source, destination) = [ source, destination ]

          def rule_action(action) = action

          def schedule_format(value) = "%H:%M %d %B %Y"

          def validate_rule(rule, action:)
            raise ArgumentError, "ASA rules require a rule set" if rule.rule_set.nil?
            raise ArgumentError, "An action is required" if action.nil?
          end

          def validate_nat_pool(pool)
            raise ArgumentError, "ASA NAT pools require a zone" if pool.zone.nil?
          end

          def validate_static_nat(nat)
            require_mapped_zone(nat)
            require_real_zone(nat)
          end

          def validate_dynamic_nat(nat) = require_source_zone(nat)
        end
      end
    end
  end
end
