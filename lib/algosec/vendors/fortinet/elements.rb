# frozen_string_literal: true

require_relative "../../elements/definition"

module Algosec
  module Vendors
    module Fortinet
      # FortiOS 的 vdom、策略和 NAT 身份及校验约定。
      class Elements < Algosec::Elements::Definition
        identity :static_nat, :name
        defaults default_vrf: "root"

        class << self
          def nat_stage(nat)
            return :vip if nat.is_a?(Algosec::Elements::StaticNat)
            :policy if nat.policy_id || nat.name
          end

          def nat_source_translation_mode(nat, pool: nil)
            return nat.source_nat_enabled == true ? :static_ip : :none if nat.is_a?(Algosec::Elements::StaticNat)
            super
          end

          def rule_identity(object) = [ object.rule_set || "root", object.native_rule_id ]

          def dynamic_nat_identity(object) = [ object.name || object.policy_id ]

          def schedule_format(value) = "%H:%M %Y/%m/%d"

          def validate_static_nat(nat)
            raise ArgumentError, "Fortinet static NAT requires an interface" if nat.interface.nil?
            super
          end
        end
      end
    end
  end
end
