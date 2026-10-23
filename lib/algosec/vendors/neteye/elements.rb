# frozen_string_literal: true

require_relative "../../elements/definition"

module Algosec
  module Vendors
    module Neteye
      # Neteye 的网络对象、规则身份和 NAT 约定。
      class Elements < Algosec::Elements::Definition
        identity :rule, :native_rule_id
        identity :static_nat, :id
        defaults unresolved_route_source?: true
        defaults static_nat_set_mode: :empty

        class << self
          def validate_dynamic_nat(nat) = require_direction(nat)

          def schedule_format(value)
            raise ArgumentError, "No date format for neteye"
          end
        end
      end
    end
  end
end
