# frozen_string_literal: true

require_relative "../../elements/definition"

module Algosec
  module Vendors
    module Topsec
      # Topsec 的 VLAN、网络对象和策略身份约定。
      class Elements < Algosec::Elements::Definition
        identity :rule, :native_rule_id
        identity :dynamic_nat, :id, :from_zone, :to_zone
        defaults default_access_mode: "access"
        defaults static_nat_set_mode: :explicit

        class << self
          def validate_dynamic_nat(nat) = require_direction(nat)
        end
      end
    end
  end
end
