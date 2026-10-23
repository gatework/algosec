# frozen_string_literal: true

require_relative "../../elements/definition"

module Algosec
  module Vendors
    module H3c
      # H3C 的对象组、规则编号和 NAT 方向约定。
      class Elements < Algosec::Elements::Definition
        defaults static_nat_set_mode: :explicit

        class << self
          def rule_vendor_fields = { "acl_type" => String }

          def rule_identity(object) = [ object.native_rule_type, object.rule_set, object.native_rule_id ]

          def schedule_format(value) = "%H:%M %m/%d/%Y"

          def validate_dynamic_nat(nat) = require_direction(nat)
        end
      end
    end
  end
end
