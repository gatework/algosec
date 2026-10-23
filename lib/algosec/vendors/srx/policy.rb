# frozen_string_literal: true

require_relative "../../policy"

module Algosec
  module Vendors
    module Srx
      # 提供 SRX 区域、VRF 和规则集相关的策略行为。
      class Policy < Algosec::Policy::Behavior
        ADDRESS_MAPPING = { plain: :main, private_destination: true, source_pools: true, rule_sets: true }.freeze

        # 只接受动作和两个区域均精确匹配的策略。
        def candidate?(rule, from_zone:, to_zone:)
          exact_candidate?(rule, action: "allow", from_zone: from_zone, to_zone: to_zone)
        end

        def address_in_zone?(address, zone) = address.zone == zone

        def strict_reverse_nat? = true

        def matches_translated_service? = true
      end
    end
  end
end
