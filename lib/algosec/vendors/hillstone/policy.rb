# frozen_string_literal: true

require_relative "../../policy"

module Algosec
  module Vendors
    module Hillstone
      # 提供 StoneOS 不限区域语义和策略候选判断。
      class Policy < Algosec::Policy::Behavior
        ADDRESS_MAPPING = { plain: :fallback, destination_interface: :static }.freeze

        # StoneOS 在对应方向不受限时省略 src-zone/dst-zone。
        # 空区域表示不限；带应用检查的规则不参与纯网络请求匹配。
        def candidate?(rule, from_zone:, to_zone:)
          rule.action == "allow" && rule.application_check.nil? &&
            rule.security_profiles.empty? && !rule.unparsed_commands? &&
            rule_in_zones?(rule, from_zone: from_zone, to_zone: to_zone)
        end

        def ordered_policy? = true

        def rule_in_zones?(rule, from_zone:, to_zone:)
          (rule.from_zones.nil? || zone_matches?(rule.from_zones, from_zone)) &&
            (rule.to_zones.nil? || zone_matches?(rule.to_zones, to_zone))
        end
      end
    end
  end
end
