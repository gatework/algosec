# frozen_string_literal: true

require_relative "../../policy"

module Algosec
  module Vendors
    module Neteye
      # 提供 Neteye 接口方向和静态 NAT 区域判断。
      class Policy < Algosec::Policy::Behavior
        ADDRESS_MAPPING = { plain: :fallback, source_interface: true, destination_interface: :all }.freeze
        # 映射端未声明区域时允许当前区域，否则必须精确相等。
        def static_nat_zone?(nat, zone) = nat.mapped_zone.nil? || nat.mapped_zone == zone

        # 生成器目前只输出 protocol-object；组的引用需要独立命令适配。
        def reusable_service?(service) = service.is_a?(Algosec::Elements::ServiceObject)
      end
    end
  end
end
