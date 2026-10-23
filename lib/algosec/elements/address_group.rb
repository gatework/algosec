# frozen_string_literal: true

require_relative "address_object"

module Algosec
  module Elements
    # 地址组保留成员引用，按当前依赖计算展开叶子和地址范围。
    class AddressGroup < Group
      ELEMENT_TYPE = :address_group
      include Address::Expansion
      MEMBER_CLASS = AddressObject
      attr_reader :zone

      def group_class = AddressGroup

      def initialize(zone: nil, **attributes)
        @zone = text(zone, optional: true)
        super(**attributes)
      end

      protected

      # 由设备定义决定地址组身份字段。
      def identity_parts = element_definition.address_group_identity(self)
    end
  end
end
