# frozen_string_literal: true

require_relative "nat"

module Algosec
  module Elements
    # StaticNat 与 DynamicNat 的共同领域协议；不创建旁路的规范 NAT 副本。
    class NatRule < Base
      ELEMENT_TYPE = :nat_rule
      attr_reader :original_packet, :source_translation, :destination_translation, :stage, :bidirectional

      # 原生顺序和身份独立；未知位置不通过名称或 ID 猜测。
      def position = nat_order
      def exempt? = source_translation.identity? && destination_translation.identity?
      def bidirectional? = bidirectional == true
      def dual_translation? = !source_translation.identity? && !destination_translation.identity?
      def translation_known? = source_translation.known? && destination_translation.known?

      protected

      def initialize_nat_semantics
        @stage = element_definition.nat_stage(self)
        @bidirectional = element_definition.nat_bidirectional(self)
        unless @bidirectional.nil? || @bidirectional == true || @bidirectional == false
          raise ArgumentError, "NAT bidirectional must be true, false or nil"
        end
      end
    end
  end
end
