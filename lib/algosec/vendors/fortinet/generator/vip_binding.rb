# frozen_string_literal: true

require_relative "../generator"

module Algosec
  module Vendors
    module Fortinet
      class Generator
        # VIP 的原始匹配范围和逐地址、逐端口转换；名称不决定两次分配是否相容。
        class VipBinding < Data.define(:external, :internal, :interface, :protocol, :external_port, :internal_port)
          def initialize(external:, internal:, interface:, protocol: nil, external_port: nil, internal_port: nil)
            super(external: external, internal: internal, interface: interface.to_s.dup.freeze,
              protocol: protocol&.dup&.freeze, external_port: external_port, internal_port: internal_port)
          end

          def conflicts?(other)
            same_interface = interface == other.interface || interface == "any" || other.interface == "any"
            same_service = protocol.nil? || other.protocol.nil? || (protocol == other.protocol && external_port == other.external_port)
            same_interface && same_service && external.overlap?(other.external) && translation != other.translation
          end

          protected

          # 完整地址映射保留端口；等长地址段在交集内具有相同偏移才是同一转换。
          def translation = [ internal.min - external.min, internal_port ? internal_port - external_port : 0 ]
        end

        private_constant :VipBinding
      end
    end
  end
end
