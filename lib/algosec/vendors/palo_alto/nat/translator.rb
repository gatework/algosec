# frozen_string_literal: true

require_relative "../../../vendors"
require_relative "../../../policy/nat/translator"

module Algosec
  module Vendors
    module PaloAlto
      module Nat
        # 安全策略始终匹配原始源地址；显式源分配交给同条 NAT 规则生成。
        class Translator < Algosec::Policy::Nat::Translator
          private

          def map_address(address, entry, context)
            if context[:mode] != 0 && context[:side] == :source && context[:hit] == :destination && entry[:nat]
              original = entry[:main] || entry[:origin]
              entry[:action], entry[:real_ip] = :new_nat, original
              return original
            end
            super
          end
        end
      end
    end
  end
end
