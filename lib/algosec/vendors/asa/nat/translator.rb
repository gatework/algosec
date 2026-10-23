# frozen_string_literal: true

require_relative "../../../vendors"
require_relative "../../../policy/nat/translator"

module Algosec
  module Vendors
    module Asa
      module Nat
        # ASA 8.3 的策略地址语义由版本决定，地址与端口判断共用同一版本规则。
        class Translator < Algosec::Policy::Nat::Translator
          private

          # 按查询方向和 ASA 版本在真实地址、映射地址之间切换。
          def map_address(address, address_entry, context)
            main = address_entry[:main] || address_entry[:origin]
            # 同设备的目标仍保留 ASA 策略地址键，真实目标及区域另供转发校验。
            if context[:mode] != 0 && context[:same_device] && context[:side] == :destination
              address_entry[:private], context[:real_zone] = @nat.reverse(address) unless address_entry[:private]
            end
            return main if context[:mode] == 0 || context[:side] != context[:hit]
            if context[:hit] == :source
              direction = context[:same_device] ? nil : :source
              address_entry[:private], context[:real_zone] = @nat.reverse(address, direction: direction) unless address_entry[:private]
              if context[:mode] == 1
                existing_nat = @nat.find(address_entry[:private], zone: context[:zone], peers: context[:peers], direction: :source, services: context[:services], flow: context[:flow])
                if existing_nat
                  address_entry[:nat] = existing_nat
                else
                  validate_allocation!(address, address_entry, zone: context[:zone])
                  address_entry[:action], address_entry[:real_ip] = :new_nat, address_entry[:private]
                end
              end
              return address_entry[:private]
            end
            if address_entry[:main] == address_entry[:origin]
              address_entry[:private], context[:real_zone] = @nat.reverse(address) unless address_entry[:private]
            else
              existing_nat = @nat.find(address_entry[:private] || address, zone: context[:zone], peers: context[:peers], direction: :destination, services: context[:services], flow: context[:flow])
              if existing_nat
                address_entry[:nat], main = existing_nat, existing_nat[:address]
              else
                validate_allocation!(address, address_entry, zone: context[:zone])
                address_entry[:action], address_entry[:real_ip], main = :new_nat, address_entry[:private] || address, address_entry[:nat][:address]
              end
              address_entry[:private] ||= address
            end
            (context[:mode] == 2 || !@snapshot.behavior.modern?) ? main : address_entry[:private]
          end
        end
      end
    end
  end
end
