# frozen_string_literal: true

require_relative "../../policy"

module Algosec
  module Vendors
    module Netscreen
      # 提供 ScreenOS Global 地址、策略 NAT 和规则编号相关行为。
      class Policy < Algosec::Policy::Behavior
        ADDRESS_MAPPING = { plain: :main, infer_same_device: true, source_interface: true, source_pools: true,
                            destination_pools: true, destination_interface: :all, peer_interface: true }.freeze

        # 只接受动作和两个区域均精确匹配的策略。
        def candidate?(rule, from_zone:, to_zone:)
          exact_candidate?(rule, action: "allow", from_zone: from_zone, to_zone: to_zone)
        end

        def address_in_zone?(address, zone) = address.zone == zone

        # 与 ScreenOS 解析入口一致，内建服务先于同名用户服务组查找。
        def service_priority = %i[service builtin service_group]

        def modified_to_zone(rule, requested) = rule.to_zones.first

        def policy_embeds_nat? = true

        def retain_source_nat?(nat) = nat[:type] != :static

        # 静态目的 NAT 使用 Global 对象，其余地址继续沿用目标区域。
        def refine_new_rule_names(group, maps, names, to_zone)
          destination_nat = group[:nat_mode] == 1 && group[:hit] == :destination
          return to_zone unless group[:nat_mode] == 2 || destination_nat
          missing = names[:destinations].select { |_address, found| found.nil? }.keys
          return to_zone if missing.empty?
          global = yield "Global"
          if missing.any? { |address| maps[:destinations][address].dig(:nat, :type) == :static }
            names[:destinations] = global
            "Global"
          else
            missing.each { |address| names[:destinations][address] = global[address] }
            to_zone
          end
        end

        def augment_local_entry(address, entry, location)
          if location && location[:zone] == "Global" && location[:address_type] == :main
            entry[:private], entry[:resolved_zone] = Algosec::Policy::Nat::Resolver.new(snapshot).reverse(address)
          end
        end
      end
    end
  end
end
