# frozen_string_literal: true

require_relative "../../elements/definition"

module Algosec
  module Vendors
    module Huawei
      # Huawei 的 VRF、规则身份和 NAT 集合约定。
      class Elements < Algosec::Elements::Definition
        identity :rule, :name
        identity :static_nat, :name
        defaults default_vrf: "default"
        defaults static_nat_set_mode: :explicit

        class << self
          # Server-map 先于目的/双向策略，再到纯源策略；仍由 Behavior 管理分组。
          def nat_stage(nat)
            return :server_map if nat.is_a?(Algosec::Elements::StaticNat) || nat.rule_set == "nat-server"
            return unless nat.rule_set == "nat-policy"
            { source: :source_policy, destination: :destination_policy, bidirectional: :destination_policy }[nat.direction]
          end

          def nat_source_translation_interface(nat)
            nat.interface if nat.is_a?(Algosec::Elements::DynamicNat) && nat.extra_conf["source_mode"] == "easy-ip"
          end

          def nat_source_translation_mode(nat, pool: nil)
            return super if nat.is_a?(Algosec::Elements::StaticNat) || nat.extra_conf["source_mode"].nil?
            return :none if nat.direction == :destination
            case nat.extra_conf["source_mode"]
            when "easy-ip" then :dynamic_ip_and_port
            when "address-group" then { "pat" => :dynamic_ip_and_port, "no-pat global" => :dynamic_ip }[pool&.mode]
            when "address" then nil
            else :unknown
            end
          end

          # 单地址目的池的配置关系确定；池分配模式仍由 DestinationTranslation 保留为 dynamic。
          def nat_destination_translation_mode(nat, pool: nil, addresses: nil)
            return :static if pool && pool.direction == :destination && pool.mode.nil? && pool.port.nil? && addresses&.cardinality == 1
            super
          end

          # 命名的服务器映射和策略 NAT 属于不同配置命名空间。
          def dynamic_nat_identity(nat) = [ nat.rule_set || "nat-policy", nat.name ]

          def schedule_format(value) = "%H:%M:%S %Y/%m/%d"
        end
      end
    end
  end
end
