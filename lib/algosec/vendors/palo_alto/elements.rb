# frozen_string_literal: true

require_relative "../../elements/definition"

module Algosec
  module Vendors
    module PaloAlto
      class Elements < Algosec::Elements::Definition
        class << self
          def nat_stage(nat) = :policy

          def nat_source_translation_mode(nat, pool: nil)
            return super if nat.is_a?(Algosec::Elements::StaticNat) || nat.nat_type.nil?
            mode = { "static-ip" => :static_ip, "dynamic-ip" => :dynamic_ip, "dynamic-ip-and-port" => :dynamic_ip_and_port }.fetch(nat.nat_type, :unknown)
            return :unknown if mode == :unknown
            return :none if nat.extra_conf["no_translation"] == true || nat.direction == :destination
            mode
          end

          def nat_source_translation_interface(nat)
            return unless nat.is_a?(Algosec::Elements::DynamicNat)
            fields = nat.extra_conf.dig("panos", "translations") || []
            names = fields.filter_map { |field| field[4] if field[0, 4] == %w[source-translation dynamic-ip-and-port interface-address interface] }.uniq
            names.first if names.one?
          end

          # 双向规则生成与同一条规则同时 SNAT/DNAT 是两个不同事实。
          def nat_bidirectional(nat)
            return super unless nat.is_a?(Algosec::Elements::DynamicNat)
            fields = nat.extra_conf.dig("panos", "translations") || []
            values = fields.filter_map { |field| field[3] if field[0, 3] == %w[source-translation static-ip bi-directional] }.uniq
            return unless values.one?
            { "yes" => true, "no" => false }[values.first]
          end

          def rule_identity(rule) = [ rule.rule_set || "vsys1/rulebase", rule.name || rule.native_rule_id ]
          def dynamic_nat_identity(nat) = [ nat.name || nat.id ]
          def rule_action(action) = action || "allow"
          def rule_vendor_fields = { "panos" => String }
          def schedule_components(value, reference_time:)
            Date._strptime(value, "%Y/%m/%d@%H:%M")
          end
        end
      end
    end
  end
end
