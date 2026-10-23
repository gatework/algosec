# frozen_string_literal: true

require_relative "../../policy"
require_relative "nat/translator"

module Algosec
  module Vendors
    module PaloAlto
      # PAN-OS 使用转换前地址、转换后区域；App-ID 等条件不能按端口规则推断。
      class Policy < Algosec::Policy::Behavior
        def nat_translator = Nat::Translator
        def ordered_policy? = true

        # PAN 本地规则库的原生兜底；配置中的 default-security-rules 仍先参与匹配。
        def rulebase_default_action(from_zone:, to_zone:, rule_set: nil, scope: nil)
          return unless local_rulebase_context?(rule_set, scope)
          return if [ from_zone, to_zone ].any? { |zone| zone.nil? || zone.empty? || zone == "any" }
          from_zone == to_zone ? "allow" : "deny"
        end

        # PAN 的源、目的和双向转换共享原始报文规则链，目录保留解析顺序。
        def nat_policy_rules = snapshot.active_dynamic_nats

        def nat_groups = [ snapshot.active_static_nats ]

        def nat_query_flow(flow) = flow.merge(to_zone_stage: :security)

        # NAT 的出口区域属于转换前报文，不能用转换目标的区域替换。
        def nat_flow_matches?(nat, flow:, relation:)
          from = nat.extra_conf.fetch("src_zones", [ nat.from_zone ])
          to = nat.extra_conf.fetch("dst_zones", [ nat.to_zone ])
          route = original_nat_route(flow) if flow[:to_zone_stage] == :security || nat.interface
          to_zone = flow[:to_zone_stage] == :security ? route&.zone : flow[:to_zone]
          nat_zones_match?(from, flow[:from_zone], relation: relation) &&
            nat_zones_match?(to, to_zone, relation: relation) &&
            nat_context_matches?(nat.vrf, flow[:vrf], relation: relation) &&
            nat_context_matches?(nat.interface, route&.destination_interface, relation: relation)
        end
        def candidate?(rule, from_zone:, to_zone:)
          rule.action == "allow" && rule_in_zones?(rule, from_zone: from_zone, to_zone: to_zone) &&
            !%w[negate-source negate-destination].any? { |key| JSON.parse(rule.vendor_data.fetch("panos", "{}"))[key] == [ "yes" ] } &&
            rule.application_check.nil? && rule.security_profiles.empty? && !rule.unparsed_commands?
        end

        # 解析器已把本地默认规则排在普通规则之后；仅归并明确支持的配置段。
        def rule_chain(rule)
          chain = super
          return chain unless chain == "vsys1/rulebase/default-security-rules" && JSON.parse(rule.vendor_data.fetch("panos", "{}"))["family"] == "default-security-rules"
          "vsys1/rulebase"
        end

        # 普通安全规则创建在默认层之前，不对应可发送的 move 命令。
        def terminal_rule?(rule)
          JSON.parse(rule.vendor_data.fetch("panos", "{}"))["family"] == "default-security-rules"
        end

        def rule_in_zones?(rule, from_zone:, to_zone:)
          kind = rule.rule_type
          return false if kind == :intrazone && from_zone != to_zone
          return false if kind == :interzone && from_zone == to_zone
          super
        end

        protected

        # 空筛选结果并非默认规则证据；未知链、作用域或被缺失作用域过滤的规则仍是不确定的。
        def local_rulebase_context?(selected_chain, selected_scope)
          return false unless [ nil, "vsys1/rulebase" ].include?(selected_chain)
          supported = { virtual_system: [ nil, "vsys1" ], rulebase: [ nil, "rulebase" ], address_book: [ nil ], zone: [ nil ] }
          return false if selected_scope && supported.any? { |field, values| !values.include?(selected_scope.public_send(field)) }
          snapshot.rules.all? do |rule|
            chain = rule_chain(rule)
            # 未记录链不能证明规则位于已选择的本地链之外。
            next false if selected_chain && chain.nil?
            next true if selected_chain && chain != selected_chain
            next false unless [ nil, "vsys1/rulebase" ].include?(chain)
            supported.all? do |field, values|
              actual = rule.scope.public_send(field)
              values.include?(actual) && !(selected_scope&.public_send(field) && actual.nil?)
            end
          end
        end

        # 安全策略出口不能用于 NAT 命中；按原始目的在入口路由域内独立选路。
        def original_nat_route(flow)
          return unless flow[:source] && flow[:destination] && flow[:from_zone]

          vrf = flow[:vrf] || snapshot.vrf(flow[:from_zone])
          return unless vrf

          route = Algosec::Elements::RoutingTable.new(snapshot.routes).lookup(
            source: flow[:source], destination: flow[:destination], vrf: vrf, source_zone: flow[:from_zone])
          return if route&.destination_vrf && route.destination_vrf != vrf

          route
        rescue Algosec::Elements::RoutingTable::ConditionalRoute
          nil
        end

        def nat_zones_match?(zones, requested, relation:)
          return true if zones.compact.empty? || zones.include?("any")
          return relation == :overlap? unless requested

          zone_matches?(zones, requested)
        end
      end
    end
  end
end
