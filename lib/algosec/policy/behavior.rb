# frozen_string_literal: true

require_relative "ranges"

module Algosec
  module Policy
    # 共享查询算法调用的厂商边界；实例只持有当前配置快照。
    class Behavior
      ADDRESS_MAPPING = { plain: :fallback }.freeze
      attr_reader :snapshot

      # 保存当前配置快照，所有查询行为都从该快照读取。
      def initialize(snapshot)
        @snapshot = snapshot
      end

      # 返回地址映射策略配置。
      def address_mapping = self.class::ADDRESS_MAPPING

      # 返回地址转换器实现类，厂商可以替换这一边界。
      def nat_translator
        require_relative "nat/translator" unless defined?(Nat::Translator)
        Nat::Translator
      end

      # 判断规则动作和起止区域是否满足查询候选条件。
      def candidate?(rule, from_zone:, to_zone:)
        rule.action == "allow" && zone_matches?(rule.from_zones, from_zone) && zone_matches?(rule.to_zones, to_zone)
      end

      def reusable_names? = true

      # 名称可查询不代表现有生成器支持该对象类型的引用命令。
      def reusable_service?(service) = true

      # 名称比较和查找优先级分别沿用厂商约定。
      def service_name_key(name) = name

      def service_priority = %i[service service_group builtin]

      # 可查询不代表可在当前区域对中修改；厂商负责共享规则链及命令能力约束。
      def editable_rule?(rule, from_zone:, to_zone:) = true

      # 流量命中判断包含允许和拒绝规则，区域筛选不依赖规则动作。
      def rule_in_zones?(rule, from_zone:, to_zone:)
        zone_matches?(rule.from_zones, from_zone) && zone_matches?(rule.to_zones, to_zone)
      end

      # 证明上下文沿用设备真正参与匹配的维度；默认保留完整区域对。
      def proof_context(context) = context

      # 每个条目保留一个真实绑定的两维集合，不能把多个绑定先分别合并。
      def proof_zone_pairs(rule) = [ [ rule.from_zones, rule.to_zones ] ]

      # 普通规则默认没有独立的末尾层；仅厂商声明可提供这个落位事实。
      def terminal_rule?(rule) = false

      def ordered_policy? = true

      # 无原生默认动作证据时保持未知；调用方须先评估全部显式规则。
      def rulebase_default_action(from_zone:, to_zone:, rule_set: nil, scope: nil) = nil

      # 网络请求没有接口或 VLAN 维度；只有厂商明确映射到区域后才能消除这些条件。
      def unresolved_network_conditions?(rule)
        rule.from_interface || !rule.dst_interfaces.empty? || !rule.from_vlans.empty? || !rule.to_vlans.empty?
      end

      def address_in_zone?(address, zone) = true

      def refine_new_rule_names(group, maps, names, to_zone, &) = to_zone

      def modified_to_zone(rule, requested) = requested

      def policy_embeds_nat? = false

      def nat_policy_id(nat) = nat.policy_id

      def retain_source_nat?(nat) = true

      def static_nat_zone?(nat, zone) = nat.mapped_zone == zone

      def static_nat_source?(nat) = nat.source_nat_enabled != false

      # 组间依序匹配，组内必须证明映射无歧义；通用设备保留静态优先的约定。
      def nat_groups
        [ snapshot.active_static_nats.sort_by { |nat| snapshot.signature(nat) }, *snapshot.active_dynamic_nats.map { |nat| [ nat ] } ]
      end

      # 原生策略先按原始流量选择整条规则；nil 表示仍使用独立映射组。
      def nat_policy_rules = nil

      # 搜索器与地址转换器提供策略阶段区域，厂商可保留其阶段供原始报文选路。
      def nat_query_flow(flow) = flow

      # 原始报文的两个区域和路由域均参与判断；厂商可按 NAT 阶段覆盖。
      def nat_flow_matches?(nat, flow:, relation:)
        nat_context_matches?(nat.from_zone, flow[:from_zone], relation: relation) &&
          nat_context_matches?(nat.to_zone, flow[:to_zone], relation: relation) &&
          nat_context_matches?(nat.vrf, flow[:vrf], relation: relation)
      end

      # 转换目标的可用性在规则命中后核对，不能用于跳过前置规则。
      def validate_nat_target!(nat, flow:) end

      # 反查区域与正向匹配分离；默认保留仅按显式接口限制反查的约定。
      def reverse_nat_zone?(nat, zone) = !nat.interfaces || static_nat_zone?(nat, zone)

      def dynamic_nat_zone?(nat, zone, direction:)
        actual = direction == :source ? nat.to_zone : nat.from_zone
        actual == zone || actual == "any" || (direction == :destination && actual.nil?)
      end

      def static_nat_peers?(nat, peers, relation: :cover?) = true

      def static_nat_translation(nat, target, peers:, relation: :cover?) = nat.translate(target)

      # 厂商 ACL 是完整流量谓词；地址投影只能用于筛选候选。
      def nat_acl_matches?(nat, sources:, destinations:, services:, relation:) = true

      def validate_reverse_nat!(nat) end

      def strict_reverse_nat? = false

      def infer_private_peers? = true

      def augment_local_entry(address, entry, location) end

      def matches_translated_service? = false

      def divide(group) = [ group ]

      # 统一已解析的终结动作；reject 等带额外语义的动作不等同于 deny。
      def rule_decision(rule)
        { "allow" => :permit, "deny" => :deny, "drop" => :deny }[rule.action]
      end

      # 规则编号来自配置中的执行顺序，不能用对象名称或策略 ID 代替。
      def rule_number(rule) = rule.rule_number

      # 厂商可明确归并同一执行链的配置段，规则身份仍保留原始 rule_set。
      def rule_chain(rule) = rule.rule_set

      # 显式查询规则链时沿用厂商的名称比较语义。
      def rule_set_matches?(rule, name) = rule.rule_set == name

      # 只有同一规则链中的规则才能互相覆盖；厂商可收紧链的身份。
      def rule_scope(rule)
        [ rule.scope, rule.rule_type, rule.native_rule_type, rule.rule_set, rule.from_zones&.sort, rule.to_zones&.sort ]
      end

      protected

      # 未提供受限的原始上下文时，只能证明潜在命中，不能证明覆盖。
      def nat_context_matches?(actual, requested, relation:)
        return true if actual.nil? || actual == "any"
        return relation == :overlap? unless requested

        actual == requested
      end

      # 判断规则是否精确落在请求动作和两个区域上。
      def exact_candidate?(rule, action:, from_zone:, to_zone:)
        rule.action == action && rule.from_zones == [ from_zone ] && rule.to_zones == [ to_zone ]
      end

      # 判断区域值是否相等；厂商可覆盖大小写或别名规则。
      def zone_equal?(actual, requested) = actual == requested

      # 判断区域列表是否包含请求区域或任意区域。
      def zone_matches?(zones, requested)
        Array(zones).any? { |zone| zone.casecmp?("any") || zone_equal?(zone, requested) }
      end
    end
  end
end
