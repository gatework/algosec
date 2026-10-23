# frozen_string_literal: true

require_relative "../../policy"
require_relative "nat/acl"
require_relative "nat/translator"

module Algosec
  module Vendors
    module Asa
      # 提供 ASA 版本相关的候选、地址映射和策略 NAT 行为。
      class Policy < Algosec::Policy::Behavior
        # 只接受动作和入口 ACL 均匹配的规则作为候选。
        def candidate?(rule, from_zone:, to_zone:)
          rule.action == "allow" && !rule.unparsed_commands? && rule.rule_set == snapshot.zone(from_zone).acl_name
        end

        # 入站 ACL 不匹配出站区域；不同入口仍是独立目标，不能掩盖共享 ACL 的扩大。
        def proof_context(context) = context.merge(to_zone: nil)

        def proof_zone_pairs(rule)
          snapshot.elements(Algosec::Elements::Zone).select { |zone| zone.acl_name == rule.rule_set }
            .map { |zone| [ [ zone.name ], nil ] }
        end

        def reusable_names? = false

        # ASA 用入口区域绑定的 ACL 确定规则链。
        def rule_in_zones?(rule, from_zone:, to_zone:)
          rule.rule_set == snapshot.zone(from_zone).acl_name
        end

        def rule_scope(rule) = [ rule.rule_set ]

        def nat_translator = Nat::Translator

        def strict_reverse_nat? = true

        # 现代 ASA NAT 统一按手工前置、对象 NAT、手工后置排序，不能静态优先。
        def nat_groups
          candidates = snapshot.active_static_nats + snapshot.active_dynamic_nats
          return super if candidates.none?(&:nat_order)
          orders = candidates.map(&:nat_order)
          if orders.any?(&:nil?) || orders.uniq.size != orders.size
            raise Algosec::Policy::Error.new("ASA NAT 执行顺序尚未完整解析", code: :conditional_nat)
          end
          candidates.sort_by(&:nat_order).map { |nat| [ nat ] }
        end

        def static_nat_peers?(nat, peers, relation: :cover?) = !nat.destination_set || !peers || nat.destination_set.public_send(relation, peers)

        def static_nat_translation(nat, target, peers:, relation: :cover?)
          nat.acl_name.present? ? nat.mapped_set : nat.translate(target)
        end

        def nat_acl_matches?(nat, **conditions)
          return true if nat.acl_name.blank?
          Nat::Acl.new(snapshot, nat.acl_name).matches?(**conditions)
        end

        # 无对端和服务的反查不能证明 policy NAT 的适用条件及逆映射。
        def validate_reverse_nat!(nat)
          if nat.acl_name.present?
            raise Algosec::Policy::Error.new("ASA ACL NAT 反查需要完整流量上下文", code: :conditional_nat)
          end
        end

        # 根据设备版本决定使用 ASA 8.3 之后的地址语义。
        def modern?
          match = snapshot.software_version&.match(/\A(?:ASA Version\s+)?(\d+)\.(\d+)(?:[.(\s]|\z)/i)
          !!(match && ([ match[1].to_i, match[2].to_i ] <=> [ 8, 3 ]) >= 0)
        end

        def matches_translated_service? = modern?

        def divide(group)
          group[:sources].to_a.product(group[:destinations].to_a, group[:services].to_a).map do |source, destination, service|
            group.merge(sources: [ source ].to_h, destinations: [ destination ].to_h, services: [ service ].to_h)
          end
        end
      end
    end
  end
end
