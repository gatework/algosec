# frozen_string_literal: true

require_relative "../../../vendors"
require_relative "../../../policy/analysis/rule_view"

module Algosec
  module Vendors
    module Asa
      module Nat
        # Policy NAT 的 ACL 保留每条规则的组合条件，不用独立维度的并集证明覆盖。
        # 不处理 nat 0 豁免；其 deny 和端口语义与 policy NAT 不同。
        class Acl
          def initialize(snapshot, name)
            @snapshot, @name = snapshot, name
          end

          def matches?(sources:, destinations:, services:, relation:)
            requested = { sources: sources, destinations: destinations,
                          services: services.present? ? Algosec::Policy::Ranges.services(services.map { |value, entry| entry.fetch(:origin, value) }) : nil }
            ordered_rules.each do |rule|
              view = Algosec::Policy::Analysis::RuleView.new(@snapshot, rule, at: Time.current)
              ranges = view.ranges
              next if requested.any? { |dimension, set| set && !ranges.fetch(dimension).overlap?(set) }

              if rule.schedule || rule.schedule_name || rule.starts_at || rule.expires_at
                unknown!("时间条件尚不能证明")
              end
              if requested.any? { |dimension, set| set.nil? && !view.any?(dimension) }
                unknown!("缺少对端或服务上下文")
              end
              return requested.all? { |dimension, set| set.nil? || ranges.fetch(dimension).public_send(relation, set) }
            end
            false
          rescue Algosec::Policy::Analysis::Unknown => error
            unknown!(error.message)
          end

          private

          def ordered_rules
            rules = @snapshot.rules.select { |rule| rule.rule_set == @name }
            unknown!("引用不存在") if rules.empty?
            # Policy NAT 只接受 permit；不能套用接口 ACL 或 NAT 豁免的 deny 行为。
            unknown!("包含非 permit 动作") if rules.any? { |rule| rule.action != "allow" }
            rules = rules.reject do |rule|
              Algosec::Policy::Analysis::RuleView.new(@snapshot, rule, at: Time.current).disabled?
            end
            numbered = rules.map { |rule| [ rule, @snapshot.behavior.rule_number(rule) ] }
            numbers = numbered.map(&:last)
            if rules.size > 1 && (numbers.any?(&:nil?) || numbers.uniq.size != numbers.size)
              unknown!("规则顺序不完整")
            end
            numbered.sort_by { |_rule, number| number || 0 }.map(&:first)
          end

          def unknown!(reason)
            raise Algosec::Policy::Error.new("ASA NAT ACL #{@name} #{reason}", code: :conditional_nat)
          end
        end
      end
    end
  end
end
