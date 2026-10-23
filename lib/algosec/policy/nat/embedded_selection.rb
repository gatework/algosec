# frozen_string_literal: true

require_relative "../evaluation"
require_relative "service_query"

module Algosec
  module Policy
    module Nat
      # 内嵌转换只有其所属安全规则首条命中时才生效，普通规则也能终结这条链。
      class EmbeddedSelection
        def initialize(snapshot)
          @snapshot = snapshot
        end

        def matches?(nat, flow:, services:, source_port:)
          unless flow && flow.values_at(:source, :destination, :from_zone, :to_zone).none?(&:nil?)
            raise Error.new("内嵌 NAT 需要完整的原始流量与区域上下文", code: :conditional_nat)
          end
          rule = nat.match_rule
          unless @snapshot.rules.any? { |actual| actual.equal?(rule) }
            raise Error.new("内嵌 NAT 的关联规则不属于当前安全规则图", code: :conditional_nat)
          end
          traffic = Nat::ServiceQuery.coerce(services).traffic(sources: flow.fetch(:source),
            destinations: flow.fetch(:destination), source_port: source_port)
          context = flow.slice(:from_zone, :to_zone)
          require_stable_time!(rule, traffic, context)
          result = Evaluation.new(@snapshot).perform(traffic, **context)
          unless result.complete?
            raise Error.new("内嵌 NAT 的安全首匹配含有未知条件", code: :conditional_nat)
          end
          matches = result.partitions.count { |part| part.rule.equal?(rule) && part.action == "allow" }
          if matches.positive? && matches < result.partitions.size
            raise Error.new("内嵌 NAT 只在部分原始流量上首条命中，需拆分查询", code: :conditional_nat)
          end
          matches.positive?
        rescue RuleOrder::Unproven, TrafficSet::LimitExceeded => error
          raise Error.new(error.message, code: :conditional_nat)
        end

        private

        # NAT 关系不带时间上下文；当前不活跃的前序规则也不能被当作永久不匹配。
        def require_stable_time!(nat_rule, traffic, context)
          rules = @snapshot.rulebase(**context).ordered_rules
          position = rules.index(nat_rule)
          return unless position
          rules.take(position + 1).each do |rule|
            next unless rule.schedule || rule.schedule_name || rule.starts_at || rule.expires_at
            untimed = rule.with(schedule: nil, schedule_name: nil,
              conditions: rule.semantic_conditions.except("starts_at", "expires_at"), unparsed_commands_metadata: rule.unparsed_commands_metadata)
            predicate = Evaluation::Predicate.new(@snapshot, untimed, at: Time.current, domains: {},
              application: nil, source_user: nil, application_definitions: {})
            next if predicate.partitions(traffic).empty?
            raise Error.new("内嵌 NAT 的前序或关联规则含时间条件，无法证明无条件转换", code: :conditional_nat)
          end
        end
      end
    end
  end
end
