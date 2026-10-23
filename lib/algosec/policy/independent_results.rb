# frozen_string_literal: true

require_relative "rule_matcher"

module Algosec
  module Policy
    # 独立需求不能共同扩展同一规则，否则会产生请求之外的交叉组合。
    class IndependentResults
      def self.perform(results)
        shared = results.select { |result| result.type == :modify }
                        .group_by { |result| [ result.device_id, result.rule.rule_id ] }
                        .select { |_key, entries| entries.size > 1 }.keys
        results.map do |result|
          next result unless result.type == :modify && shared.include?([ result.device_id, result.rule.rule_id ])

          matcher = RuleMatcher.new(result.snapshot)
          members = Result::DIMENSIONS.to_h do |dimension|
            zone = dimension == :sources ? result.from_zone : result.to_zone
            [ dimension, matcher.names_for(dimension, result.public_send(dimension), zone) ]
          end
          maps = Result::DIMENSIONS.to_h { |dimension| [ dimension, result.public_send(dimension) ] }
          group = { nat_mode: result.nat_mode, hit: result.hit }
          to_zone = result.snapshot.behavior.refine_new_rule_names(group, maps, members, result.to_zone) do |zone|
            matcher.names_for(:destinations, result.destinations, zone)
          end
          nat = result.actions.fetch(:new, {}).slice(:nat_sources, :nat_destinations)
          # 内嵌 NAT 必须沿用原策略的转换语义，即使本次没有新增 NAT。
          if result.snapshot.behavior.policy_embeds_nat?
            retained = result.sources.each_with_object({}) do |(address, entry), records|
              next unless entry.dig(:nat, :rule) && result.snapshot.behavior.retain_source_nat?(entry[:nat])
              records[address] = Value.copy(entry).tap { |copy| copy[:real_ip] ||= copy[:private] || address }
            end
            nat = nat.merge(nat_sources: retained.merge(nat.fetch(:nat_sources, {}))) if retained.any?
          end
          Result.new(device_id: result.device_id, device_name: result.device_name, vendor: result.vendor,
            nat_mode: result.nat_mode, from_zone: result.from_zone, to_zone: to_zone, hit: result.hit,
            type: :new, sources: result.sources, destinations: result.destinations, services: result.services,
            schedule: result.schedule, snapshot: result.snapshot, decision: result.decision,
            source_rule_id: result.source_rule_id, conflicting_rules: result.conflicting_rules,
            actions: { new: members.merge(nat) })
        end
      end
    end
  end
end
