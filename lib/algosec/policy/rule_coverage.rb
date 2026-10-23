# frozen_string_literal: true

require_relative "analysis"
require_relative "evaluation"
require_relative "change_set/proof_contexts"

module Algosec
  module Policy
    # 覆盖证据来自各真实区域对上的首条匹配，不按单独维度合并前序规则。
    class RuleCoverage
      def initialize(snapshot, at:, proof_limit: TrafficSet::DEFAULT_LIMIT)
        @snapshot, @at, @proof_limit = snapshot, at, proof_limit
      end

      def call(rule)
        traffic = traffic(rule)
        return false if traffic.empty?
        covering = []
        contexts(rule).each do |context|
          ordered = @snapshot.rulebase(**context.slice(:from_zone, :to_zone, :rule_set)).ordered_rules(at: @at)
          position = ordered.index(rule)
          return false unless position
          preceding = ordered.take(position)
          result = Evaluation.new(@snapshot, at: @at).perform(traffic, **context)
          unknown!("前序规则的匹配条件尚未完整证明", :unsupported_conditions) unless result.complete?
          return false unless result.partitions.all? { |part| part.rule && preceding.include?(part.rule) }
          covering.concat(result.partitions.map(&:rule))
        end
        return false if covering.empty?
        covering.uniq!
        kind = if covering.any? { |other| other.action != rule.action }
          :shadowed
        elsif covering.one? && equivalent_declaration?(covering.first, rule, traffic)
          :duplicate
        else
          :redundant
        end
        ids = covering.map { |other| @snapshot.signature(other) }
        { kind: kind, covering_rule_ids: ids, covering_rule_id: ids.one? ? ids.first : nil,
          covering_action: covering.map(&:action).uniq.one? ? covering.first.action : nil,
          covering_decision: covering.one? ? @snapshot.behavior.rule_decision(covering.first) : nil }
      rescue RuleOrder::Unproven => error
        unknown!(error.message, :unknown_order)
      rescue TrafficSet::LimitExceeded => error
        unknown!(error.message, :proof_budget_exceeded)
      end

      private

      def traffic(rule)
        predicate = Evaluation::Predicate.new(@snapshot, rule, at: @at, domains: {},
          application: nil, source_user: nil, application_definitions: {})
        partitions = predicate.partitions(TrafficSet.universe(limit: @proof_limit))
        unless partitions.all? { |part| part.status == :matched }
          unknown!("规则含有尚未证明的匹配条件", :unsupported_conditions)
        end
        partitions.reduce(TrafficSet.new([], limit: @proof_limit)) { |set, part| set | part.traffic_set }
      end

      def contexts(rule)
        contexts = ChangeSet::ProofContexts.new(@snapshot, @snapshot, targets: [], rules: [ rule ], same_controls: true,
          budget: ChangeSet::ProofContexts::Budget.new(@proof_limit)).resolve.filter_map do |context|
          next unless @snapshot.behavior.rule_in_zones?(rule, **context.slice(:from_zone, :to_zone))
          context.merge(rule_set: rule.rule_set)
        end
        unknown!("规则没有可验证的区域上下文", :unproven_control_context) if contexts.empty?
        contexts.uniq
      rescue Error => error
        unknown!(error.message, error.code)
      end

      def equivalent_declaration?(first, second, second_traffic)
        first_traffic = traffic(first)
        first_traffic.cover?(second_traffic) && second_traffic.cover?(first_traffic) && metadata(first) == metadata(second)
      end

      def metadata(rule)
        [ rule.action, rule.log, rule.log_enabled, rule.applications, rule.source_users, rule.security_profiles,
          rule.schedule&.kind, rule.schedule&.window, rule.starts_at, rule.expires_at, rule.semantic_conditions ]
      end

      def unknown!(message, code) = raise(Analysis::Unknown.new(message, code: code))
    end
  end
end
