# frozen_string_literal: true

require_relative "plan"
require_relative "time_verification"
require_relative "nat/verification"
require_relative "../config/document"
require_relative "plan_document/proposed_graph"

module Algosec
  module Policy
    # 审批输入文档保存声明而非证明回执；恢复始终重新构造领域对象并重新证明。
    class PlanDocument
      V = Config::Document::Value
      KEYS = %w[schema_version semantic_version operation script changes target_baseline source_baseline at_epoch proof_limit intents declarations targets required_effects effects].freeze

      def self.dump(plan)
        raise ArgumentError, "Expected executable Plan" unless plan.is_a?(Plan) && plan.executable?
        change = plan.change_set
        rules = change.intents.filter_map(&:rule)
        document = { "schema_version" => 2, "semantic_version" => Algosec::SEMANTIC_VERSION,
          "operation" => plan.operation.to_s, "script" => plan.script, "changes" => review(plan.changes),
          "target_baseline" => review(plan.target_baseline), "source_baseline" => review(plan.source_baseline),
          "at_epoch" => [ change.at.to_r.numerator, change.at.to_r.denominator ], "proof_limit" => change.proof_limit,
          "intents" => change.intents.map { |intent| { "operation" => intent.operation.to_s, "rule_id" => intent.rule_id,
            "rule" => intent.rule && rules.index(intent.rule), "placement" => intent.placement&.to_s, "before" => intent.before, "after" => intent.after } },
          "declarations" => ProposedGraph.dump(rules, snapshot: change.snapshot, at: change.at),
          "targets" => review(change.targets.map(&:to_h)), "required_effects" => plan.required_effects.map(&:to_s),
          "effects" => plan.effect_proofs.to_h { |effect, proof| [ effect.to_s, effect_inputs(proof, change) ] } }
        V.json(document)
      end

      def self.load(document, target:, source: target)
        V.json(document)
        V.object(document, KEYS)
        V.fail! unless document["schema_version"] == 2 && document["semantic_version"] == Algosec::SEMANTIC_VERSION
        V.fail! unless %w[configure migrate reclaim converge].include?(document["operation"]) && document["script"].is_a?(String)
        Plan.validate_baseline!(target, document.fetch("target_baseline"))
        Plan.validate_baseline!(source, document.fetch("source_baseline"))
        epoch = document.fetch("at_epoch")
        V.fail! unless epoch.is_a?(Array) && epoch.size == 2 && epoch.all? { |part| part.is_a?(Integer) } && epoch.last.positive?
        at = Time.at(Rational(*epoch)).utc
        rules = ProposedGraph.load(document.fetch("declarations"), snapshot: target)
        intents = document.fetch("intents").map do |entry|
          V.object(entry, %w[operation rule_id rule placement before after])
          operation = { "create" => :create, "modify" => :modify, "move" => :move, "delete" => :delete }.fetch(entry.fetch("operation"))
          placement = { nil => nil, "append" => :append, "prepend" => :prepend, "before_terminal" => :before_terminal }.fetch(entry.fetch("placement"))
          index = entry.fetch("rule")
          V.fail! unless index.nil? || (index.is_a?(Integer) && index >= 0 && index < rules.size)
          ChangeSet::Intent.new(operation: operation, rule_id: entry.fetch("rule_id"), rule: index && rules.fetch(index),
            placement: placement, before: entry.fetch("before"), after: entry.fetch("after"))
        end
        targets = document.fetch("targets").map { |entry| restore_target(entry) }
        change = ChangeSet.new(snapshot: target, intents: intents, targets: targets, at: at, proof_limit: document.fetch("proof_limit"))
        effects = document.fetch("required_effects")
        V.fail! unless effects.is_a?(Array) && effects.uniq == effects && (effects - %w[time nat]).empty?
        inputs = document.fetch("effects")
        V.fail! unless inputs.is_a?(Hash) && inputs.keys.sort == effects.sort
        proofs = inputs.to_h { |effect, value| [ { "time" => :time, "nat" => :nat }.fetch(effect), restore_effect(effect, value, change) ] }
        Plan.new(operation: document.fetch("operation").to_sym, snapshot: target, source: source,
          changes: document.fetch("changes"), commands: document.fetch("script"), change_set: change,
          required_effects: effects.map(&:to_sym), effect_proofs: proofs)
      rescue Config::Document::InvalidDocument, KeyError, TypeError, NoMethodError, IndexError => error
        raise ArgumentError, "Invalid approved plan document", cause: error
      end

      # 展示字段引用稳定身份；它们不参与领域对象恢复或授权。
      def self.review(value)
        case value
        when Hash then value.to_h { |key, item| [ key.to_s, review(item) ] }
        when Array then value.map { |item| review(item) }
        when Elements::Base then { "type" => value.class.name.split("::").last, "identity" => review(value.identity) }
        when Elements::Scope then review(value.to_h)
        when Set then { "ranges" => value.ranges.map { |range| [ range.begin, range.end ] } }
        when Time then value.iso8601(9)
        when Symbol then value.to_s
        when String, Integer, TrueClass, FalseClass, NilClass then value
        else raise ArgumentError, "Unsupported plan review value"
        end
      end

      def self.effect_inputs(proof, change)
        case proof
        when TimeVerification then { "kind" => "time" }
        when Nat::Verification
          { "kind" => "nat", "candidate" => ProposedGraph.dump(proof.candidate.catalog.to_a, snapshot: proof.candidate, at: change.at),
            "expectations" => review(proof.expectations.map(&:to_h)), "require_untranslated" => proof.require_untranslated }
        else raise ArgumentError, "Unsupported effect input"
        end
      end
      private_class_method :effect_inputs

      def self.restore_effect(effect, input, change)
        if effect == "time"
          V.object(input, %w[kind]); V.fail! unless input["kind"] == "time"
          TimeVerification.new(change_set: change)
        else
          V.object(input, %w[kind candidate expectations require_untranslated]); V.fail! unless input["kind"] == "nat"
          elements = ProposedGraph.load(input.fetch("candidate"), snapshot: change.snapshot)
          candidate = change.snapshot.with_catalog(Elements::Catalog.new(elements, vendor: change.snapshot.vendor, device_id: change.snapshot.device_id))
          Nat::Verification.new(snapshot: change.snapshot, candidate: candidate, change_set: change,
            expectations: input.fetch("expectations").map { |entry| Nat::Verification::Expectation.from_h(entry) },
            require_untranslated: input.fetch("require_untranslated"))
        end
      end
      private_class_method :restore_effect

      def self.restore_target(entry)
        V.object(entry, %w[traffic action context effective_window metadata])
        regions = entry.fetch("traffic").map do |region|
          V.object(region, [ "family", *TrafficSet::DIMENSIONS.map(&:to_s) ])
          family = { "ipv4" => :ipv4, "ipv6" => :ipv6 }.fetch(region.fetch("family"))
          { family: family, **TrafficSet::DIMENSIONS.to_h do |dimension|
            ranges = region.fetch(dimension.to_s).map do |pair|
              V.fail! unless pair.is_a?(Array) && pair.size == 2 && pair.all? { |part| part.is_a?(Integer) }
              pair.first..pair.last
            end
            [ dimension, Set.new(*ranges) ]
          end }
        end
        context = entry.fetch("context")
        V.object(context, %w[from_zone to_zone rule_set application source_user])
        window = entry.fetch("effective_window")
        if window
          V.object(window, %w[kind name start_at end_at window time_zone])
          V.fail! unless window["kind"] == "once"
          window_object = Elements::Schedule.new(name: window.fetch("name"), start_at: Time.iso8601(window.fetch("start_at")),
            end_at: Time.iso8601(window.fetch("end_at")), time_zone: window.fetch("time_zone"))
          V.fail! unless [ window_object.window.begin, window_object.window.end ] == window.fetch("window")
        end
        ChangeSet::Target.new(traffic_set: TrafficSet.new(regions), action: entry.fetch("action"),
          **context.transform_keys(&:to_sym), effective_window: window_object, metadata: restore_metadata(entry.fetch("metadata")))
      end
      private_class_method :restore_target

      def self.restore_metadata(metadata)
        V.fail! unless metadata.is_a?(Hash) && (metadata.keys - %w[log log_enabled]).empty?
        metadata.transform_keys(&:to_sym)
      end
      private_class_method :restore_metadata
    end
  end
end
