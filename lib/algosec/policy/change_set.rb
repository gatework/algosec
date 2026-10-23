# frozen_string_literal: true

require_relative "evaluation"
require_relative "analysis"
require_relative "change_set/declaration_comparison"
require_relative "change_set/proof_contexts"

module Algosec
  module Policy
    # 意图、候选和证明分别保存；任何未知都不能成为执行许可。
    class ChangeSet
      Difference = Data.define(:kind, :traffic_set, :context, :before, :after)
      def self.traffic_document(traffic)
        traffic.regions.map do |region|
          { family: region.family, **TrafficSet::DIMENSIONS.to_h { |name| [ name, region.public_send(name).map { |range| [ range.begin, range.end ] } ] } }
        end
      end

      def self.partition_document(partition)
        return partition unless partition.is_a?(Evaluation::Partition)
        { traffic: traffic_document(partition.traffic_set), action: partition.action, status: partition.status,
          rule_id: partition.rule&.rule_id, log: partition.rule&.log, log_enabled: partition.rule&.log_enabled, reason: partition.reason, default: partition.default? }
      end

      attr_reader :snapshot, :intents, :targets, :at, :baseline, :proof_limit

      def initialize(snapshot:, intents:, targets:, at: Time.current, proof_limit: TrafficSet::DEFAULT_LIMIT)
        raise ArgumentError, "ChangeSet requires a Snapshot" unless snapshot.is_a?(Snapshot)
        raise ArgumentError, "Invalid intents" unless intents.is_a?(Array) && intents.all? { |intent| intent.is_a?(Intent) }
        raise ArgumentError, "Invalid targets" unless targets.is_a?(Array) && targets.all? { |target| target.is_a?(Target) }
        raise ArgumentError, "Proof limit must be positive" unless proof_limit.is_a?(Integer) && proof_limit.positive?
        @proof_limit = proof_limit
        snapshot.catalog.seal!
        snapshot.builtin_services.each(&:seal!)
        @snapshot, @intents, @targets, @at = snapshot, intents.dup.freeze, targets.dup.freeze, at.dup.freeze
        @baseline = snapshot.baseline
        freeze
      end

      # 固定时刻的安全证明不能替代转换或整个时间窗口的效果证明。
      def required_effects
        return [] if intents.empty? && targets.empty?
        rules = snapshot.rules + intents.filter_map(&:rule)
        effects = []
        effects << :nat if snapshot.nat_rules.any? || rules.any?(&:nat?)
        effects << :time if targets.any?(&:effective_window) || rules.any? { |rule| rule.schedule || rule.schedule_name || rule.starts_at || rule.expires_at }
        effects.freeze
      end

      # 只输出稳定的 JSON 证据；此文档不是可绕过重新证明的执行凭据。
      def to_h
        { semantic_version: Algosec::SEMANTIC_VERSION, baseline: baseline, at: at.iso8601(9), at_epoch: [ at.to_r.numerator, at.to_r.denominator ],
          intents: intents.map do |intent|
            rule = intent.rule
            { operation: intent.operation, rule_id: intent.rule_id || rule&.rule_id, placement: intent.placement, before: intent.before, after: intent.after,
              declaration: rule && { native_rule_id: rule.native_rule_id, rule_set: rule.rule_set, scope: rule.scope.to_h, action: rule.action,
                log: rule.log, log_enabled: rule.log_enabled, from_zones: rule.from_zones, to_zones: rule.to_zones } }
          end,
          targets: targets.map(&:to_h) }
      end

      def apply(current = snapshot)
        # 修订缺失时仍可离线证明，但不可把另一图当成原来的配置。
        raise Error.new("变更集基线对象已变化", code: :stale_plan) unless current.equal?(snapshot)
        current.require_complete!
        return current if intents.empty?
        return delete_rules(current) if intents.all? { |intent| intent.operation == :delete }
        sequences = current.rules.group_by { |rule| current.behavior.rule_chain(rule) }.transform_values do |rules|
          RuleOrder.new(current.behavior).resolve(rules).dup
        end
        intents.each do |intent|
          if intent.operation == :create
            rule = intent.rule
            unless rule.vendor == current.vendor && [ nil, current.device_id ].include?(rule.device_id)
              raise ArgumentError, "Candidate rule belongs to another device"
            end
            raise ArgumentError, "Duplicate candidate rule" if sequences.values.flatten.any? { |item| item.rule_id == rule.rule_id }
            chain = (sequences[current.behavior.rule_chain(rule)] ||= [])
            case intent.placement
            when :prepend then chain.unshift(rule)
            when :before_terminal
              chain.insert(chain.index { |item| current.behavior.terminal_rule?(item) } || chain.size, rule)
            else chain.push(rule)
            end
          else
            chain = sequences.values.find { |rules| rules.any? { |rule| rule.rule_id == intent.rule_id } }
            raise ArgumentError, "Unknown changed rule: #{intent.rule_id}" unless chain
            index = chain.index { |rule| rule.rule_id == intent.rule_id }
            case intent.operation
            when :delete then chain.delete_at(index)
            when :modify
              original = chain[index]
              unless intent.rule.identity == original.identity && current.behavior.rule_chain(intent.rule) == current.behavior.rule_chain(original)
                raise ArgumentError, "Modify cannot change rule identity or chain"
              end
              chain[index] = intent.rule
            when :move
              moving = chain.delete_at(index)
              anchor = chain.index { |rule| rule.rule_id == (intent.before || intent.after) }
              raise ArgumentError, "Move anchor must be another rule in the same chain" unless anchor
              chain.insert(anchor + (intent.after ? 1 : 0), moving)
            end
          end
        end
        original_ids = current.rules.map(&:rule_id)
        rules = sequences.values.flat_map { |chain| positioned(chain, original_ids) }
        catalog = Elements::Catalog.new(current.catalog.reject { |element| element.is_a?(Elements::SecurityRule) && !element.container? } + rules,
          vendor: current.vendor, device_id: current.device_id).seal!
        current.with_catalog(catalog)
      end

      def verify(candidate: nil, at: self.at)
        at = at.dup.freeze
        candidate ||= apply
        unless candidate.is_a?(Snapshot) && candidate.device_id == snapshot.device_id && candidate.vendor == snapshot.vendor && candidate.complete? &&
            candidate.software_version == snapshot.software_version && candidate.settings == snapshot.settings && candidate.time_zone == snapshot.time_zone
          raise ArgumentError, "Verification candidate must be a complete snapshot of the same device"
        end
        # 证明接管完整的同一张图；不能留下可在证明后修改的读回对象。
        candidate.catalog.seal!
        candidate.builtin_services.each(&:seal!)
        deleted_ids = intents.select { |intent| intent.operation == :delete }.map(&:rule_id)
        if candidate.rules.any? { |rule| deleted_ids.include?(rule.rule_id) }
          raise Error.new("读回仍包含计划删除的规则", code: :unfulfilled_deletion)
        end
        comparison = ChangeSet::DeclarationComparison.new(snapshot, candidate)
        affected_rules = candidate.equal?(snapshot) ? [] : comparison.changed_rules
        same_controls = candidate.equal?(snapshot) || comparison.same_control_context?
        budget = ChangeSet::ProofContexts::Budget.new(proof_limit)
        if !required_effects.include?(:time) && affected_rules.any? { |rule| rule.schedule || rule.schedule_name || rule.starts_at || rule.expires_at }
          raise Error.new("读回新增时间条件但计划没有时间证明", code: :unexpected_time_effect)
        end
        contexts = ChangeSet::ProofContexts.new(snapshot, candidate, targets: targets, rules: affected_rules, same_controls: same_controls, budget: budget).resolve
        active_targets = targets.select { |target| target.active?(at: at) }
        evaluations, differences = [], []
        active_targets.each do |target|
          evaluation = Evaluation.new(candidate, at: at).perform(target.traffic_set, **target.evaluation_context(behavior: candidate.behavior))
          evaluations << evaluation
          evaluation.partitions.each do |part|
            next if target.matches?(part)
            differences << Difference.new(kind: :target, traffic_set: part.traffic_set, context: target.context, before: target.metadata.empty? ? target.action : { action: target.action, metadata: target.metadata }, after: part)
          end
        end
        contexts.each do |context|
          affected = same_controls ? affected_traffic(affected_rules, context, at: at) : universe
          requested = active_targets.select { |target| target.covers_context?(context, behavior: snapshot.behavior) }.reduce(TrafficSet.new) { |set, target| set | target.traffic_set }
          outside = affected - requested
          next if outside.empty?
          before = Evaluation.new(snapshot, at: at).perform(outside, **context)
          after = Evaluation.new(candidate, at: at).perform(outside, **context)
          budget.charge!(before.partitions.size * after.partitions.size)
          before.partitions.each do |left|
            after.partitions.each do |right|
              shared = left.traffic_set & right.traffic_set
              next if shared.empty? || equivalent?(left, right)
              differences << Difference.new(kind: :outside_target, traffic_set: shared, context: context, before: left, after: right)
            end
          end
        end
        Verification.new(change_set: self, candidate: candidate, at: at, target_evaluations: evaluations.freeze, differences: differences.freeze, issues: [].freeze)
      rescue Error, ArgumentError, KeyError => error
        issue = Finding.new(check: :semantic_proof, rule_id: nil, status: :unknown, severity: :critical,
          message: error.message, evidence: { code: error.respond_to?(:code) ? error.code : :unproven_change })
        Verification.new(change_set: self, candidate: nil, at: at, target_evaluations: [].freeze, differences: [].freeze, issues: [ issue ].freeze)
      end

      # 时间分段只需要可能影响变更/目标域的规则；移除时间后仍复用同一匹配谓词。
      def temporal_rules(candidate:)
        comparison = ChangeSet::DeclarationComparison.new(snapshot, candidate)
        changed = comparison.changed_rules
        same_controls = comparison.same_control_context?
        budget = ChangeSet::ProofContexts::Budget.new(proof_limit)
        contexts = ChangeSet::ProofContexts.new(snapshot, candidate, targets: targets, rules: changed, same_controls: same_controls, budget: budget).resolve
        contexts = (contexts + targets.map { |target| target.evaluation_context(behavior: snapshot.behavior) }).uniq
        entries = [ snapshot, candidate ].flat_map { |graph| graph.rules.map { |rule| [ graph, rule ] } }
        projections = {}.compare_by_identity
        contexts.each_with_object([]) do |context, relevant|
          changed_entries = entries.select { |_graph, rule| changed.include?(rule) }
          affected = same_controls ? potential_traffic(changed_entries, context, projections) : universe
          targets.each do |target|
            next unless target.covers_context?(context, behavior: snapshot.behavior)
            affected |= target.traffic_set
          end
          next if affected.empty?
          entries.each do |graph, rule|
            next unless rule.schedule || rule.schedule_name || rule.starts_at || rule.expires_at
            budget.charge!(1)
            next if (potential_traffic([ [ graph, rule ] ], context, projections) & affected).empty?
            relevant << rule
          end
        end.uniq.freeze
      end

      private

      # 纯删除不需要为未启用规则臆造顺序；活动顺序是否可知仍交给安全证明。
      def delete_rules(current)
        ids = intents.map(&:rule_id)
        raise ArgumentError, "Duplicate deleted rule" unless ids.uniq.size == ids.size
        existing = current.rules.group_by(&:rule_id)
        ids.each do |id|
          raise ArgumentError, "Unknown or ambiguous changed rule: #{id}" unless existing[id]&.one?
        end
        removed = ids.to_h { |id| [ id, true ] }
        elements = current.catalog.reject do |element|
          element.is_a?(Elements::SecurityRule) && !element.container? && removed.key?(element.rule_id)
        end
        current.with_catalog(Elements::Catalog.new(elements, vendor: current.vendor, device_id: current.device_id).seal!)
      end

      def potential_traffic(entries, context, projections)
        entries.reduce(TrafficSet.new) do |traffic, (graph, rule)|
          next traffic unless graph.behavior.rule_in_zones?(rule, **context.slice(:from_zone, :to_zone))
          untimed = projections[rule] ||= rule.with(schedule: nil, schedule_name: nil,
            conditions: rule.semantic_conditions.except("starts_at", "expires_at"), unparsed_commands_metadata: rule.unparsed_commands_metadata).seal!
          predicate = Evaluation::Predicate.new(graph, untimed, at: at, domains: {},
            application: context[:application], source_user: context[:source_user], application_definitions: {})
          predicate.partitions(universe).reduce(traffic) { |all, part| all | part.traffic_set }
        end
      end

      # 保留已有的有效序号和对象；只有插入/移动确实需要时才复制顺序声明。
      def positioned(chain, original_ids)
        return chain if chain.all? { |rule| original_ids.include?(rule.rule_id) } && intents.none? { |intent| intent.operation == :move }
        anchors = chain.each_index.select { |index| original_ids.include?(chain[index].rule_id) }
        numbers = anchors.map { |index| chain[index].rule_number }
        if numbers.any?(&:nil?) || numbers.each_cons(2).any? { |left, right| left >= right }
          return chain.each_with_index.map { |rule, index| numbered(rule, index + 1) }
        end
        assigned = {}
        previous_index, previous_number = -1, 0
        (anchors + [ chain.size ]).each do |index|
          following = index == chain.size ? nil : chain[index].rule_number
          count = index - previous_index - 1
          if following && following - previous_number - 1 < count
            return chain.each_with_index.map { |rule, position| numbered(rule, position + 1) }
          end
          count.times { |offset| assigned[previous_index + offset + 1] = previous_number + offset + 1 }
          assigned[index] = following if following
          previous_index, previous_number = index, following
        end
        chain.each_with_index.map { |rule, index| numbered(rule, assigned.fetch(index)) }
      end

      def numbered(rule, number)
        rule.rule_number == number ? rule : rule.with(rule_number: number).seal!
      end

      def universe = TrafficSet.universe

      def affected_traffic(rules, context, at:)
        rules.reduce(TrafficSet.new) do |set, rule|
          next set unless snapshot.behavior.rule_in_zones?(rule, **context.slice(:from_zone, :to_zone))
          predicate = Evaluation::Predicate.new(snapshot, rule, at: at, domains: {},
            application: context[:application], source_user: context[:source_user], application_definitions: {})
          predicate.partitions(universe).reduce(set) { |affected, part| affected | part.traffic_set }
        end
      end

      def equivalent?(left, right)
        return false unless left.status == :matched && right.status == :matched && left.action == right.action
        metadata(left.rule) == metadata(right.rule)
      end

      def metadata(rule)
        return [ nil, nil, [], [], nil, {} ] unless rule
        [ rule.log, rule.log_enabled, rule.applications.reject { |name| name == "any" }, rule.source_users.reject { |name| name == "any" },
          rule.schedule&.window, rule.semantic_conditions ]
      end
    end
  end
end

require_relative "change_set/intent"
require_relative "change_set/target"
require_relative "change_set/verification"
