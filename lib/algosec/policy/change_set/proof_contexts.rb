# frozen_string_literal: true

module Algosec
  module Policy
    class ChangeSet
      # 从实际规则或绑定推导影响域；先扣除展开预算，再遍历区域对。
      class ProofContexts
        class Budget
          def initialize(limit)
            @remaining = limit
          end

          def charge!(count)
            raise Error.new("语义证明超过上下文或比较预算", code: :proof_budget_exceeded) if count > @remaining
            @remaining -= count
          end
        end

        def initialize(before, after, targets:, rules:, same_controls:, budget:)
          @snapshots, @targets, @rules = [ before, after ], targets, rules
          @same_controls, @budget = same_controls, budget
          @affected = {}.compare_by_identity
          rules.each { |rule| @affected[rule] = true }
        end

        def resolve
          return [] if @same_controls && @rules.empty?
          pairs = @snapshots.flat_map do |snapshot|
            rules = @same_controls ? snapshot.rules.select { |rule| @affected.key?(rule) } : snapshot.rules
            entries = rules.flat_map { |rule| snapshot.behavior.proof_zone_pairs(rule) }
            unless @same_controls
              entries += snapshot.elements(Elements::RuleBinding).map { |binding| [ [ binding.from_zone ], [ binding.to_zone ] ] }
            end
            entries
          end.uniq
          @pairs = pairs
          contexts = {}
          pairs.each do |from, to|
            sources, destinations = expand(from), expand(to)
            @budget.charge!(sources.size * destinations.size)
            sources.each do |source|
              destinations.each do |destination|
                add(contexts, from_zone: source, to_zone: destination, rule_set: nil, application: nil, source_user: nil)
              end
            end
          end
          @targets.each do |target|
            @budget.charge!(1)
            add(contexts, target.evaluation_context(behavior: @snapshots.first.behavior))
          end
          if contexts.empty? && !@same_controls
            raise Error.new("控制声明已变化但缺少可证明的作用域", code: :unproven_control_context)
          end
          contexts.values.freeze
        end

        private

        def add(contexts, context)
          contexts[context] ||= Value.immutable(context)
        end

        def expand(names)
          return known_zones if names.nil? || names.any? { |name| [ "any", "^" ].include?(name.downcase) }
          names.uniq
        end

        def known_zones
          @known_zones ||= begin
            names = @snapshots.flat_map do |snapshot|
              snapshot.elements(Elements::Zone).map(&:name) +
                snapshot.elements(Elements::RuleBinding).flat_map { |binding| [ binding.from_zone, binding.to_zone ] } +
                snapshot.rules.flat_map { |rule| Array(rule.from_zones) + Array(rule.to_zones) }
            end + @targets.flat_map { |target| target.context.values_at(:from_zone, :to_zone) } + @pairs.flatten.compact
            names = names.reject { |name| name.nil? || [ "any", "^" ].include?(name.downcase) }.uniq
            # 代表区域必须独立于真实名称；同时兼容厂商大小写不敏感的区域匹配。
            occupied = names.to_h { |name| [ name.downcase(:fold), true ] }
            index = 0
            representatives = []
            until representatives.size == 2
              name = "__algosec_unknown_zone_#{index}__"
              representatives << name unless occupied.key?(name)
              index += 1
            end
            # 两个未知区域分别代表同区和跨区，保留默认规则的区域关系。
            (names + representatives).freeze
          end
        end
      end
    end
  end
end
