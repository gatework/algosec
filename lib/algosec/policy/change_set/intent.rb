# frozen_string_literal: true

require_relative "../change_set"

module Algosec
  module Policy
    class ChangeSet
      class Intent
        attr_reader :operation, :rule_id, :rule, :placement, :before, :after

        def self.create(rule:, placement:) = new(operation: :create, rule: rule, placement: placement)
        def self.modify(rule_id:, rule:) = new(operation: :modify, rule_id: rule_id, rule: rule)
        def self.move(rule_id:, before: nil, after: nil) = new(operation: :move, rule_id: rule_id, before: before, after: after)
        def self.delete(rule_id:) = new(operation: :delete, rule_id: rule_id)

        def initialize(operation:, rule_id: nil, rule: nil, placement: nil, before: nil, after: nil)
          raise ArgumentError, "Invalid change operation" unless %i[create modify move delete].include?(operation)
          if %i[create modify].include?(operation)
            raise ArgumentError, "Change requires a SecurityRule" unless rule.is_a?(Elements::SecurityRule)
          elsif !rule.nil?
            raise ArgumentError, "Only create and modify accept a rule"
          end
          if operation == :create
            raise ArgumentError, "Create derives identity from its rule" unless rule_id.nil?
            raise ArgumentError, "Create requires native placement" unless %i[append prepend before_terminal].include?(placement)
          else
            raise ArgumentError, "Change requires a rule id" unless rule_id.is_a?(String) && !rule_id.empty?
            raise ArgumentError, "Only create accepts placement" unless placement.nil?
          end
          anchors = [ before, after ].compact
          if operation == :move
            unless anchors.one? && anchors.first.is_a?(String) && !anchors.first.empty?
              raise ArgumentError, "Move requires one nonempty text anchor"
            end
          elsif anchors.any?
            raise ArgumentError, "Only move accepts an anchor"
          end
          @operation, @rule_id, @rule = operation, rule_id&.dup&.freeze, rule
          @placement, @before, @after = placement, before&.dup&.freeze, after&.dup&.freeze
          rule&.seal!
          freeze
        end
      end
    end
  end
end
