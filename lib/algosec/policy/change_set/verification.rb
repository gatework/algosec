# frozen_string_literal: true

require_relative "../change_set"

module Algosec
  module Policy
    class ChangeSet
      Verification = Data.define(:change_set, :candidate, :at, :target_evaluations, :differences, :issues) do
        def verified? = issues.empty? && differences.empty?

        def to_h
          { semantic_version: Algosec::SEMANTIC_VERSION, baseline: change_set.baseline, at: at.iso8601(9), at_epoch: [ at.to_r.numerator, at.to_r.denominator ], verified: verified?,
            targets: target_evaluations.map { |result| { complete: result.complete?, partitions: result.partitions.map { |part| ChangeSet.partition_document(part) } } },
            differences: differences.map do |difference|
              { kind: difference.kind, traffic: ChangeSet.traffic_document(difference.traffic_set), context: difference.context,
                before: ChangeSet.partition_document(difference.before), after: ChangeSet.partition_document(difference.after) }
            end,
            issues: issues.map(&:to_h) }
        end
      end
    end
  end
end
