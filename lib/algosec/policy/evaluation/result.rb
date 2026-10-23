# frozen_string_literal: true

require_relative "../evaluation"

module Algosec
  module Policy
    class Evaluation
      class Result
        attr_reader :partitions, :remaining, :unknown, :at

        def initialize(partitions:, remaining:, at:, proven: true)
          @proven = proven
          @partitions, @remaining, @at = partitions.dup.freeze, remaining, at.dup.freeze
          @unknown = partitions.reject { |part| part.status == :matched }.reduce(TrafficSet.new([], limit: remaining.limit)) do |set, part|
            set | part.traffic_set
          end
          freeze
        end

        def complete? = @proven && unknown.empty?
      end
    end
  end
end
