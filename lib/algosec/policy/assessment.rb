# frozen_string_literal: true

require_relative "finding"

module Algosec
  module Policy
    Assessment = Data.define(:snapshot, :at, :findings) do
      def initialize(snapshot:, at:, findings:)
        super(snapshot: snapshot, at: at, findings: findings.dup.freeze)
      end

      def violations = findings.select { |finding| finding.status == :fail }

      def unknowns = findings.select { |finding| finding.status == :unknown }

      def complete? = snapshot.complete? && unknowns.empty?

      def passed? = complete? && violations.empty?
    end
  end
end
