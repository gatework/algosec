# frozen_string_literal: true

require_relative "change_set"
require_relative "effect_proof"

module Algosec
  module Policy
    # 一次性时间条件只在有限边界处改变；边界和每段常值区间分别复用安全证明。
    class TimeVerification < EffectProof
      Check = Data.define(:kind, :at, :from, :to, :verification) do
        def to_h
          { kind: kind, at: TimeVerification.instant_document(at), from: from && TimeVerification.instant_document(from),
            to: to && TimeVerification.instant_document(to), verification: verification.to_h }
        end
      end

      attr_reader :change_set, :candidate, :checks, :issues, :differences

      def initialize(change_set:, readback: nil)
        raise ArgumentError, "Time proof requires a ChangeSet" unless change_set.is_a?(ChangeSet)
        @change_set = change_set
        @readback = readback
        prove(readback)
      end

      def effect = :time
      def baseline = change_set.baseline
      def generation? = @readback.nil?
      def verified? = issues.empty? && differences.empty? && checks.any? && checks.all? { |check| check.verification.verified? }

      # 读回重新建立边界并运行全部安全求值，不接受旧的成功回执。
      def verify_readback(snapshot)
        raise ArgumentError, "Time readback requires a Snapshot" unless snapshot.is_a?(Snapshot)
        self.class.new(change_set: change_set, readback: snapshot)
      end

      def to_h
        { effect: effect, semantic_version: Algosec::SEMANTIC_VERSION, baseline: baseline,
          horizon: { from: self.class.instant_document(change_set.at), to: nil }, verified: verified?,
          expectations: change_set.to_h.fetch(:targets), checks: checks.map(&:to_h), issues: issues.map(&:to_h) }
      end

      def self.instant_document(time)
        { iso8601: time.iso8601(9), epoch: [ time.to_r.numerator, time.to_r.denominator ] }
      end

      private

      def prove(candidate)
        @candidate, @checks, @issues, @differences = candidate, [], [], []
        @candidate = candidate ||= change_set.apply
        unless candidate.is_a?(Snapshot)
          raise ArgumentError, "Time proof requires a Snapshot"
        end
        # 当前未生效不等于不相交；潜在流量先移除时间条件，再判断相关性。
        rules = change_set.temporal_rules(candidate: candidate)
        schedules = rules.filter_map(&:schedule) + change_set.targets.filter_map(&:effective_window)
        if rules.any? { |rule| rule.schedule_name && !rule.schedule } || schedules.any? { |schedule| schedule.kind != :once || !schedule.resolved? }
          raise Error.new("时间证明只支持完整的一次性窗口", code: :unsupported_time_proof)
        end
        bounds = schedules.flat_map { |schedule| [ schedule.window.begin, schedule.window.end, schedule.end_at.to_r ] } +
          rules.flat_map { |rule| [ rule.starts_at&.to_r, rule.expires_at&.to_r ] }.compact
        first = change_set.at.to_r
        boundaries = ([ first ] + bounds.map(&:to_r).select { |value| value >= first }).uniq.sort
        if boundaries.size * 2 > change_set.proof_limit
          raise Error.new("时间分段超出证明预算", code: :proof_budget_exceeded)
        end
        boundaries.each_with_index do |value, index|
          point = Time.at(value).utc.freeze
          check(:boundary, point, point, point)
          following = boundaries[index + 1]
          # 有理数边界之间必有精确中点；末界后不再有任何时间谓词变化。
          representative = following ? (value + following) / 2 : value + 1
          check(:interval, Time.at(representative).utc.freeze, point, following && Time.at(following).utc.freeze)
        end
      rescue Error, ArgumentError, KeyError => error
        @issues << Finding.new(check: :time_effect_proof, rule_id: nil, status: :unknown, severity: :critical,
          message: error.message, evidence: { code: error.respond_to?(:code) ? error.code : :unsupported_time_proof })
      ensure
        @checks.freeze
        @issues.freeze
        @differences.freeze
        freeze
      end

      def check(kind, at, from, to)
        verification = change_set.verify(candidate: candidate, at: at)
        @checks << Check.new(kind: kind, at: at, from: from, to: to, verification: verification)
        @issues.concat(verification.issues)
        @differences.concat(verification.differences)
      end
    end
  end
end
