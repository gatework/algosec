# frozen_string_literal: true

require_relative "value"

module Algosec
  module Policy
    # 分析与计划共用的判定记录；证据包含稳定规则身份，不依赖界面文案。
    Finding = Data.define(:check, :rule_id, :status, :severity, :message, :evidence, :remediation) do
      def initialize(check:, rule_id:, status:, severity:, message:, evidence: {}, remediation: nil)
        raise ArgumentError, "判定状态无效" unless %i[pass fail unknown].include?(status)
        super(check: check, rule_id: rule_id&.dup&.freeze, status: status, severity: severity,
              message: Value.text(message).freeze, evidence: Value.immutable(evidence), remediation: remediation)
      end
    end
  end
end
