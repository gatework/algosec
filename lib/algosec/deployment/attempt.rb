# frozen_string_literal: true

module Algosec
  class Deployment
    # 对外只暴露安全证据；正文和原异常由各自所有者保管。
    class Attempt
      attr_reader :status, :execution_finished_at, :error_code

      def initialize
        @status, @receipts = :prepared, []
        @writes_started = @effect_confirmed = @persistence_confirmed = @journal_committed = false
      end

      def writes_started? = @writes_started
      def effect_confirmed? = @effect_confirmed
      def persistence_confirmed? = @persistence_confirmed
      def journal_committed? = @journal_committed
      def receipts = @receipts.dup.freeze
      def to_h
        { status: status, writes_started: writes_started?, effect_confirmed: effect_confirmed?,
          persistence_confirmed: persistence_confirmed?, journal_committed: journal_committed?,
          execution_finished_at: execution_finished_at, error_code: error_code, receipts: receipts }.freeze
      end
      def inspect = "#<#{self.class.name} status=#{status} receipts=#{@receipts.size}>"

      # 状态转换仅由协调器调用，避免暴露可任意赋值的状态写入器。
      def transition!(status) = @status = status
      def finish_execution! = @execution_finished_at = Time.now.utc.iso8601(6)
      def start_writes! = @writes_started = true
      def confirm_effect!(confirmed) = @effect_confirmed = confirmed == true
      def confirm_persistence!(confirmed) = @persistence_confirmed = confirmed == true
      def commit! = @journal_committed = true

      def record(receipt) = @receipts << receipt.freeze
      def note_error!(error)
        @error_code ||= error.respond_to?(:code) ? error.code : :deployment_failed
      end

      def fail!(error)
        @status = writes_started? ? :uncertain : :failed
        note_error!(error)
      end
    end
  end
end
