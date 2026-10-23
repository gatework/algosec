# frozen_string_literal: true

require "digest"
require "time"
require_relative "connector"
require_relative "policy/plan"
require_relative "deployment/attempt"
require_relative "deployment/verification"

module Algosec
  # 单次同步部署；持久化、租约和会话所有权由宿主明确提供，不重放写入。
  class Deployment
    class Uncertain < StandardError; end
    class JournalError < StandardError; end
    attr_reader :attempt, :apply_result, :save_result

    def initialize(plan:, journal:, verifier:, session: nil, session_factory: nil)
      raise ArgumentError, "Provide exactly one borrowed session or owned factory" unless !!session ^ !!session_factory
      @plan, @journal, @verifier, @session, @session_factory = plan, journal, verifier, session, session_factory
      @attempt, @recorded, @journal_failed, @performed = Attempt.new, {}, false, false
    end

    # 原连接器异常类型保持不变；调用者从 attempt 读取独立的终止证据。
    def perform
      raise ArgumentError, "Deployment cannot be replayed" if @performed
      @performed = true
      failure = nil
      completed = false
      begin
        validate_plan!
        journal(:prepare, plan: @plan)
        @session_factory ? execute_owned : execute(@session)
        journal(:check_claim!)
        completed = true
      rescue Exception => error # rubocop:disable Lint/RescueException -- 取消同样固定终态，收尾后原样传播。
        failure = error
      ensure
        # Thread#kill 与非局部退出不经过 rescue，仍须发布保守终态。
        failure ||= Uncertain.new("Deployment interrupted before completion") unless completed
        attempt.fail!(failure) if failure
        failure = finish_attempt(failure)
      end
      raise failure if failure
      attempt
    end

    private

    def finish_attempt(failure)
      finished = false
      begin
        attempt.transition!(:succeeded) unless failure
        journal(:finish, attempt: attempt)
        finished = true
        attempt.commit! unless @journal_failed
      rescue Exception => error # rubocop:disable Lint/RescueException -- 收尾异常不能覆盖原执行失败。
        failure ||= error
      ensure
        failure ||= Uncertain.new("Deployment journal interrupted before acknowledgement") unless finished
        attempt.fail!(failure) if failure
      end
      failure
    end

    def execute_owned
      failure = nil
      yielded = false
      begin
        @session_factory.open do |session|
          raise ArgumentError, "Session factory yielded more than once" if yielded
          yielded = true
          begin
            execute(session)
          rescue Exception => error # rubocop:disable Lint/RescueException -- 先让所有者关闭，再传播原取消异常。
            failure = error
          end
        end
        raise ArgumentError, "Session factory did not yield a session" unless yielded
        attempt.finish_execution!
      rescue Exception => error # rubocop:disable Lint/RescueException -- 关闭失败或二次取消不能覆盖最初的异常。
        failure ||= error
      end
      raise failure if failure
    end

    def validate_plan!
      unless @plan.is_a?(Policy::Plan) && @plan.executable? && @plan.semantic_version == Algosec::SEMANTIC_VERSION
        raise Policy::Error.new("部署需要当前语义版本的已生成且已证明计划", code: :incomplete_plan)
      end
    end

    def execute(session)
      journal(:check_claim!)
      capture = session.read_config
      context = @verifier.preflight(plan: @plan, capture: capture)
      raise ArgumentError, "Invalid preflight context" unless context.is_a?(Verification::Context)
      @plan.validate!(target: context.target, source: context.source)
      script = Net::Connector::Script.parse(@plan.script)
      transition(:prepared)
      transition(:executing)
      journal(:check_claim!)
      attempt.start_writes!
      index = 0
      result = @apply_result = execute_with_receipts(session, :execute_script, script) do |step|
        record(:apply, index, step)
        index += 1
        journal(:check_claim!)
      end
      attempt.note_error!(result.error) if result.failure?
      record_result(:apply, result)
      result.value!
      journal(:check_claim!)
      save_steps = []
      saved = @save_result = execute_with_receipts(session, :save_config) do |step|
        save_steps << step
        confirmed = Connector.persistence_confirmed?(@plan.vendor, Net::Connector::Result.new(steps: save_steps))
        attempt.confirm_persistence!(confirmed)
        record(:save, save_steps.size - 1, step)
        journal(:check_claim!)
      end
      attempt.note_error!(saved.error) if saved.failure?
      attempt.confirm_persistence!(attempt.persistence_confirmed? || Connector.persistence_confirmed?(@plan.vendor, saved))
      record_result(:save, saved)
      saved.value!
      journal(:check_claim!)
      transition(:verifying)
      evidence = @verifier.verify(plan: @plan, capture: session.read_config)
      raise ArgumentError, "Invalid semantic readback evidence" unless evidence.is_a?(Verification::Evidence)
      attempt.confirm_effect!(evidence.confirmed?)
      journal(:verification, evidence: evidence.to_h)
      journal(:check_claim!)
      unless attempt.effect_confirmed? && attempt.persistence_confirmed?
        raise Uncertain, "Device effect or persistence was not confirmed"
      end
    end

    # 完成回执是明确的会话能力；旧宿主会话仍使用原进度块和返回结果。
    def execute_with_receipts(session, operation, *arguments, &receipt)
      if session.method(operation).parameters.include?([ :key, :on_receipt ])
        session.public_send(operation, *arguments, on_receipt: receipt)
      else
        session.public_send(operation, *arguments, &receipt)
      end
    end

    def transition(status)
      journal(:transition, status: status)
      attempt.transition!(status)
    end

    def record_result(phase, result)
      receipts = result.steps.each_with_index.filter_map { |step, index| capture_receipt(phase, index, step) }
      receipts.each { |receipt| journal(:receipt, **receipt) }
    end

    # 即使 value! 将抛错，完成步骤也先固定；持久化失败的收据不自动重试。
    def record(phase, index, step)
      receipt = capture_receipt(phase, index, step)
      journal(:receipt, **receipt) if receipt
    end

    # 批量返回的全部完成事实先进入 attempt，首条日志失败也不能抹去后续事实。
    def capture_receipt(phase, index, step)
      key = [ phase, index ]
      return if @recorded[key]
      evidence = { command_sha256: Digest::SHA256.hexdigest(step.command.text).freeze, command_bytes: step.command.text.bytesize,
        sha256: Digest::SHA256.hexdigest(step.output).freeze, bytes: step.output.bytesize,
        observed_at: Time.now.utc.iso8601(6).freeze, outcome: :completed }.freeze
      @recorded[key] = true
      attempt.record(evidence.merge(phase: phase, index: index))
      { phase: phase, index: index, evidence: evidence }.freeze
    end

    def journal(method, **arguments)
      acknowledged = @journal.public_send(method, **arguments)
      raise JournalError, "Journal did not acknowledge #{method}" unless acknowledged == true
      true
    ensure
      # 无论抛错还是线程终止，只有明确确认才算已持久化。
      @journal_failed = true unless acknowledged == true || method == :check_claim!
    end
  end
end
