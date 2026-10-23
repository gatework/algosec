# frozen_string_literal: true

require "test_helper"
require "algosec/connector"
require_relative "support/connector_fake"

class DeploymentTest < ActiveSupport::TestCase
  class Journal
    attr_reader :events
    attr_accessor :fail_at, :claim
    def initialize
      @events, @claim = [], true
    end
    %i[prepare transition receipt verification finish].each do |method|
      define_method(method) do |**data|
        @events << [ method, data ]
        raise IOError, "journal unavailable" if fail_at == method
        true
      end
    end
    def check_claim!
      raise IOError, "claim lost" unless claim
      true
    end
  end

  class Session
    attr_accessor :apply_result, :save_result, :close_error, :on_apply
    attr_reader :calls
    def initialize(result)
      @apply_result = @save_result = result
      @calls = []
    end
    def read_config
      @calls << :read
      Algosec::DeviceSession::Capture.new(content: "config")
    end
    def execute_script(_script)
      @calls << :apply
      on_apply&.call
      apply_result.steps.each { |step| yield step } if block_given?
      apply_result
    end
    def save_config
      @calls << :save
      save_result
    end
    def close
      @calls << :close
      raise close_error if close_error
    end
  end

  class Factory
    def initialize(session) = @session = session
    def open
      yield @session
    ensure
      @session.close
    end
  end

  class Plan < Algosec::Policy::Plan
    attr_accessor :valid, :executable
    def initialize
      @valid = @executable = true
    end
    def executable? = executable
    def ready? = executable?
    def semantic_version = Algosec::SEMANTIC_VERSION
    def script = "configure\n"
    def vendor = :hillstone
    def validate!(target:, source:)
      raise Algosec::Policy::Error.new("drift", code: :stale_plan) unless valid
      self
    end
  end

  class Verifier
    attr_accessor :confirmed
    def initialize = @confirmed = true
    def preflight(plan:, capture:)
      Algosec::Deployment::Verification::Context.new(target: nil, source: nil)
    end
    def verify(plan:, capture:)
      Algosec::Deployment::Verification::Evidence.new(confirmed: confirmed, revision: "readback", semantic_version: Algosec::SEMANTIC_VERSION)
    end
  end

  def setup
    @journal, @plan, @verifier = Journal.new, Plan.new, Verifier.new
    @session = Session.new(result("configure"))
    @session.save_result = result("save all", "Saving configuration is finished\n")
  end

  def result(command, output = "private-output", error: nil)
    step = Net::Connector::Command::Result.new(command: Net::Connector::Command.new(command), output: output, prompt: nil, duration: 0.1)
    Net::Connector::Result.new(steps: [ step ], error: error)
  end

  def deployment(owned: false)
    options = owned ? { session_factory: Factory.new(@session) } : { session: @session }
    Algosec::Deployment.new(plan: @plan, journal: @journal, verifier: @verifier, **options)
  end

  test "deployment coordinator is available" do
    assert defined?(Algosec::Deployment), "Deployment must coordinate receipts before propagating results"
  end

  test "unready or stale plans do not send any command" do
    @plan.executable = false
    assert_raises(Algosec::Policy::Error) { deployment.perform }
    assert_empty @session.calls
    @plan.executable, @plan.valid = true, false
    assert_raises(Algosec::Policy::Error) { deployment.perform }
    assert_equal [ :read ], @session.calls
  end

  test "journal failure before first write leaves failed attempt and zero writes" do
    @journal.fail_at = :prepare
    runner = deployment
    assert_raises(IOError) { runner.perform }
    assert_equal :failed, runner.attempt.status
    refute runner.attempt.writes_started?
    assert_empty @session.calls
  end

  test "partial apply failure records completed commands before propagating original error" do
    error = Net::Connector::ScriptError.new("partial")
    @session.apply_result = result("private-command", error: error)
    runner = deployment
    assert_same error, assert_raises(Net::Connector::ScriptError) { runner.perform }
    assert_equal :uncertain, runner.attempt.status
    assert_equal 1, runner.attempt.receipts.size
    assert_equal [ :read, :apply ], @session.calls
    assert_equal 1, @journal.events.count { |event, _| event == :receipt }
    refute_includes runner.attempt.to_h.to_s, "private-output"
    refute_includes runner.attempt.to_h.to_s, "private-command"
  end

  test "receipt failure after write does not save or replay" do
    @journal.fail_at = :receipt
    runner = deployment
    assert_raises(IOError) { runner.perform }
    assert_equal :uncertain, runner.attempt.status
    assert_equal [ :read, :apply ], @session.calls
    refute runner.attempt.journal_committed?
  end

  test "lost claim at progress prevents save and success" do
    @session.on_apply = -> { @journal.claim = false }
    runner = deployment
    assert_raises(IOError) { runner.perform }
    assert_equal :uncertain, runner.attempt.status
    assert_equal [ :read, :apply ], @session.calls
    assert_equal 1, runner.attempt.receipts.size
  end

  test "owned session closes before execution finished evidence is committed" do
    runner = deployment(owned: true)
    attempt = runner.perform
    assert_equal :succeeded, attempt.status
    assert attempt.effect_confirmed?
    assert attempt.persistence_confirmed?
    assert attempt.journal_committed?
    assert attempt.execution_finished_at
    assert_equal :close, @session.calls.last
  end

  test "borrowed session stays open and does not assert owner termination" do
    attempt = deployment.perform
    refute_includes @session.calls, :close
    assert_nil attempt.execution_finished_at
  end

  test "partial save failure retains save receipts without readback or retry" do
    error = Net::Connector::ScriptError.new("save disconnected")
    @session.save_result = result("save all", error: error)
    runner = deployment
    assert_same error, assert_raises(Net::Connector::ScriptError) { runner.perform }
    assert_equal [ :apply, :save ], runner.attempt.receipts.map { |item| item[:phase] }
    assert_equal [ :read, :apply, :save ], @session.calls
    refute runner.attempt.persistence_confirmed?
  end

  test "unconfirmed save and mismatched readback stay uncertain" do
    @session.save_result = result("save all", "accepted")
    runner = deployment
    assert_raises(Algosec::Deployment::Uncertain) { runner.perform }
    refute runner.attempt.persistence_confirmed?
    @session.save_result = result("save all", "Saving configuration is finished\n")
    @verifier.confirmed = false
    runner = deployment
    assert_raises(Algosec::Deployment::Uncertain) { runner.perform }
    refute runner.attempt.effect_confirmed?
    assert runner.attempt.persistence_confirmed?
  end

  test "final journal or owned close failure cannot report success" do
    @journal.fail_at = :finish
    runner = deployment(owned: true)
    assert_raises(IOError) { runner.perform }
    assert_equal :uncertain, runner.attempt.status
    refute runner.attempt.journal_committed?
    @journal.fail_at = nil
    @session.close_error = IOError.new("close failure")
    runner = deployment(owned: true)
    assert_raises(IOError) { runner.perform }
    assert_equal :uncertain, runner.attempt.status
    assert_nil runner.attempt.execution_finished_at
  end

  test "actual connector accepts parsed script and DeviceSession preserves its results" do
    connector_class = Class.new(Net::Connector::Base) do
      profile do
        prompts do
          login(/fw#\z/)
          command(/fw#\z/)
        end
        commands { save_config "save all" }
      end
    end
    transport = ConnectorFake.new("fw#", "configured\nfw#", "Saving configuration is finished\nfw#")
    connector = connector_class.new(host: "192.0.2.1", transport: transport)
    @session = Algosec::DeviceSession.new(connector, vendor: :hillstone, device_id: 1)
    @session.define_singleton_method(:read_config) { Algosec::DeviceSession::Capture.new(content: "config") }
    attempt = deployment.perform
    assert_equal :succeeded, attempt.status
    assert_equal [ "configure\n", "save all\n" ], transport.writes
    assert_equal 2, attempt.receipts.size
    assert_equal 0, transport.closes
  ensure
    connector&.close
  end

  test "owned close error retains the original command failure and no termination claim" do
    original = Net::Connector::ScriptError.new("partial")
    @session.apply_result = result("configure", error: original)
    @session.close_error = IOError.new("close failed")
    runner = deployment(owned: true)
    assert_same original, assert_raises(Net::Connector::ScriptError) { runner.perform }
    assert_nil runner.attempt.execution_finished_at
    assert_equal :uncertain, runner.attempt.status
  end

  test "failure steps without progress callback are still journaled" do
    original = Net::Connector::ScriptError.new("after command failed")
    @session.apply_result = result("configure", error: original)
    @session.define_singleton_method(:execute_script) do |_script|
      @calls << :apply
      apply_result
    end
    runner = deployment
    assert_same original, assert_raises(Net::Connector::ScriptError) { runner.perform }
    assert_equal 1, @journal.events.count { |event, _| event == :receipt }
  end

  test "one coordinator cannot replay a completed attempt" do
    runner = deployment
    runner.perform
    assert_raises(ArgumentError) { runner.perform }
    assert_equal 1, @session.calls.count(:apply)
    assert_equal 1, @session.calls.count(:save)
  end


  test "lost claim before first write permits no device command" do
    @journal.claim = false
    runner = deployment
    assert_raises(IOError) { runner.perform }
    assert_equal :failed, runner.attempt.status
    refute runner.attempt.writes_started?
    assert_empty @session.calls
  end

  test "readback error keeps confirmed persistence separate from unknown effect" do
    reads = 0
    @session.define_singleton_method(:read_config) do
      @calls << :read
      reads += 1
      raise IOError, "readback lost" if reads > 1
      Algosec::DeviceSession::Capture.new(content: "config")
    end
    runner = deployment
    assert_raises(IOError) { runner.perform }
    assert_equal :uncertain, runner.attempt.status
    assert runner.attempt.persistence_confirmed?
    refute runner.attempt.effect_confirmed?
    assert_equal 1, @session.calls.count(:apply)
    assert_equal 1, @session.calls.count(:save)
  end

  test "unacknowledged prepare is failure before write" do
    @journal.define_singleton_method(:prepare) { |**| nil }
    runner = deployment
    assert_raises(Algosec::Deployment::JournalError) { runner.perform }
    assert_equal :failed, runner.attempt.status
    refute runner.attempt.journal_committed?
    assert_empty @session.calls
  end

  test "receipt evidence cannot be edited after publication" do
    attempt = deployment.perform
    receipt = attempt.receipts.first
    assert_raises(FrozenError) { receipt[:sha256].replace("forged") }
    assert_raises(FrozenError) { receipt[:observed_at].replace("forged") }
  end

  test "journal loss retains the returned failed connector result and original failure code" do
    original = Net::Connector::ScriptError.new("device rejected")
    @session.apply_result = result("configure", error: original)
    @session.define_singleton_method(:execute_script) { |_script| apply_result }
    @journal.fail_at = :receipt
    runner = deployment
    assert_raises(IOError) { runner.perform }
    assert_same @session.apply_result, runner.apply_result
    assert_same original, runner.apply_result.error
    assert_equal original.code, runner.attempt.error_code
    assert_equal :uncertain, runner.attempt.status
    refute runner.attempt.journal_committed?
  end

  test "returned completed steps all survive a failure to persist the first receipt" do
    [ :apply, :save ].each do |phase|
      setup
      original = Net::Connector::ScriptError.new("device rejected later command")
      steps = 3.times.flat_map { |index| result("private-command-#{index}").steps }
      returned = Net::Connector::Result.new(steps: steps, error: original)
      @session.public_send("#{phase}_result=", returned)
      @session.define_singleton_method(:execute_script) { |_script| @calls << :apply; apply_result }
      failed_indexes = []
      failure = IOError.new("receipt storage unavailable")
      @journal.define_singleton_method(:receipt) do |**receipt|
        next true unless receipt[:phase] == phase
        failed_indexes << receipt[:index]
        raise failure
      end
      runner = deployment

      assert_same failure, assert_raises(IOError) { runner.perform }
      retained = runner.attempt.receipts.select { |receipt| receipt[:phase] == phase }
      assert_equal [ 0, 1, 2 ], retained.map { |receipt| receipt[:index] }
      assert_equal steps.map { |step| Digest::SHA256.hexdigest(step.command.text) }, retained.map { |receipt| receipt[:command_sha256] }
      assert_equal [ 0 ], failed_indexes
      assert_same returned, runner.public_send("#{phase}_result")
      assert_equal original.code, runner.attempt.error_code
      assert_equal :uncertain, runner.attempt.status
      refute runner.attempt.journal_committed?
      refute runner.attempt.effect_confirmed?
      assert_equal 1, @session.calls.count(:apply)
      assert_equal phase == :save ? 1 : 0, @session.calls.count(:save)
    end
  end

  test "native save confirmation survives a subsequent connector logging failure" do
    event_sink = lambda do |event|
      if event.name == "command_complete" && event.fields[:text] == "save all" && event.fields[:status] == "response_received"
        raise IOError, "event sink unavailable"
      end
    end
    transport = ConnectorFake.new("fw#", "configured\nfw#", "Saving configuration is finished\nfw#")
    connector = Algosec::Connector.build(:hillstone, host: "192.0.2.1", transport: transport, on_event: event_sink)
    session = Algosec::DeviceSession.new(connector, vendor: :hillstone, device_id: 1)
    session.define_singleton_method(:read_config) { Algosec::DeviceSession::Capture.new(content: "config") }
    runner = Algosec::Deployment.new(plan: @plan, journal: @journal, verifier: @verifier, session: session)

    error = assert_raises(Net::Connector::LogError) { runner.perform }
    assert_same error, runner.save_result.error
    assert runner.attempt.persistence_confirmed?
    refute runner.attempt.effect_confirmed?
    assert_equal :uncertain, runner.attempt.status
    assert_equal [ :apply, :save ], runner.attempt.receipts.map { |receipt| receipt[:phase] }
    assert_equal [ "configure\n", "save all\n" ], transport.writes
  ensure
    connector&.close
  end

  test "completion callback preserves receipts and confirmed save before original cancellation" do
    [ :apply, :save ].each do |phase|
      setup
      interruption = Interrupt.new("cancel after completed response")
      applied, saved = @session.apply_result, @session.save_result
      calls, progress_calls = [], []
      connector = Object.new
      connector.define_singleton_method(:send_commands) { |*| raise "unexpected collection" }
      connector.define_singleton_method(:connected?) { true }
      connector.define_singleton_method(:execute_script) do |_script, on_receipt: nil, &progress|
        calls << :apply
        applied.steps.each { |step| on_receipt&.call(step) }
        progress_calls << :apply if progress
        raise interruption if phase == :apply
        applied
      end
      connector.define_singleton_method(:save_config) do |on_receipt: nil|
        calls << :save
        saved.steps.each { |step| on_receipt&.call(step) }
        raise interruption
      end
      session = Algosec::DeviceSession.new(connector, vendor: :hillstone, device_id: 1)
      session.define_singleton_method(:read_config) { Algosec::DeviceSession::Capture.new(content: "config") }
      runner = Algosec::Deployment.new(plan: @plan, journal: @journal, verifier: @verifier, session: session)

      assert_same interruption, assert_raises(Interrupt) { runner.perform }
      assert_equal phase == :apply ? [ :apply ] : [ :apply, :save ], calls
      assert_equal calls, runner.attempt.receipts.map { |receipt| receipt[:phase] }
      assert_equal phase == :save, runner.attempt.persistence_confirmed?
      refute runner.attempt.effect_confirmed?
      assert_equal :uncertain, runner.attempt.status
      assert runner.attempt.journal_committed?
      assert_empty progress_calls
    end
  end

  test "native response cancellation preserves evidence exposed by the installed connector" do
    [ :apply, :save ].each do |phase|
      setup
      interruption = Interrupt.new("cancel after response")
      trigger = phase == :apply ? "configure" : "save all"
      event_sink = lambda do |event|
        raise interruption if event.name == "command_complete" && event.fields[:text] == trigger
      end
      transport = ConnectorFake.new("fw#", "configured\nfw#", "Saving configuration is finished\nfw#")
      connector = Algosec::Connector.build(:hillstone, host: "192.0.2.1", transport: transport, on_event: event_sink)
      session = Algosec::DeviceSession.new(connector, vendor: :hillstone, device_id: 1)
      session.define_singleton_method(:read_config) { Algosec::DeviceSession::Capture.new(content: "config") }
      runner = Algosec::Deployment.new(plan: @plan, journal: @journal, verifier: @verifier, session: session)
      # 同一集成回归覆盖已发布依赖的限制与新增完成回执协议；不把旧依赖的缺口算作已修复。
      completion_receipts = connector.method(:execute_script).parameters.include?([ :key, :on_receipt ])

      assert_same interruption, assert_raises(Interrupt) { runner.perform }
      expected = phase == :apply ? [] : [ :apply ]
      expected << phase if completion_receipts
      assert_equal expected, runner.attempt.receipts.map { |receipt| receipt[:phase] }
      assert_equal expected.size, @journal.events.count { |name, _| name == :receipt }
      assert_equal completion_receipts && phase == :save, runner.attempt.persistence_confirmed?
      refute runner.attempt.effect_confirmed?
      assert_equal :uncertain, runner.attempt.status
      assert runner.attempt.journal_committed?
      assert_nil runner.save_result
      assert_equal phase == :apply ? [ "configure\n" ] : [ "configure\n", "save all\n" ], transport.writes
      assert_equal 1, transport.closes
      assert_raises(ArgumentError) { runner.perform }
    ensure
      connector&.close
    end
  end

  test "native thread termination survives a secondary receipt journal failure" do
    event_sink = lambda do |event|
      Thread.current.kill if event.name == "command_complete" && event.fields[:text] == "save all"
    end
    transport = ConnectorFake.new("fw#", "configured\nfw#", "Saving configuration is finished\nfw#")
    connector = Algosec::Connector.build(:hillstone, host: "192.0.2.1", transport: transport, on_event: event_sink)
    session = Algosec::DeviceSession.new(connector, vendor: :hillstone, device_id: 1)
    session.define_singleton_method(:read_config) { Algosec::DeviceSession::Capture.new(content: "config") }
    @journal.define_singleton_method(:receipt) do |phase:, **|
      raise IOError, "save receipt unavailable" if phase == :save
      true
    end
    runner = Algosec::Deployment.new(plan: @plan, journal: @journal, verifier: @verifier, session: session)
    completion_receipts = connector.method(:save_config).parameters.include?([ :key, :on_receipt ])
    continued = false
    worker = Thread.new { runner.perform; continued = true }

    assert worker.join(5), "deployment thread did not terminate"
    refute continued
    assert_equal completion_receipts ? [ :apply, :save ] : [ :apply ], runner.attempt.receipts.map { |receipt| receipt[:phase] }
    assert_equal completion_receipts, runner.attempt.persistence_confirmed?
    assert_equal !completion_receipts, runner.attempt.journal_committed?
    assert_equal :uncertain, runner.attempt.status
    refute runner.attempt.effect_confirmed?
    assert_nil runner.save_result
    assert_equal [ "configure\n", "save all\n" ], transport.writes
    assert_equal 1, transport.closes
  ensure
    worker&.kill&.join
    connector&.close
  end

  test "save completion is retained before its receipt journal fails" do
    @session.define_singleton_method(:save_config) do |&block|
      @calls << :save
      save_result.steps.each(&block)
      save_result
    end
    failure = IOError.new("receipt unavailable")
    @journal.define_singleton_method(:receipt) do |phase:, **|
      raise failure if phase == :save
      true
    end
    runner = deployment

    assert_same failure, assert_raises(IOError) { runner.perform }
    assert_nil runner.save_result
    assert runner.attempt.persistence_confirmed?
    assert_equal [ :apply, :save ], runner.attempt.receipts.map { |receipt| receipt[:phase] }
    refute runner.attempt.journal_committed?
    assert_equal :uncertain, runner.attempt.status
    assert_equal [ :read, :apply, :save ], @session.calls
  end

  test "owned factory must yield exactly once and cannot cause a second write sequence" do
    factory = Object.new
    factory.define_singleton_method(:open) { |&block| nil }
    runner = Algosec::Deployment.new(plan: @plan, journal: @journal, verifier: @verifier, session_factory: factory)
    assert_raises(ArgumentError) { runner.perform }
    assert_equal :failed, runner.attempt.status
    assert_empty @session.calls
    session = @session
    factory.define_singleton_method(:open) { |&block| 2.times { block.call(session) } }
    runner = Algosec::Deployment.new(plan: @plan, journal: @journal, verifier: @verifier, session_factory: factory)
    assert_raises(ArgumentError) { runner.perform }
    assert_equal :uncertain, runner.attempt.status
    assert_equal 1, @session.calls.count(:apply)
    assert_equal 1, @session.calls.count(:save)
  end

  test "owned cancellation closes before terminal evidence and rethrows the original interrupt" do
    interruption = Interrupt.new("cancel")
    @session.on_apply = -> { raise interruption }
    runner = deployment(owned: true)
    assert_same interruption, assert_raises(Interrupt) { runner.perform }
    assert_equal :uncertain, runner.attempt.status
    assert runner.attempt.execution_finished_at
    assert_equal [ :read, :apply, :close ], @session.calls
    assert_equal 1, @journal.events.count { |name, _| name == :finish }
  end

  test "thread termination finalizes owned and borrowed attempts without replay" do
    [ false, true ].each do |owned|
      setup
      @session.on_apply = -> { Thread.current.kill }
      runner = deployment(owned: owned)

      worker = Thread.new { runner.perform }
      assert worker.join(5), "deployment thread did not terminate"
      assert_equal :uncertain, runner.attempt.status
      assert runner.attempt.writes_started?
      assert runner.attempt.journal_committed?
      assert_equal 1, @journal.events.count { |name, _| name == :finish }
      assert_equal owned ? [ :read, :apply, :close ] : [ :read, :apply ], @session.calls
      assert_nil runner.attempt.execution_finished_at
      assert_raises(ArgumentError) { runner.perform }
    ensure
      worker&.kill&.join
    end
  end

  test "thread termination before writes records failure and a lost journal acknowledgement" do
    @journal.define_singleton_method(:prepare) { |**| Thread.current.kill }
    runner = deployment(owned: true)

    worker = Thread.new { runner.perform }
    assert worker.join(5), "deployment thread did not terminate"
    assert_equal :failed, runner.attempt.status
    refute runner.attempt.writes_started?
    refute runner.attempt.journal_committed?
    assert_empty @session.calls
    assert_equal 1, @journal.events.count { |name, _| name == :finish }
  ensure
    worker&.kill&.join
  end

  test "thread termination during terminal journal cannot expose success" do
    @journal.define_singleton_method(:finish) do |**data|
      @events << [ :finish, data ]
      Thread.current.kill
    end
    runner = deployment(owned: true)

    worker = Thread.new { runner.perform }
    assert worker.join(5), "deployment thread did not terminate"
    assert_equal :uncertain, runner.attempt.status
    assert runner.attempt.effect_confirmed?
    assert runner.attempt.persistence_confirmed?
    refute runner.attempt.journal_committed?
    assert runner.attempt.execution_finished_at
    assert_equal 1, @journal.events.count { |name, _| name == :finish }
    assert_equal 1, @session.calls.count(:apply)
    assert_equal 1, @session.calls.count(:save)
  ensure
    worker&.kill&.join
  end

  test "borrowed cancellation records uncertainty without closing the external owner" do
    interruption = Interrupt.new("cancel")
    @session.on_apply = -> { raise interruption }
    runner = deployment
    assert_same interruption, assert_raises(Interrupt) { runner.perform }
    assert_equal :uncertain, runner.attempt.status
    assert_nil runner.attempt.execution_finished_at
    refute_includes @session.calls, :close
    assert_equal 1, @journal.events.count { |name, _| name == :finish }
  end

  test "final journal cancellation cannot expose an uncommitted success" do
    interruption = Interrupt.new("cancel final commit")
    finish_calls = 0
    @journal.define_singleton_method(:finish) do |**|
      finish_calls += 1
      raise interruption
    end
    runner = deployment(owned: true)
    assert_same interruption, assert_raises(Interrupt) { runner.perform }
    assert_equal :uncertain, runner.attempt.status
    refute runner.attempt.journal_committed?
    assert runner.attempt.execution_finished_at
    assert_equal 1, finish_calls
  end

  test "cancellation plus close failure preserves cancellation without termination proof" do
    interruption = Interrupt.new("cancel")
    @session.on_apply = -> { raise interruption }
    @session.close_error = IOError.new("close failed")
    runner = deployment(owned: true)
    assert_same interruption, assert_raises(Interrupt) { runner.perform }
    assert_equal :uncertain, runner.attempt.status
    assert_nil runner.attempt.execution_finished_at
    assert_equal 1, @journal.events.count { |name, _| name == :finish }
  end

  test "SystemExit before writes stays failed and is rethrown unchanged" do
    cancellation = SystemExit.new(2)
    @session.define_singleton_method(:read_config) { raise cancellation }
    runner = deployment(owned: true)
    assert_same cancellation, assert_raises(SystemExit) { runner.perform }
    assert_equal :failed, runner.attempt.status
    refute runner.attempt.writes_started?
    assert runner.attempt.execution_finished_at
    assert_equal [ :close ], @session.calls
    assert_equal 1, @journal.events.count { |name, _| name == :finish }
  end

  test "receipt cancellation does not become a complete journal commit" do
    interruption = Interrupt.new("cancel receipt")
    @journal.define_singleton_method(:receipt) { |**| raise interruption }
    runner = deployment(owned: true)
    assert_same interruption, assert_raises(Interrupt) { runner.perform }
    assert_equal :uncertain, runner.attempt.status
    refute runner.attempt.journal_committed?
    assert runner.attempt.execution_finished_at
    assert_equal 1, runner.attempt.receipts.size
  end

  test "confirmed save remains confirmed when save receipt persistence fails" do
    failure = IOError.new("save receipt unavailable")
    @journal.define_singleton_method(:receipt) do |phase:, **|
      raise failure if phase == :save
      true
    end
    runner = deployment(owned: true)
    assert_same failure, assert_raises(IOError) { runner.perform }
    assert_same @session.save_result, runner.save_result
    assert runner.attempt.persistence_confirmed?
    assert_equal :uncertain, runner.attempt.status
    refute runner.attempt.journal_committed?
    refute runner.attempt.effect_confirmed?
    finish = @journal.events.find { |name, _| name == :finish }.last.fetch(:attempt)
    assert finish.persistence_confirmed?
    assert_equal 1, @session.calls.count(:save)
  end

  test "installed connector cancellation closes once and retains terminal ownership evidence" do
    connector_class = Class.new(Net::Connector::Base) do
      profile do
        prompts do
          login(/fw#\z/)
          command(/fw#\z/)
        end
      end
    end
    interruption = Interrupt.new("cancel transport")
    transport = ConnectorFake.new("fw#")
    transport.on_write = ->(*) { raise interruption }
    factory = Object.new
    factory.define_singleton_method(:open) do |&block|
      connector_class.open(host: "192.0.2.1", transport: transport) do |connector|
        session = Algosec::DeviceSession.new(connector, vendor: :hillstone, device_id: 1)
        session.define_singleton_method(:read_config) { Algosec::DeviceSession::Capture.new(content: "config") }
        block.call(session)
      end
    end
    runner = Algosec::Deployment.new(plan: @plan, journal: @journal, verifier: @verifier, session_factory: factory)
    assert_same interruption, assert_raises(Interrupt) { runner.perform }
    assert_equal :uncertain, runner.attempt.status
    assert runner.attempt.execution_finished_at
    assert_equal [ "configure\n" ], transport.writes
    assert_equal 1, transport.closes
    assert_equal 1, @journal.events.count { |name, _| name == :finish }
  end
end
