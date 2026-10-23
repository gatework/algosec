# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "support/connector_fake"

class ConnectorExecutionTest < Minitest::Test
  def test_registered_connector_reuses_session_and_stops_at_device_error
    transport = ConnectorFake.new("router#", "one\nrouter#", "two\nrouter#", "% Incomplete command.\nrouter#")
    device = Algosec::Connector.build("Cisco IOS", host: "192.0.2.1", transport: transport)
    result = device.execute_script([ "first", "second", "bad", "never" ])
    assert_equal [ "first\n", "second\n", "bad\n" ], transport.writes
    assert_equal 2, result.steps.size
    assert_instance_of Net::Connector::DeviceError, result.error
    assert_equal 1, transport.opens
    assert_equal 1, transport.closes
  ensure
    device&.close
  end

  def test_invalid_command_batch_performs_no_io
    transport = ConnectorFake.new
    device = Algosec::Connector.build(:cisco_n9k, host: "192.0.2.1", transport: transport)
    assert_raises(Net::Connector::ScriptError) { device.execute_script([ "show version", "bad\ncommand" ]) }
    assert_equal 0, transport.opens
    assert_empty transport.writes
  ensure
    device&.close
  end

  def test_expired_interaction_callback_does_not_send_confirmation
    now = 100.0
    transport = ConnectorFake.new("router#", "Proceed?")
    device = Algosec::Connector.build(:cisco_ios, host: "192.0.2.1", transport: transport)
    interaction = Net::Connector::Interaction.new(/Proceed\?\z/, ->(_prompt) {
      now += 2
      "yes\n"
    })

    original_clock = Expect.method(:monotonic)
    Expect.define_singleton_method(:monotonic) { now }
    result = device.execute_command("delete configuration", interactions: [ interaction ], timeout: 1)

    # 新版引擎在交互回调耗尽命令预算后即停止，不再进入写入阶段。
    assert_instance_of Net::Connector::CommandTimeout, result.error
    assert_equal [ "delete configuration\n" ], transport.writes
    assert_equal :command, result.error.phase
    assert_empty result.steps
    refute device.connected?
  ensure
    Expect.define_singleton_method(:monotonic, original_clock) if original_clock
    device&.close
  end

  def test_device_session_keeps_success_progress_separate_from_completed_receipts
    [ Net::Connector::LogError.new("event sink failed"), nil ].each do |error|
      step = Net::Connector::Command::Result.new(command: Net::Connector::Command.new("first"),
        output: "done", prompt: nil, duration: 0.1)
      expected = Net::Connector::Result.new(steps: [ step ], error: error)
      connector = Object.new
      connector.define_singleton_method(:send_commands) { |*| raise "unexpected collection" }
      connector.define_singleton_method(:connected?) { true }
      connector.define_singleton_method(:execute_script) do |_script, on_receipt: nil, &progress|
        on_receipt&.call(step)
        progress&.call(step) if expected.success?
        expected
      end
      session = Algosec::DeviceSession.new(connector, vendor: :hillstone)
      progress, receipts = [], []

      assert_same expected, session.execute_script([ "first" ]) { |completed| progress << completed }
      assert_equal error ? [] : [ step ], progress
      progress.clear
      actual = session.execute_script([ "first" ], on_receipt: ->(completed) { receipts << completed }) do |completed|
        progress << completed
      end
      assert_same expected, actual
      assert_equal [ step ], receipts
      assert_equal error ? [] : [ step ], progress
    end
  end

  def test_device_session_supports_explicit_receipts_with_the_legacy_progress_contract
    step = Net::Connector::Command::Result.new(command: Net::Connector::Command.new("first"),
      output: "done", prompt: nil, duration: 0.1)
    expected = Net::Connector::Result.new(steps: [ step ])
    connector = Object.new
    connector.define_singleton_method(:send_commands) { |*| raise "unexpected collection" }
    connector.define_singleton_method(:connected?) { true }
    connector.define_singleton_method(:execute_script) { |_script, &progress| progress&.call(step); expected }
    session = Algosec::DeviceSession.new(connector, vendor: :hillstone)
    events = []

    actual = session.execute_script([ "first" ], on_receipt: ->(_) { events << :receipt }) { events << :progress }

    assert_same expected, actual
    assert_equal [ :receipt, :progress ], events
    [ false, Object.new ].each do |invalid|
      assert_raises(ArgumentError) { session.execute_script([ "never" ], on_receipt: invalid) }
    end
    assert_equal [ :receipt, :progress ], events
  end
end
