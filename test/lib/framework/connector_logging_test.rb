# frozen_string_literal: true

require "minitest/autorun"
require "tmpdir"
require "algosec"
require "algosec/connector"
require_relative "support/connector_fake"

class ConnectorLoggingTest < Minitest::Test
  def test_sensitive_profile_interaction_pauses_logging_and_restores_log_target
    with_device("Token:", "example-otp\nfw#") do |device, transport, path|
      assert_nil device.execute_command("verify").error
      refute_nil transport.log_output
      device.close

      assert_equal [ "verify\n", "example-otp\n" ], transport.writes
      log = File.binread(path)
      refute_includes log, "example-otp"
      refute_includes log, "Token:"
    end
  end

  def test_command_sensitive_interaction_restores_normal_logging_for_next_command
    with_device("Secret:", "command-token\nfw#", "ordinary output\nfw#", sensitive: false) do |device, _transport, path|
      interaction = Net::Connector::Interaction.new(/Secret:\z/, "command-token\n", sensitive: true)
      assert_nil device.execute_command("verify", interactions: [ interaction ]).error
      assert_nil device.execute_command("show status").error
      device.close

      log = File.binread(path)
      refute_includes log, "command-token"
      assert_includes log, "ordinary output"
    end
  end

  def test_sensitive_profile_response_is_redacted_from_errors
    with_device("Token:", "\nerror: example-otp rejected\nfw#") do |device, _transport, path|
      error = device.execute_command("verify").error
      assert_instance_of Net::Connector::DeviceError, error
      assert_includes error.message, "[REDACTED]"
      assert_includes error.output, "[REDACTED]"
      refute_includes error.message, "example-otp"
      refute_includes error.output, "example-otp"
      refute_includes File.binread(path), "example-otp"
    end
  end

  def test_nonsensitive_profile_interaction_keeps_logging_and_error_diagnostics
    with_device("Token:", "\nerror: public-response rejected\nfw#", sensitive: false) do |device, _transport, path|
      error = device.execute_command("verify").error
      assert_instance_of Net::Connector::DeviceError, error
      assert_includes error.message, "public-response rejected"
      assert_includes error.output, "public-response rejected"
      assert_includes File.binread(path), "public-response rejected"
    end
  end

  def test_sensitive_command_callback_failure_preserves_raw_step_and_redacts_error
    with_device("private-command\r\nfw#", sensitive: false) do |device, _transport, _path|
      result = device.execute_command("private-command", sensitive: true) do |step|
        raise "callback failed: #{step.command.text}"
      end

      assert_equal :script, result.error.phase
      assert_equal "[REDACTED]", result.error.command
      assert_equal "[REDACTED]", result.error.underlying.message
      assert_equal 1, result.steps.size
      assert_equal "private-command\r\nfw#", result.steps.first.output
      assert_equal "private-command", result.steps.first.command.text
      refute device.connected?
    end
  end

  def test_sensitive_interaction_after_command_failure_redacts_dynamic_response
    with_device("Token:", "example-otp\r\nfw#") do |device, _transport, _path|
      device.define_singleton_method(:after_command) do |_command, response, _execution|
        raise "postprocessing failed: #{response.raw}"
      end
      result = device.execute_command("verify")

      assert_equal :script, result.error.phase
      assert_equal "verify", result.error.command
      assert_equal "[REDACTED]", result.error.underlying.message
      refute_includes result.error.underlying.message, "example-otp"
      assert_includes result.error.underlying.message, "[REDACTED]"
      assert_equal 1, result.steps.size
      assert_includes result.steps.first.output, "example-otp\r\nfw#"
      refute device.connected?
    end
  end

  def test_sensitive_command_preparation_failure_redacts_the_unsent_command
    with_device(sensitive: false) do |device, transport, path|
      device.define_singleton_method(:prepare_command) do |command, _execution|
        raise "cannot prepare #{command.text}"
      end

      result = device.execute_command("private-command", sensitive: true)

      assert_equal "[REDACTED]", result.error.command
      assert_equal "[REDACTED]", result.error.underlying.message
      assert_empty result.steps
      assert_empty transport.writes
      refute_includes File.binread(path), "private-command"
      refute device.connected?
    end
  end

  def test_wrapped_preparation_error_redacts_underlying_message_and_backtrace
    with_device(sensitive: false) do |device, transport, _path|
      device.define_singleton_method(:prepare_command) do |command, _execution|
        original = RuntimeError.new("cannot prepare #{command.text}")
        original.set_backtrace([ "prepare #{command.text}" ])
        underlying = Net::Connector::UnderlyingError.new(original, Net::Connector::Redactor.new)
        raise Net::Connector::ScriptError.new("preparation failed", underlying: underlying)
      end

      result = device.execute_command("private-command", sensitive: true)

      assert_instance_of Net::Connector::ScriptError, result.error
      assert_equal "[REDACTED]", result.error.command
      assert_equal "RuntimeError", result.error.underlying.type
      assert_equal "[REDACTED]", result.error.underlying.message
      assert_empty result.error.underlying.backtrace
      assert_empty result.steps
      assert_empty transport.writes
      assert_nil result.error.cause
    end
  end

  private

  def with_device(*events, sensitive: true)
    response = sensitive ? "example-otp\n" : "public-response\n"
    connector_class = Class.new(Net::Connector::Base) do
      profile do
        prompts do
          login(/fw#\z/)
          command(/fw#\z/)
        end
        errors { command(/^error:/) }
        interactions { confirm(/Token:\z/, response: response, sensitive: sensitive) }
      end
    end
    Dir.mktmpdir("connector-logging") do |directory|
      path = File.join(directory, "session.log")
      transport = ConnectorFake.new("fw#", *events)
      device = connector_class.new(host: "192.0.2.1", transport: transport, log_file: path, log_level: :debug)
      begin
        yield device, transport, path
      ensure
        device.close
      end
    end
  end
end
