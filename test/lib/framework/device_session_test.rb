# frozen_string_literal: true

require "test_helper"
require "json"
require "pp"
require_relative "support/connector_fake"

class DeviceSessionTest < Minitest::Test
  CONFIGURATION = "zone inside\nexit\nzone outside\nexit\nrule id 7\n action permit\nexit\n".freeze
  SERVICES = "Name Protocol Dst-Port/Type Src-Port/Code Timeout\nTotal configured: 1\nHTTPS TCP 443 Any -\n".freeze

  def test_login_collect_parse_and_close_use_the_real_gems
    transport = ConnectorFake.new("login:", "Password:", "fw#", "terminal length 0\nfw#",
      "show configuration running\n#{CONFIGURATION}fw#", "show service predefined\n#{SERVICES}fw#")
    captured = Algosec::DeviceSession.open(:hillstone, device_id: 42, host: "192.0.2.1", username: "operator", password: "secret", transport: transport) do |session|
      session.collect
    end

    assert_equal CONFIGURATION, captured.content
    assert_equal [ "operator\n", "secret\n", "terminal length 0\n", "show configuration running\n", "show service predefined\n" ], transport.writes
    assert_equal 1, transport.opens
    assert_equal 1, transport.closes
    assert_equal 3, captured.evidence.size
    assert captured.evidence.all? { |entry| entry[:sha256].size == 64 && entry[:bytes].positive? }
    result = Algosec::Config::Parser.perform(captured.content, vendor: :hillstone, device_id: 42, builtin_services: captured.builtin_services)
    assert result.complete?, result.diagnostics.inspect
    assert_equal "7", result.rules.sole.rule_id
    assert_equal "HTTPS", captured.builtin_services.values.sole.name
    assert_equal 42, captured.builtin_services.values.sole.device_id
  end

  def test_driver_preserves_command_body_and_stops_after_session_loss
    transport = ConnectorFake.new("fw#", "show first\n  值\nfw#", :timeout)
    Algosec::DeviceSession.open(:hillstone, host: "192.0.2.1", transport: transport) do |session|
      first = session.read("show first")
      assert_instance_of CtxDriver::Capture, first
      assert first.success?
      assert_equal "  值\n", first.body
      failed = session.read("show second")
      refute failed.success?
      skipped = session.read("show third")
      assert skipped.skipped?
      assert_equal failed.failure, skipped.failure
      assert_equal [ "show first\n", "show second\n" ], transport.writes
    end
  end

  def test_failed_configuration_does_not_request_services_or_reconnect
    transport = ConnectorFake.new("fw#", "fw#", :timeout)
    assert_raises(Net::Connector::CommandTimeout) do
      Algosec::DeviceSession.open(:hillstone, host: "192.0.2.1", transport: transport) { |session| session.collect }
    end
    assert_equal [ "terminal length 0\n", "show configuration running\n" ], transport.writes
    assert_equal 1, transport.opens
    assert_equal 1, transport.closes
  end

  def test_failed_builtin_query_rejects_the_capture_without_exposing_output
    transport = ConnectorFake.new("fw#", "fw#", "#{CONFIGURATION}fw#", "Error: private-secret-material\nfw#")
    error = assert_raises(Algosec::DeviceSession::ReadError) do
      Algosec::DeviceSession.open(:hillstone, host: "192.0.2.1", transport: transport) { |session| session.collect }
    end
    refute_includes error.message, "private-secret-material"
    assert_equal :device_error, error.code
  end

  def test_read_config_only_reads_configuration_even_for_hillstone
    transport = ConnectorFake.new("fw#", "fw#", "#{CONFIGURATION}fw#")
    captured = Algosec::DeviceSession.open(:hillstone, host: "192.0.2.1", transport: transport) do |session|
      session.read_config
    end

    assert_equal CONFIGURATION, captured.content
    assert_nil captured.builtin_services
    assert_equal [ "terminal length 0\n", "show configuration running\n" ], transport.writes
    assert_equal 1, transport.closes
  end

  def test_incomplete_builtin_table_does_not_return_a_successful_capture
    table = SERVICES.sub("Total configured: 1", "Total configured: 2")
    transport = ConnectorFake.new("fw#", "fw#", "#{CONFIGURATION}fw#", "#{table}fw#")

    error = assert_raises(ArgumentError) do
      Algosec::DeviceSession.open(:hillstone, host: "192.0.2.1", transport: transport) { |session| session.collect }
    end
    assert_match(/Incomplete predefined service table/, error.message)
    assert_equal 1, transport.opens
    assert_equal 1, transport.closes
  end

  def test_capture_summary_hides_body_and_builtin_definitions
    capture = Algosec::DeviceSession::Capture.new(content: "private-secret-material")
    [ capture.inspect, capture.to_s, PP.pp(capture, +""), JSON.generate(capture.as_json) ].each do |text|
      refute_includes text, "private-secret-material"
    end
    assert_equal "private-secret-material", capture.content
    assert capture.content.frozen?
  end
end
