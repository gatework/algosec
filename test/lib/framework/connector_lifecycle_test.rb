# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "support/connector_fake"

class ConnectorLifecycleTest < Minitest::Test
  def test_created_rule_remains_in_partial_result_when_follow_up_query_times_out
    transport = ConnectorFake.new("<H3C>", "rule pass\n[H3C-policy]", :timeout)
    device = Algosec::Connector.build(:h3c, host: "192.0.2.1", transport: transport)

    result = device.execute_script([ "rule pass", "rule XXX append source-ip 192.0.2.2 32" ])

    assert result.failure?
    assert_equal [ "rule pass" ], result.steps.map { |step| step.command.text }
    assert_equal "dis this", result.error.command
    assert_equal [ "rule pass\n", "dis this\n" ], transport.writes
    assert_equal 1, transport.opens
    assert_equal 1, transport.closes
    refute device.connected?
  ensure
    device&.close
  end

  def test_created_rule_remains_in_partial_result_when_returned_rule_id_is_missing
    transport = ConnectorFake.new("<H3C>", "rule pass\n[H3C-policy]", "dis this\n#\n[H3C-policy]")
    device = Algosec::Connector.build(:h3c, host: "192.0.2.1", transport: transport)

    result = device.execute_script([ "rule pass", "rule XXX append source-ip 192.0.2.2 32" ])

    assert result.failure?
    assert_equal [ "rule pass" ], result.steps.map { |step| step.command.text }
    assert_instance_of Net::Connector::ScriptError, result.error
    assert_equal "rule pass", result.error.command
    assert_equal [ "rule pass\n", "dis this\n" ], transport.writes
    assert_equal 1, transport.opens
    assert_equal 1, transport.closes
  ensure
    device&.close
  end
end
