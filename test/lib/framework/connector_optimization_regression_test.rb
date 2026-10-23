# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "support/connector_fake"
require_relative "../../support/method_replacement"
require "rake"

class ConnectorOptimizationRegressionTest < Minitest::Test
  include MethodReplacement

  def test_hillstone_only_tolerates_explicit_existing_entity_responses
    [ "This entity already exists.", "This entity is already exists.",
      "This entity already exist", "This entity is already exist" ].each do |message|
      transport = ConnectorFake.new("fw#", "Error: #{message}\r\nfw#", "fw#")
      device = Algosec::Connector.build(:hillstone, host: "192.0.2.1", transport: transport)

      result = device.execute_script([ 'address "shared"', "exit" ])

      assert result.success?, message
      assert_equal [ "address \"shared\"\n", "exit\n" ], transport.writes
      assert_equal 2, result.steps.size
    ensure
      device&.close
    end
  end

  def test_hillstone_stops_on_other_already_states_before_the_next_command
    assert_hillstone_error("This entity is already in use.")
  end

  def test_hillstone_does_not_ignore_an_error_with_an_existing_entity_prefix
    assert_hillstone_error("This entity already exists but cannot be modified.")
  end

  def test_hillstone_does_not_complete_an_error_from_a_later_output_line
    assert_hillstone_error("This entity\nalready exists.")
  end

  def test_hillstone_stops_when_an_existing_entity_response_is_followed_by_another_error
    assert_hillstone_error("This entity already exists.\nError: Permission denied")
  end

  private

  def assert_hillstone_error(message)
    transport = ConnectorFake.new("fw#", "Error: #{message}\r\nfw#", "fw#")
    device = Algosec::Connector.build(:hillstone, host: "192.0.2.1", transport: transport)

    result = device.execute_script([ 'address "shared"', "ip 192.0.2.1/32" ])

    assert result.failure?, message
    assert_instance_of Net::Connector::DeviceError, result.error
    assert_empty result.steps
    assert_equal [ "address \"shared\"\n" ], transport.writes
    assert_equal 1, transport.closes
    refute device.connected?
  ensure
    device&.close
  end
end
