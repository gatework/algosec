# frozen_string_literal: true

require "minitest/autorun"
require "algosec"
require "algosec/connector"
require_relative "framework/support/connector_fake"

class AlgosecConnectorTest < Minitest::Test
  Connector = Net::Connector

  def test_registered_vendors_delegate_device_operations_to_net_connector
    Algosec::Vendors.names(:connector).each do |vendor|
      device = Algosec::Connector.build(vendor, host: "192.0.2.1")
      upstream_vendor = vendor == :cisco_n9k ? :cisco_nxos : vendor
      upstream = Connector.vendors.include?(upstream_vendor) ? Connector.vendor_class(upstream_vendor) : Connector::Base
      assert_kind_of upstream, device
      assert_equal Connector::Base, device.method(:execute_script).owner
      assert_equal Connector::Base, device.method(:connect).owner
      assert_instance_of Connector::Configuration, device.configuration
    end
    refute Algosec::Connector.const_defined?(:Session, false)
    refute Algosec::Connector.const_defined?(:Transports, false)
  end

  def test_connector_profiles_use_the_short_scoped_name
    connector_class = Class.new(Connector::Base) do
      profile do
        commands { running_config "show running" }
        prompts { login(/fw#\z/); command(/fw#\z/) }
      end
    end

    assert_instance_of Connector::Profile, connector_class.profile
    assert_equal [ "show running" ], connector_class.profile.config_commands
    refute Connector.const_defined?(:DeviceProfile, false)
  end

  def test_connector_log_and_terminal_output_have_explicit_roles
    assert Connector.const_defined?(:Log, false)
    assert Connector::Terminal.const_defined?(:Renderer, false)
    refute Connector.const_defined?(:SessionLog, false)
    refute Connector.const_defined?(:Transcript, false)
    assert_equal "show version\nready", Connector::Terminal::Text.render("show versXXX\b\b\bion\r\nready")
  end

  def test_every_registered_device_authenticates_and_releases_its_session
    prompts = { asa: "fw#", srx: "operator@fw>", netscreen: "fw->", fortinet: "fw #",
      h3c: "<fw>", huawei: "<fw>", hillstone: "fw#", topsec: "fw#", neteye: "fw#",
      cisco_ios: "fw#", cisco_n9k: "fw#", palo_alto: "operator@fw>", radware: ">> Alteon - Main#" }
    assert_equal Algosec::Vendors.names(:connector).sort, prompts.keys.sort
    prompts.each do |vendor, prompt|
      transport = ConnectorFake.new("login:", "Password:", prompt)
      Algosec::Connector.open(vendor, host: "192.0.2.1", username: "operator", password: "secret", transport: transport) do |device|
        assert device.connected?, vendor.to_s
      end
      assert_equal [ "operator\n", "secret\n" ], transport.writes, vendor.to_s
      assert_equal 1, transport.opens, vendor.to_s
      assert_equal 1, transport.closes, vendor.to_s
    end
  end
end
