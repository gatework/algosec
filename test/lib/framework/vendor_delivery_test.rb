# frozen_string_literal: true

require "test_helper"
require_relative "support/policy_factory"
require_relative "support/connector_fake"

class VendorDeliveryTest < Minitest::Test
  include PolicyFactory

  def test_asa_and_huawei_scripts_enter_and_leave_configuration_mode
    { asa: [ "configure terminal", "end" ], huawei: [ "system-view", "return" ],
      srx: [ "configure", "exit" ] }.each do |vendor, (enter, leave)|
      result = P::RuleMatcher.new(snapshot(vendor)).match(group(vendor))
      script = result.definition.generator.new(snapshot: result.snapshot).render([ result ]).text
      assert_equal enter, script.lines.first.chomp, vendor.to_s
      assert_equal leave, script.lines.last.chomp, vendor.to_s
      if vendor == :asa
        plan = P::Planner.new(P::Report.new(results: [ result ])).plans.sole
        assert plan.generated?
        refute plan.ready?
        assert_raises(P::Error) { plan.script }
      end
    end
  end

  def test_application_firewall_profiles_save_without_reimplementing_transport
    { asa: [ "fw#", "write memory" ], neteye: [ "fw#", "save config" ], netscreen: [ "fw->", "save" ] }.each do |vendor, (prompt, command)|
      # Neteye 的批次准备需要先确认 configure mode 提权。
      transport = ConnectorFake.new(prompt, *(vendor == :neteye ? [ prompt ] : []), "saved\n#{prompt}")
      connector = Algosec::Connector.build(vendor, host: "192.0.2.1", transport: transport)
      result = connector.save_config
      assert result.success?, "#{vendor}: #{result.error&.code}"
      assert_equal command, result.steps.last.command.text
      assert_equal "#{command}\n", transport.writes.last
    ensure
      connector&.close
    end
  end

  def test_missing_parser_or_persistence_never_advertises_deployment
    %i[cisco_ios cisco_n9k radware topsec palo_alto srx generic neteye netscreen huawei].each do |vendor|
      refute Algosec::Connector.capabilities(vendor).fetch(:deploy), vendor.to_s
    end
  end

  def test_saving_requires_the_vendor_completion_line_from_the_actual_save_command
    { hillstone: [ "fw#", "Saving configuration is finished" ],
      h3c: [ "<fw>", "Saved the current configuration to mainboard device successfully." ],
      asa: [ "fw#", "[OK]" ], fortinet: [ "fw #", "config saved." ] }.each do |vendor, (prompt, success)|
      [ prompt, "Saving in progress\n#{prompt}", "Failed to save the configuration.\n#{success}\n#{prompt}",
        "Failed to save\r\e[2K#{success}\n#{prompt}", "#{success}\n#{prompt}" ].each_with_index do |output, index|
        transport = ConnectorFake.new(prompt, output)
        connector = Algosec::Connector.build(vendor, host: "192.0.2.1", transport: transport)
        result = connector.save_config
        assert_equal index == 4, Algosec::Connector.persistence_confirmed?(vendor, result), "#{vendor}: #{output.inspect}"
        assert Algosec::Connector.capabilities(vendor).fetch(:deploy)
      ensure
        connector&.close
      end
    end
    wrong_step = Net::Connector::Command::Result.new(command: Net::Connector::Command.new("show configuration running"),
      output: "Saving configuration is finished\nfw#", prompt: "fw#", duration: 0.01)
    refute Algosec::Connector.persistence_confirmed?(:hillstone, Net::Connector::Result.new(steps: [ wrong_step ]))
  end

  def test_fortinet_ambiguous_no_change_response_is_not_save_confirmation
    transport = ConnectorFake.new("fw #", "no config to be saved.\nfw #")
    connector = Algosec::Connector.build(:fortinet, host: "192.0.2.1", transport: transport)
    refute Algosec::Connector.persistence_confirmed?(:fortinet, connector.save_config)
  ensure
    connector&.close
  end

  def test_logging_failure_still_requires_complete_positive_save_evidence
    failures = [ Net::Connector::LogError.new("log failed"), Net::Connector::DeviceError.new("device rejected"),
      Net::Connector::ConnectionClosed.new("connection lost") ]
    outputs = [ "Saving configuration is finished\nfw#", "Failed to save\nSaving configuration is finished\nfw#", "accepted\nfw#" ]
    failures.product(outputs).each do |error, output|
      step = Net::Connector::Command::Result.new(command: Net::Connector::Command.new("save all"), output: output, prompt: "fw#", duration: 0.01)
      result = Net::Connector::Result.new(steps: [ step ], error: error)
      expected = error.is_a?(Net::Connector::LogError) && output == outputs.first
      assert_equal expected, Algosec::Connector.persistence_confirmed?(:hillstone, result)
    end
    refute Algosec::Connector.persistence_confirmed?(:hillstone, Net::Connector::Result.new(error: failures.first))
  end
end
