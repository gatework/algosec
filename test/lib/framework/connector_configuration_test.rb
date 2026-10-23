# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "support/connector_fake"

class ConnectorConfigurationTest < Minitest::Test
  def test_running_config_excludes_terminal_setup_but_preserves_all_steps
    transport = ConnectorFake.new("fw#", "terminal length 0\nfw#", "zone inside\nexit\nfw#")
    device = Algosec::Connector.build(:hillstone, host: "192.0.2.1", transport: transport)
    result = device.running_config
    assert result.success?, result.error&.message
    refute_includes result.config, "terminal length"
    assert_includes result.output, "terminal length"
    assert_equal [ "terminal length 0", "show configuration running" ], result.steps.map { |step| step.command.text }
  ensure
    device&.close
  end

  def pan_transport(content, before_diff: "", after_diff: "")
    ConnectorFake.new("admin@fw>", "admin@fw>", "admin@fw>",
                      "show config diff\r\n#{before_diff}\r\nadmin@fw>",
                      "Entering configuration mode\r\n[edit]\r\nadmin@fw#",
                      "show\r\n#{content}\r\n[edit]\r\nadmin@fw#",
                      "admin@fw>", "show config diff\r\n#{after_diff}\r\nadmin@fw>")
  end

  def test_palo_alto_collects_set_directly_and_checks_candidate_before_and_after
    content = "set shared address web ip-netmask 192.0.2.1/32"
    device = Algosec::Connector.build(:palo_alto, host: "192.0.2.1", transport: pan_transport(content))
    result = device.running_config
    assert result.success?, result.error&.message
    assert_equal content, result.config
    assert_equal [ "set cli pager off", "set cli config-output-format set", "show config diff",
                   "configure", "show", "exit", "show config diff" ], result.steps.map { |step| step.command.text }
    parsed = Algosec::Config::Parser.perform(result.value!, vendor: :palo_alto, device_id: 1)
    assert parsed.complete?, parsed.diagnostics.inspect
    assert_equal "web", parsed.elements(Algosec::Elements::AddressObject).sole.name
  ensure
    device&.close
  end

  def test_palo_alto_preserves_multiline_quoted_values
    content = "set shared certificate example certificate \"-----BEGIN CERTIFICATE-----\nexample\n-----END CERTIFICATE-----\""
    device = Algosec::Connector.build(:palo_alto, host: "192.0.2.1", transport: pan_transport(content))
    assert_equal content, device.running_config.value!
  ensure
    device&.close
  end

  def test_business_capture_preserves_configuration_values_ending_with_known_prompts
    %w[admin@fw> prefixadmin@fw#].each do |description|
      content = "set shared address web description #{description}"
      transport = pan_transport(content)
      capture = Algosec::DeviceSession.open(:palo_alto, host: "192.0.2.1", transport: transport, &:read_config)
      assert_equal content, capture.content
    end
  end

  def test_palo_alto_rejects_xml_braces_and_empty_configuration
    device = nil
    [ "<config><shared/></config>", "deviceconfig { hostname fw; }", 'set shared certificate name "unterminated', "" ].each do |content|
      device = Algosec::Connector.build(:palo_alto, host: "192.0.2.1", transport: pan_transport(content))
      result = device.running_config
      assert result.failure?
      assert_equal :unsupported_configuration_format, result.error.code
      assert_nil result.config
      device.close
    end
  ensure
    device&.close
  end

  def test_palo_alto_refuses_preexisting_and_concurrent_uncommitted_changes
    device = nil
    [ :before_diff, :after_diff ].each do |phase|
      transport = pan_transport("set shared address web ip-netmask 192.0.2.1/32", **{ phase => "+ candidate-only" })
      device = Algosec::Connector.build(:palo_alto, host: "192.0.2.1", transport: transport)
      result = device.running_config
      assert result.failure?
      assert_equal :uncommitted_configuration, result.error.code
      assert_nil result.config
      refute_includes result.error.message, "candidate-only"
      refute_includes transport.writes, "configure\n" if phase == :before_diff
      device.close
    end
  ensure
    device&.close
  end

  def test_srx_reads_committed_configuration_only_from_operational_mode
    content = "set security zones security-zone inside"
    transport = ConnectorFake.new("operator@fw>", "show config | display set | no-more\n#{content}\noperator@fw>")
    capture = Algosec::DeviceSession.open(:srx, host: "192.0.2.1", transport: transport, &:read_config)
    assert_equal "#{content}\n", capture.content

    candidate = ConnectorFake.new("operator@fw#", "#{content}\noperator@fw#")
    error = assert_raises(Net::Connector::DeviceError) do
      Algosec::DeviceSession.open(:srx, host: "192.0.2.1", transport: candidate, &:read_config)
    end
    assert_equal :uncommitted_configuration, error.code
    assert_empty candidate.writes
    assert_equal 1, candidate.closes
  end
end
