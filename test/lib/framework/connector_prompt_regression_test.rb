# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "support/connector_fake"

class ConnectorPromptRegressionTest < Minitest::Test
  class LocalTransport < Net::Connector::Transports::Pty
    def initialize(configuration, script)
      super(configuration)
      @script = script
    end

    def argv = [ RbConfig.ruby, "--disable-gems", "-e", @script ]
  end

  def test_radware_waits_for_the_complete_menu_prompt_before_reading_configuration
    configuration = Net::Connector::Configuration.new(host: "192.0.2.1", username: "test", login_timeout: 2, command_timeout: 2)
    transport = LocalTransport.new(configuration, <<~'RUBY')
      $stdout.sync = true
      $stdout.write(">>")
      sleep 0.05
      $stdout.write(" Alteon - Main#")
      abort unless $stdin.gets == "/cfg/dump\n"
      sleep 0.05
      $stdout.write("/cfg/dump\n/c/real/config\n>> Alteon - Configuration#")
      $stdin.read
    RUBY
    device = Algosec::Connector.build(:radware, configuration: configuration, transport: transport)

    result = device.running_config

    assert result.success?, result.error&.message
    assert_includes result.config, "/c/real/config"
  ensure
    device&.close
  end

  def test_radware_does_not_accept_an_unterminated_menu_title
    transport = ConnectorFake.new(">> Alteon Main", :timeout)
    device = Algosec::Connector.build(:radware, host: "192.0.2.1", transport: transport)
    result = device.running_config

    refute result.success?
    assert_empty transport.writes
    assert_nil result.config
  ensure
    device&.close
  end

  def test_fortinet_script_can_enter_edit_next_and_leave_configuration_contexts
    transport = ConnectorFake.new("FortiGate #", "FortiGate (policy) #", "FortiGate (0) #",
                                  "FortiGate (policy) #", "FortiGate #")
    device = Algosec::Connector.build(:fortinet, host: "192.0.2.1", transport: transport)
    commands = [ "config firewall policy", "edit 0", "next", "end" ]
    result = device.execute_script(commands)

    assert result.success?, result.error&.message
    assert_equal commands.map { |command| "#{command}\n" }, transport.writes
    assert_equal commands, result.steps.map { |step| step.command.text }
  ensure
    device&.close
  end

  def test_fortinet_does_not_accept_incomplete_context_or_arbitrary_output
    device = nil
    [ "FortiGate (policy)", "FortiGate (policy #", "some output #" ].each do |prompt|
      transport = ConnectorFake.new(prompt, :timeout)
      device = Algosec::Connector.build(:fortinet, host: "192.0.2.1", transport: transport)
      refute device.execute_command("show").success?, prompt
      assert_empty transport.writes
      device.close
    end
  ensure
    device&.close
  end
end
