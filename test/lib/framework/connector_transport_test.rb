# frozen_string_literal: true

require_relative "../../test_helper"

class ConnectorTransportTest < Minitest::Test
  Connector = Net::Connector

  # 对端仅是本地 Ruby 子进程；真实 PTY 验证分片、写入和进程回收，不连接网络。
  class LocalTransport < Connector::Transports::Pty
    attr_reader :channel

    def initialize(configuration, script)
      super(configuration)
      @script = script
    end

    def argv = [ RbConfig.ruby, "--disable-gems", "-e", @script ]
  end

  def test_fragmented_pager_preserves_output_and_reaps_the_child
    device, transport = local_device(<<~'RUBY')
      $stdout.sync = true
      $stdout.write("router#")
      abort unless $stdin.gets == "show\n"
      $stdout.write("first\n--Mo")
      sleep 0.02
      $stdout.write("re--")
      abort unless $stdin.read(1) == " "
      $stdout.write("\nlast\nrouter#")
      $stdin.read
    RUBY

    result = device.execute_command("show")
    assert result.success?, result.error&.message
    assert_equal "first\n\nlast\nrouter#", result.output
    channel = transport.channel
    pid = channel.pid
    device.close
    assert channel.closed?
    refute channel.alive?
    assert_raises(Errno::ECHILD) { Process.waitpid(pid, Process::WNOHANG) }
  ensure
    device&.close
  end

  def test_unmatched_output_limit_stops_the_script_and_closes_the_real_transport
    device, transport = local_device(<<~'RUBY', max_output_bytes: 1024)
      $stdout.sync = true
      $stdout.write("router#")
      abort unless $stdin.gets == "show\n"
      $stdout.write("x" * 16384)
      $stdin.read
    RUBY

    result = device.execute_script([ "show", "never" ])
    assert_instance_of Connector::OutputLimitExceeded, result.error
    assert_equal "show", result.error.command
    assert_operator result.error.output.bytesize, :<=, 4096
    assert_empty result.steps
    assert transport.closed?
    refute device.connected?
  ensure
    device&.close
  end

  def test_streaming_progress_does_not_restart_the_command_deadline
    device, transport = local_device(<<~'RUBY')
      $stdout.sync = true
      $stdout.write("router#")
      abort unless $stdin.gets == "show\n"
      loop do
        $stdout.write("progress\n")
        sleep 0.01
      end
    RUBY
    device.connect
    channel = transport.channel
    started = Expect.monotonic

    result = device.execute_command("show", timeout: 0.1)

    assert_instance_of Connector::CommandTimeout, result.error
    assert_operator Expect.monotonic - started, :<, 2
    assert_includes result.error.output, "progress"
    assert channel.closed?
    refute channel.alive?
  ensure
    device&.close
  end

  def test_business_collection_uses_real_pty_authentication_driver_and_parser
    script = <<~'RUBY'
      $stdout.sync = true
      $stdout.write("login:")
      abort unless $stdin.gets == "operator\n"
      $stdout.write("Password:")
      abort unless $stdin.gets == "secret\n"
      $stdout.write("fw#")
      abort unless $stdin.gets == "terminal length 0\n"
      $stdout.write("fw#")
      abort unless $stdin.gets == "show configuration running\n"
      $stdout.write("show configuration running\nrule id 7\n action permit\nexit\nfw#")
      abort unless $stdin.gets == "show service predefined\n"
      $stdout.write("show service predefined\nName Protocol Dst-Port/Type Src-Port/Code Timeout\nTotal configured: 1\nHTTPS TCP 443 Any -\nfw#")
      $stdin.read
    RUBY
    configuration = Connector::Configuration.new(host: "192.0.2.1", username: "operator", password: "secret",
      login_timeout: 2, command_timeout: 2)
    transport = LocalTransport.new(configuration, script)

    channel = pid = nil
    capture = Algosec::DeviceSession.open(:hillstone, device_id: 19, configuration: configuration, transport: transport) do |session|
      channel = transport.channel
      pid = channel.pid
      session.collect
    end
    result = Algosec::Config::Parser.perform(capture.content, vendor: :hillstone, device_id: 19, builtin_services: capture.builtin_services)

    assert result.complete?, result.diagnostics.inspect
    assert_equal "7", result.rules.sole.rule_id
    assert_equal "HTTPS", capture.builtin_services.values.sole.name
    assert_equal 3, capture.evidence.size
    assert channel.closed?
    refute channel.alive?
    assert_raises(Errno::ECHILD) { Process.waitpid(pid, Process::WNOHANG) }
  ensure
    transport&.close
  end

  private

  def local_device(script, **options)
    configuration = Connector::Configuration.new(host: "192.0.2.1", username: "test",
                                                 login_timeout: 2, command_timeout: 2, **options)
    transport = LocalTransport.new(configuration, script)
    [ Algosec::Connector.build(:cisco_ios, configuration: configuration, transport: transport), transport ]
  end
end
