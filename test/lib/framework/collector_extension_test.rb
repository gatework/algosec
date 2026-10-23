# frozen_string_literal: true

require "test_helper"
require "open3"
require "json"

class CollectorExtensionTest < Minitest::Test
  def test_registered_collector_adds_auxiliary_data_using_the_borrowed_session
    result = collect_example(with_collector: true)

    assert_equal "host web 192.0.2.1\nauxiliary-data\n", result.fetch("content")
    assert_equal [ "show configuration\n", "show auxiliary\n" ], result.fetch("writes")
    assert_equal [ "show configuration", "show auxiliary" ], result.fetch("commands")
    assert_equal 1, result.fetch("opens")
    assert_equal 1, result.fetch("closes")
  end

  def test_vendor_without_collector_uses_configuration_only
    result = collect_example(with_collector: false)

    assert_equal "host web 192.0.2.1\n", result.fetch("content")
    assert_equal [ "show configuration\n" ], result.fetch("writes")
    assert_equal [ "show configuration" ], result.fetch("commands")
    assert_equal 1, result.fetch("opens")
    assert_equal 1, result.fetch("closes")
  end

  private

  # Isolate the extension registry while retaining real Connector/Driver behavior.
  def collect_example(with_collector:)
    script = <<~'RUBY'
      require "algosec"
      require "json"
      require_relative "test/lib/framework/support/connector_fake"
      components = %i[elements connector]
      components << :collector if ARGV.fetch(0) == "true"
      Algosec::Vendors.register :example, namespace: "Example", components: components,
        directory: "test/fixtures/vendors/example"
      Algosec::Vendors.validate!
      transport = ConnectorFake.new("example#", "show configuration\nhost web 192.0.2.1\nexample#",
        "show auxiliary\nauxiliary-data\nexample#")
      capture = Algosec::DeviceSession.open(:example, host: "192.0.2.1", transport: transport) { |session| session.collect }
      puts JSON.generate(content: capture.content, commands: capture.evidence.map { |item| item.fetch(:command) },
        writes: transport.writes, opens: transport.opens, closes: transport.closes)
    RUBY
    output, error, status = Open3.capture3(RbConfig.ruby, "-Ilib", "-e", script, with_collector.to_s, chdir: TestPaths.root.to_s)
    assert status.success?, error
    JSON.parse(output)
  end
end
