# frozen_string_literal: true

require_relative "../../test_helper"
require "tmpdir"

class OfflineCheckTest < Minitest::Test
  def test_each_zone_result_keeps_its_own_command_artifact
    with_verifier do |verifier, _config_path, _plan_path|
      results = verifier.perform.fetch(:cases).sole.fetch(:results)

      assert_equal 2, results.size
      assert_equal [ :new, :new ], results.map { |result| result.fetch(:type) }
      assert_equal 2, results.map { |result| result.fetch(:commands) }.uniq.size
      results.each do |result|
        commands = File.read(result.fetch(:commands))
        assert_includes commands, "src-zone \"#{result.fetch(:from_zone)}\""
        assert_includes commands, 'dst-zone "outside"'
      end
    end
  end

  def test_plan_changed_after_initialization_cannot_supply_the_report_digest
    with_verifier do |verifier, _config_path, plan_path|
      changed_plan = JSON.parse(File.read(plan_path))
      changed_plan.fetch("cases").sole.fetch("request")["services"] = [ "tcp/80" ]
      File.write(plan_path, JSON.generate(changed_plan))

      error = assert_raises(Algosec::OfflineCheck::Error) { verifier.perform }

      assert_match(/验证输入在运行期间发生变化/, error.message)
      refute File.exist?(File.join(verifier.output_path, "report.json"))
    end
  end

  def test_configuration_changed_after_read_cannot_supply_the_report_digest
    with_verifier do |verifier, config_path, _plan_path|
      original_read = File.method(:binread)
      File.define_singleton_method(:binread) do |path, *arguments, **options|
        content = original_read.call(path, *arguments, **options)
        File.write(config_path, content + "hostname changed\n") if path == config_path
        content
      end

      error = assert_raises(Algosec::OfflineCheck::Error) { verifier.perform }

      assert_match(/验证输入在运行期间发生变化/, error.message)
      refute File.exist?(File.join(verifier.output_path, "report.json"))
    ensure
      File.define_singleton_method(:binread, original_read) if original_read
    end
  end

  def test_report_checksums_match_all_parsed_input_bytes
    services = { "services" => { "WEB" => [ { "protocol" => "tcp", "destination_port" => "443" } ] } }
    with_verifier(builtin_services: services) do |verifier, config_path, plan_path, services_path|
      report = verifier.perform

      expected = [ config_path, plan_path, services_path ].map do |path|
        { path: path, sha256: Digest::SHA256.hexdigest(File.binread(path)) }
      end
      assert_equal expected, report.fetch(:inputs)
      assert_equal({ provided: true, imported: 1 }, report.fetch(:builtin_services))
      report.fetch(:inputs)[1][:sha256].replace("0" * 64)
      assert_equal expected, verifier.perform.fetch(:inputs)
    end
  end

  def test_fortinet_uses_the_selected_vdom_for_coverage_and_generated_commands
    with_fortinet_verifier(settings: { "vdom" => "tenant" }) do |verifier|
      report = verifier.perform
      result = report.fetch(:cases).sole.fetch(:results).sole

      assert report.dig(:configuration, :complete)
      assert_equal :new, result.fetch(:type)
      assert_equal :readback_unavailable, result.fetch(:verification)
      assert File.read(result.fetch(:commands)).start_with?("config vdom\nedit \"tenant\"\n")
    end
  end

  def test_fortinet_defaults_to_root_when_no_vdom_is_selected
    with_fortinet_verifier(settings: {}) do |verifier|
      result = verifier.perform.fetch(:cases).sole.fetch(:results).sole

      assert_equal :ignore, result.fetch(:type)
      assert_equal :existing_coverage_verified, result.fetch(:verification)
      assert_empty File.read(result.fetch(:commands))
    end
  end

  def test_joint_coverage_verifies_without_a_single_selected_rule
    content = %w[10.0.0.0/25 10.0.0.128/25].each_with_index.map do |source, index|
      pan_rule("allow-#{index}", source: source)
    end.join
    with_coverage_verifier(content: content, vendor: :palo_alto) do |verifier|
      report = verifier.perform
      result = report.fetch(:cases).sole.fetch(:results).sole

      assert_equal :ignore, result.fetch(:type)
      assert_nil result.fetch(:rule_id)
      assert_equal :existing_coverage_verified, result.fetch(:verification)
      assert_empty File.read(result.fetch(:commands))
      assert File.file?(report.fetch(:report))
    end
  end

  def test_partial_coverage_readback_checks_only_the_generated_gap
    content = hillstone_rule(1, source: "10.0.0.0/25")
    with_coverage_verifier(content: content, vendor: :hillstone) do |verifier|
      report = verifier.perform
      result = report.fetch(:cases).sole.fetch(:results).sole

      assert_equal :new, result.fetch(:type)
      assert_equal :exact_ranges_after_readback, result.fetch(:verification)
      commands = File.read(result.fetch(:commands))
      assert_includes commands, "10.0.0.128/25"
      refute_includes commands, "10.0.0.0/24"
      assert File.file?(report.fetch(:report))
    end
  end

  def test_crossed_pairs_keep_the_two_generated_gaps_separate
    content = hillstone_rule(1, source: "10.0.0.1/32", destination: "192.0.2.1") +
      hillstone_rule(2, source: "10.0.0.2/32", destination: "192.0.2.2")
    request = { sources: [ "10.0.0.1-10.0.0.2" ], destinations: [ "192.0.2.1-192.0.2.2" ], services: [ "tcp/443" ] }
    with_coverage_verifier(content: content, vendor: :hillstone, request: request) do |verifier|
      results = verifier.perform.fetch(:cases).sole.fetch(:results)

      assert_equal [ :new, :new ], results.map { |result| result.fetch(:type) }
      assert_equal [ :exact_ranges_after_readback ] * 2, results.map { |result| result.fetch(:verification) }
      assert_equal 2, results.map { |result| result.fetch(:commands) }.uniq.size
      commands = results.map { |result| File.read(result.fetch(:commands)) }
      assert_equal [ 1, 1 ], commands.map { |text| text.lines.count { |line| line == "rule top\n" } }
      assert_includes commands.first, 'src-addr "Host_10.0.0.2"'
      assert_includes commands.first, 'dst-addr "Host_192.0.2.1"'
      assert_includes commands.last, 'src-addr "Host_10.0.0.1"'
      assert_includes commands.last, 'dst-addr "Host_192.0.2.2"'
    end
  end

  def test_joint_coverage_is_rechecked_against_current_order_and_remaining_traffic
    content = %w[10.0.0.0/25 10.0.0.128/25].each_with_index.map do |source, index|
      pan_rule("allow-#{index}", source: source)
    end.join
    parse = ->(text) { Algosec::Config::Parser.perform(text, vendor: :palo_alto, device_id: 1) }
    original = parse.call(content)
    at = Time.utc(2026, 9, 30)
    snapshot = Algosec::Policy::Snapshot.from_config(original)
    maps = { sources: { "10.0.0.0/24" => {} }, destinations: { "192.0.2.1" => {} }, services: { "tcp/443" => {} } }
    result = Algosec::Policy::RuleMatcher.new(snapshot, at: at).match({ **maps,
      device_id: 1, device_name: "fw", vendor: :palo_alto, from_zone: "inside", to_zone: "outside", hit: :source })
    assert_equal :ignore, result.type
    assert_nil result.rule

    [ pan_rule("half", source: "10.0.0.0/25"),
      pan_rule("deny-first", source: "10.0.0.1", action: "deny") + content ].each do |changed|
      readback = Algosec::OfflineCheck.const_get(:Readback).new(parse.call(changed), enabled: true, prefix: nil, at: at)
      error = assert_raises(Algosec::OfflineCheck::Error) { readback.perform(result, "") }
      assert_includes error.message, "已有规则不能覆盖请求"
    end
  end

  def test_query_after_split_keeps_its_own_commands
    content = "zone inside\nexit\nzone guests\nexit\nzone outside\nexit\n" +
      hillstone_rule(1, source: "10.0.0.1/32", destination: "192.0.2.1") +
      hillstone_rule(2, source: "10.0.0.2/32", destination: "192.0.2.2")
    request = { sources: [ "10.0.0.1-10.0.0.2", "10.0.1.3" ],
      destinations: [ "192.0.2.1-192.0.2.2" ], services: [ "tcp/443" ] }
    plan = { cases: [ { name: "split and next zone", request: request } ] }
    with_verifier(content: content, plan_overrides: plan, readback: true) do |verifier|
      results = verifier.perform.fetch(:cases).sole.fetch(:results)

      assert_equal 3, results.size
      assert_equal [ :exact_ranges_after_readback ] * 3, results.map { |result| result.fetch(:verification) }
      commands = results.map { |result| File.read(result.fetch(:commands)) }
      assert_equal 3, commands.uniq.size
      assert_equal "guests", results.last.fetch(:from_zone)
      assert_includes commands.last, 'src-addr "Host_10.0.1.3"'
      commands.first(2).each { |text| refute_includes text, 'src-addr "Host_10.0.1.3"' }
    end
  end

  def test_settings_must_be_an_object_before_verification_starts
    [ nil, [], "tenant", false ].each do |settings|
      error = assert_raises(Algosec::OfflineCheck::Error) do
        with_verifier(plan_overrides: { settings: settings }) { flunk "invalid settings were accepted" }
      end
      assert_includes error.message, "settings"
    end
  end

  def test_invalid_builtin_terms_keep_the_offline_error_contract
    services = { "services" => { "WEB" => [ { "protocol" => "tcp", "destination_prt" => "443" } ] } }
    with_verifier(builtin_services: services) do |verifier|
      error = assert_raises(Algosec::OfflineCheck::Error) { verifier.perform }

      assert_includes error.message, "WEB"
      assert_includes error.message, "destination_prt"
      refute File.exist?(File.join(verifier.output_path, "report.json"))
    end
  end

  private

  def pan_rule(name, source:, destination: "192.0.2.1", action: "allow")
    { from: "inside", to: "outside", source: source, destination: destination,
      service: "any", application: "any", action: action }.map do |field, value|
      "set rulebase security rules #{name} #{field} #{value}\n"
    end.join
  end

  def hillstone_rule(id, source:, destination: "192.0.2.1")
    <<~CONFIG
      address source-#{id}
       ip #{source}
      exit
      address destination-#{id}
       ip #{destination}/32
      exit
      rule id #{id}
       src-zone inside
       dst-zone outside
       src-addr source-#{id}
       dst-addr destination-#{id}
       service-rule tcp dst-port 443
       action permit
      exit
    CONFIG
  end

  def with_coverage_verifier(content:, vendor:, request: nil)
    network = if vendor == :palo_alto
      <<~CONFIG
        set network interface ethernet ethernet1/1 layer3 ip 10.0.0.254/24
        set network interface ethernet ethernet1/2 layer3 ip 192.0.2.254/24
        set network virtual-router default interface [ ethernet1/1 ethernet1/2 ]
        set zone inside network layer3 ethernet1/1
        set zone outside network layer3 ethernet1/2
      CONFIG
    else
      "zone inside\nexit\nzone outside\nexit\n"
    end
    common = { device_id: 1, device_name: "fw", vendor: vendor.to_s, nat_mode: 0, address_type: "main" }
    plan = { vendor: vendor.to_s,
      networks: [ common.merge(zone: "inside", protected: true, address: "10.0.0.0/24"),
                  common.merge(zone: "outside", protected: false, address: "0.0.0.0/0") ],
      cases: [ { name: "range coverage", request: request || {
        sources: [ "10.0.0.0/24" ], destinations: [ "192.0.2.1" ], services: [ "tcp/443" ]
      } } ] }
    with_verifier(content: network + content, plan_overrides: plan, readback: true) { |verifier| yield verifier }
  end

  def with_fortinet_verifier(settings:)
    root = File.read(TestPaths.root.join("test/fixtures/config/fortinet.cfg"))
    tenant = root.gsub('set vdom "root"', 'set vdom "tenant"').sub("set action accept", "set action deny")
    content = "config vdom\nedit root\n#{root}next\nedit tenant\n#{tenant}next\nend\n"
    common = { device_id: 1, device_name: "fw", vendor: "fortinet", nat_mode: 0, address_type: "main" }
    plan = {
      vendor: "fortinet", settings: settings,
      networks: [ common.merge(zone: "inside", protected: true, address: "10.0.0.0/24"),
                  common.merge(zone: "outside", protected: false, address: "0.0.0.0/0") ],
      cases: [ { name: "selected VDOM", request: {
        sources: [ "10.0.0.10" ], destinations: [ "198.51.100.20" ], services: [ "tcp/443" ]
      } } ]
    }
    with_verifier(content: content, plan_overrides: plan, readback: true) { |verifier| yield verifier }
  end

  def with_verifier(builtin_services: nil, content: nil, plan_overrides: {}, readback: false)
    Dir.mktmpdir("algosec-offline-check") do |directory|
      config_path = File.join(directory, "config.txt")
      plan_path = File.join(directory, "plan.json")
      content ||= <<~CONFIG
        zone inside
        exit
        zone guests
        exit
        zone outside
        exit
      CONFIG
      File.write(config_path, content)
      common = { device_id: 1, device_name: "fw", vendor: "hillstone", nat_mode: 0, address_type: "main" }
      plan = {
        device_id: 1, vendor: "hillstone", reference_time: "2026-09-30T00:00:00Z",
        networks: [
          common.merge(zone: "inside", protected: true, address: "10.0.0.0/24"),
          common.merge(zone: "guests", protected: true, address: "10.0.1.0/24"),
          common.merge(zone: "outside", protected: false, address: "0.0.0.0/0")
        ],
        cases: [ { name: "two source zones", request: {
          sources: [ "10.0.0.1", "10.0.1.1" ], destinations: [ "192.0.2.1" ], services: [ "tcp/443" ]
        } } ]
      }
      File.write(plan_path, JSON.generate(plan.merge(plan_overrides)))
      if builtin_services
        services_path = File.join(directory, "services.json")
        File.write(services_path, JSON.generate(builtin_services))
      end
      verifier = Algosec::OfflineCheck::Firewall.new(config_path: config_path, plan_path: plan_path,
        output_path: File.join(directory, "output"), readback: readback, builtin_services_path: services_path)
      yield verifier, config_path, plan_path, services_path
    end
  end
end
