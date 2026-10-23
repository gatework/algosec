# frozen_string_literal: true

require_relative "../../test_helper"
require "algosec/dns_resolver"

class ConfigComparisonTest < Minitest::Test
  E = Algosec::Elements

  def content
    <<~CONFIG
      address leaf
        ip 10.0.0.1/32
      exit
      address outer
        member leaf
      exit
      service web
        tcp dst-port 443
      exit
      servgroup web-group
        service web
      exit
      rule id 1
        action permit
        src-addr outer
        dst-ip 192.0.2.1/32
        service web-group
      exit
    CONFIG
  end

  def parse(text, **options)
    Algosec::Config::Parser.perform(text, vendor: :hillstone, device_id: 1, **options)
  end

  def compare(before, after)
    Algosec::Config::Comparison.new(before: before, after: after).perform
  end

  def test_nested_address_and_service_definitions_change_independently
    before = parse(content)
    [ content.sub("10.0.0.1/32", "10.0.0.2/32"), content.sub("dst-port 443", "dst-port 8443") ].each do |text|
      after = parse(text)
      report = compare(before, after)
      assert report[:complete]
      assert_equal({ "modified" => 1 }, report[:summary])
      assert_equal before.rules.sole.config, after.rules.sole.config
      assert_equal report, compare(before, after)
    end
  end

  def test_missing_references_remain_visible_and_incomplete
    before = parse(content)
    after = parse(content.sub("member leaf", "member missing"))
    report = compare(before, after)
    refute report[:complete]
    missing = report[:changes].sole[:after][:objects].find { |item| item[:name] == "outer" }
    assert_equal({ "missing" => nil }, missing[:references])
    refute_empty report[:changes]
  end

  def test_unrelated_objects_and_dns_answers_are_not_rule_definition_changes
    before = parse(content.sub("ip 10.0.0.1/32", "host example.test"))
    resolver = Algosec::DnsResolver.new(device_id: 1, servers: [ "192.0.2.53" ], transport: ->(*) { [ [ "192.0.2.88" ], 60 ] })
    after = parse(content.sub("ip 10.0.0.1/32", "host example.test") + "address unused\n ip 10.1.0.1/32\nexit\n", dns_resolver: resolver)
    assert_empty compare(before, after)[:changes]
  end

  def test_builtin_service_changes_include_full_source_port_definitions
    text = "rule id 1\n action permit\n service WEB\nexit\n"
    make = ->(source_port) {
      Algosec::Elements::ServiceObject.new(name: "WEB", vendor: :hillstone, device_id: 1,
        protocol: "tcp", source_port: source_port, destination_port: "443")
    }
    before = parse(text, builtin_services: { "WEB" => make.call("0-65535") })
    after = parse(text, builtin_services: { "WEB" => make.call("1024-65535") })
    report = compare(before, after)
    assert_equal({ "modified" => 1 }, report[:summary])
    service = report[:changes].sole[:after][:objects].find { |item| item[:name] == "WEB" }
    assert_equal "1024-65535", service[:terms].sole[:source_port]
  end

  def test_execution_order_changes_are_reported_even_with_identical_rule_text
    first = "rule id 1\n action permit\nexit\n"
    second = "rule id 2\n action deny\nexit\n"
    report = compare(parse(first + second), parse(second + first))
    assert_equal({ "modified" => 2 }, report[:summary])
    assert report[:changes].all? { |row| row[:before][:configuration] == row[:after][:configuration] }
  end

  def test_schedule_time_zone_is_part_of_the_declared_behavior
    text = <<~CONFIG + File.read(TestPaths.root.join("test/fixtures/config/fortinet.cfg")).sub('set schedule "always"', 'set schedule "office"')
      config firewall schedule onetime
        edit office
          set start 09:00 2030/01/01
          set end 10:00 2030/01/01
        next
      end
    CONFIG
    before, after = [ "UTC", "Asia/Shanghai" ].map do |zone|
      Algosec::Config::Parser.perform(text, vendor: :fortinet, device_id: 1, time_zone: zone)
    end
    assert_equal({ "modified" => 1 }, compare(before, after)[:summary])
  end

  def test_shared_reference_paths_emit_each_dependency_once
    branches = "address left\n member leaf\nexit\naddress right\n member leaf\nexit\n"
    text = content.sub("address outer\n  member leaf", branches + "address outer\n  member left\n  member right")
    report = compare(parse(text), parse(text.sub("10.0.0.1/32", "10.0.0.2/32")))
    assert report[:complete]
    objects = report[:changes].sole[:after][:objects]
    assert_equal 1, objects.count { |item| item[:name] == "leaf" }
    assert_equal 1, objects.count { |item| item[:name] == "left" }
    assert_equal 1, objects.count { |item| item[:name] == "right" }
  end

  def test_other_devices_cannot_be_compared
    other = Algosec::Config::Parser.perform(content, vendor: :hillstone, device_id: 2)
    assert_raises(ArgumentError) { compare(parse(content), other) }
  end

  def test_root_and_nested_address_negation_changes_are_reported_without_raw_commands
    [ false, true ].each do |nested|
      before = result_with_address_group(negated: false, nested: nested)
      after = result_with_address_group(negated: true, nested: nested)

      report = compare(before, after)

      assert report.fetch(:complete)
      assert_equal({ "modified" => 1 }, report.fetch(:summary))
      refute before.rules.sole.sources.set == after.rules.sole.sources.set
      assert_equal report, compare(before, after)
    end
  end

  def test_synthetic_match_group_names_are_not_rule_declaration_changes
    before = result_with_address_group(negated: false, nested: false, name: "before-wrapper")
    after = result_with_address_group(negated: false, nested: false, name: "after-wrapper")

    assert_empty compare(before, after).fetch(:changes)
  end

  def test_redacted_root_wrapper_text_is_not_required_to_compare_its_declaration
    before = result_with_address_group(negated: true, nested: false, config: "root wrapper text")
    document = JSON.parse(JSON.generate(Algosec::Config::Document.dump(before)))
    after = Algosec::Config::Document.load(document)

    refute after.rules.sole.sources.config_available?
    assert_empty compare(before, after).fetch(:changes)
  end

  private

  def result_with_address_group(negated:, nested:, name: "addresses", config: nil)
    context = { vendor: :palo_alto, device_id: 1 }
    address = E::AddressObject.new(**context, name: "host", member: [ { type: "host", value: "192.0.2.1" } ])
    type = negated ? E::AddressGroup::Negated : E::AddressGroup
    group = type.new(**context, name: name, config: config, members: { "host" => address })
    group = E::AddressGroup.new(**context, name: "root", members: { "addresses" => group }) if nested
    rule = E::SecurityRule.new(**context, name: "rule", sources: group)
    Algosec::Config::Result.new(reader: Algosec::Config::Reader.new("", **context),
      catalog: E::Catalog.new([ address, rule ], **context), diagnostics: [], at: Time.utc(2026))
  end
end
