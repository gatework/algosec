# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "support/policy_factory"
require "algosec/vendors/palo_alto/set_configuration"

class PaloAltoParserTest < Minitest::Test
  include PolicyFactory

  def parse(text)
    Algosec::Config::Parser.perform(text, vendor: :palo_alto, device_id: 1)
  end

  def fixture
    File.read(TestPaths.root.join("test/fixtures/config/palo_alto.cfg"))
  end

  def test_explicit_logging_states_preserve_unknown_defaults_and_cache_roundtrip
    base = fixture.lines.reject { |line| line.match?(/ log-(start|end) /) }.join
    [ [ nil, nil, nil ], [ "no", nil, nil ], [ nil, "no", nil ],
      [ "yes", nil, true ], [ nil, "yes", true ], [ "yes", "no", true ], [ "no", "no", false ] ].each do |start_log, end_log, expected|
      content = base.dup
      content << "set rulebase security rules allow-web log-start #{start_log}\n" if start_log
      content << "set rulebase security rules allow-web log-end #{end_log}\n" if end_log
      result = parse(content)
      actual = result.rules.sole.log_enabled
      expected.nil? ? assert_nil(actual) : assert_equal(expected, actual)
      cache = Algosec::Config::Cache.new(store: ActiveSupport::Cache::MemoryStore.new)
      cache.save(result)
      cached = cache.load(1).rules.sole.log_enabled
      expected.nil? ? assert_nil(cached) : assert_equal(expected, cached)
    end
  end

  def test_addresses_services_interfaces_schedules_and_nat_from_set_export
    result = parse(fixture)
    assert result.complete?, result.diagnostics.inspect
    assert_equal "203.0.113.9/24", result.find(E::Interface, name: "ethernet1/2").ipaddr
    assert_equal Algosec::IPAddr.parse("203.0.113.0/24"), result.find(E::AddressObject, name: "uplink").set
    rule = result.rules.sole
    assert_equal "allow", rule.action
    assert_equal [ "inside" ], rule.from_zones
    assert rule.sources.set.cover?(Algosec::IPAddr.parse("10.1.0.1-10.1.0.5"))
    assert rule.services.set.cover?(Algosec::IPAddr.service("tcp/8080-8082"))
    refute rule.services.set.cover?(Algosec::IPAddr.service("tcp/81"))
    assert_equal "maintenance window", rule.schedule.name
    assert_equal Time.utc(2026, 9, 18, 1), rule.schedule.start_at
    assert_equal 1, result.reference_counts.fetch(rule.schedule.identity)
    snat, dnat = result.elements(E::DynamicNat)
    assert_equal Algosec::IPAddr.parse("203.0.113.9"), snat.source_targets
    assert_equal "ethernet1/2", snat.interface
    assert_equal Algosec::IPAddr.service("any"), snat.service_set
    assert_equal Algosec::IPAddr.parse("192.0.2.9"), dnat.destination_targets
    assert_equal "8443", dnat.translated_destination_port
    assert_equal "443", dnat.destination_port
    assert dnat.disabled?
    assert_equal 2, dnat.extra_conf.fetch("panos").fetch("translations").size
  end

  def test_negated_rule_addresses_resolve_named_address_groups
    result = parse(<<~CONFIG)
      set address excluded-host ip-netmask 192.0.2.9/32
      set address-group excluded static [ excluded-host ]
      set rulebase security rules allow-rest destination excluded
      set rulebase security rules allow-rest negate-destination yes
      set rulebase security rules allow-rest service any
      set rulebase security rules allow-rest action allow
    CONFIG

    assert result.complete?, result.diagnostics.inspect
    rule = result.rules.sole
    refute rule.destinations.set.cover?(Algosec::IPAddr.parse("192.0.2.9"))
    assert rule.destinations.set.cover?(Algosec::IPAddr.parse("198.51.100.9"))
    assert_same result.find(E::AddressGroup, name: "excluded"), rule.destinations.members.fetch("excluded")
    assert_equal rule.destinations.set, result.rule_projection.destinations.fetch(rule.identity)
  end

  def test_application_default_negation_and_dynamic_groups_cannot_be_any
    text = fixture.sub("service web-group", "service application-default") + <<~CONFIG
      set rulebase security rules allow-web negate-destination yes
      set address-group registered dynamic filter "'production'"
    CONFIG
    result = parse(text)
    refute result.complete?
    rule = result.rules.sole
    assert_equal :application_default, rule.service_selection
    assert rule.services.members.empty?
    assert rule.destinations.resolved?
    refute result.find(E::AddressGroup, name: "registered").resolved?
    assert_empty rule.unparsed_commands
  end

  def test_default_rules_keep_intrazone_and_interzone_boundaries
    result = parse(<<~CONFIG)
      set rulebase default-security-rules rules intrazone-default action allow
      set rulebase default-security-rules rules interzone-default action deny
    CONFIG
    assert result.complete?, result.diagnostics.inspect
    current = P::Snapshot.new(vendor: :palo_alto, device_id: 1, catalog: result.catalog)
    query = { source: "10.0.0.1", destination: "192.0.2.1", protocol: "tcp", source_port: 1234, destination_port: 443 }
    assert_equal :permit, P::TrafficMatcher.new(current).perform(**query, from_zone: "inside", to_zone: "inside").decision
    assert_equal :deny, P::TrafficMatcher.new(current).perform(**query, from_zone: "inside", to_zone: "outside").decision
    assert_empty P::RuleMatcher.new(current).candidates(from_zone: "inside", to_zone: "outside")
  end

  def test_repeated_xml_members_keep_every_zone_and_negation_cannot_skip_to_allow
    source = fixture.sub("from [ inside ]", 'from [ inside ]\nset rulebase security rules allow-web from dmz'.gsub('\n', "\n"))
    result = parse(source)
    assert_equal [ "inside", "dmz" ], result.rules.sole.from_zones
    negated = parse(source + "set rulebase security rules allow-web negate-destination yes\n")
    assert negated.complete?, negated.diagnostics.inspect
    refute negated.rules.sole.destinations.set.cover?(Algosec::IPAddr.parse("192.0.2.9"))
    assert negated.rules.sole.destinations.set.cover?(Algosec::IPAddr.parse("198.51.100.9"))
  end

  def test_running_xml_is_normalized_without_entering_candidate_configuration
    xml = <<~XML
      <config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">
      <address><entry name="with space"><ip-netmask>192.0.2.9/32</ip-netmask></entry></address>
      <address-group><entry name="group"><static><member>with space</member></static></entry></address-group>
      </entry></vsys></entry></devices></config>
    XML
    normalized = Algosec::Vendors::PaloAlto::SetConfiguration.from_xml(xml)
    result = parse(normalized)
    assert result.complete?, result.diagnostics.inspect
    assert_equal Algosec::IPAddr.parse("192.0.2.9"), result.find(E::AddressGroup, name: "group").set
    assert_raises(ArgumentError) { Algosec::Vendors::PaloAlto::SetConfiguration.from_xml('<!DOCTYPE a SYSTEM "file:///etc/passwd"><config/>') }
    assert_raises(ArgumentError) { Algosec::Vendors::PaloAlto::SetConfiguration.from_xml("<broken>") }
  end

  def test_transcript_noise_is_not_a_command_and_unsupported_secrets_are_not_diagnostics
    text = "spawn ssh user@device\r\nuser@device(active)# show\r\n" + fixture +
      "set mgt-config users admin phash secret-value\nset shared certificate vpn private-key \"private-value\n"
    result = parse(text)
    assert_equal 1, result.rules.size
    assert_equal 2, result.diagnostics.count { |d| d.code == :unsupported_command }
    refute_includes result.diagnostics.map(&:message).join, "secret-value"
    refute_includes result.diagnostics.map(&:message).join, "private-value"
    assert_includes result.reader.content, "secret-value"
  end

  def test_combined_translation_preserves_both_sides_and_namespaced_vsys_is_not_merged
    combined = fixture + "set rulebase nat rules publish source-translation dynamic-ip-and-port translated-address 203.0.113.21\n"
    nat = parse(combined).elements(E::DynamicNat).last
    assert_equal :bidirectional, nat.direction
    assert_equal Algosec::IPAddr.parse("203.0.113.21"), nat.source_targets
    assert_equal Algosec::IPAddr.parse("192.0.2.9"), nat.destination_targets
    result = parse("set vsys vsys2 address clients ip-netmask 10.9.0.0/16\n" + fixture)
    assert_includes result.diagnostics.map(&:code), :unsupported_scope
    assert_equal Algosec::IPAddr.parse("10.0.0.0/24"), result.find(E::AddressObject, name: "clients").set
  end

  def test_panorama_rules_do_not_overwrite_local_rules_with_the_same_name
    result = parse(fixture + "set pre-rulebase security rules allow-web action deny\n")
    assert_includes result.diagnostics.map(&:code), :unsupported_scope
    assert_equal 1, result.rules.size
    assert_equal "allow", result.rules.sole.action
    refute result.complete?
  end

  def test_local_objects_override_whole_shared_definitions_in_either_order
    shared = "set shared address-group office static server\n"
    [ shared + fixture, fixture + shared ].each do |source|
      result = parse(source)
      assert result.complete?, result.diagnostics.inspect
      assert_equal [ "clients" ], result.find(E::AddressGroup, name: "office").members.keys
    end
  end

  def test_negation_retains_references_and_matches_complement_after_cache_round_trip
    source = fixture.lines.reject { |line| line.include?("rules allow-web schedule") }.join
    result = parse(source + "set rulebase security rules allow-web negate-destination yes\n")
    server = result.find(E::AddressObject, name: "server")
    assert_equal 2, result.reference_counts.fetch(server.identity) # 安全策略与 NAT 均引用服务器。
    store = ActiveSupport::Cache::MemoryStore.new
    cache = Algosec::Config::Cache.new(store: store)
    cache.save(result)
    restored = cache.load(1)
    config = P::Snapshot.new(vendor: :palo_alto, device_id: 1, catalog: restored.catalog)
    matcher = P::TrafficMatcher.new(config)
    query = { source: "10.0.0.1", protocol: "tcp", source_port: 50000, destination_port: 443,
      from_zone: "inside", to_zone: "outside" }
    denied = matcher.perform(**query, destination: "192.0.2.9")
    assert_equal :matched, denied.status
    assert_equal :deny, denied.decision
    assert_nil denied.rule
    assert_equal :permit, matcher.perform(**query, destination: "198.51.100.9").decision
    dynamic = parse(source.sub("ip-netmask 192.0.2.9/32", "fqdn example.test") + "set rulebase security rules allow-web negate-destination yes\n")
    refute dynamic.rules.sole.destinations.resolved?
    assert_empty dynamic.rules.sole.destinations.set
  end

  def test_explicit_default_rules_are_evaluated_after_local_security_rules
    source = "set rulebase default-security-rules rules interzone-default action deny\n" + fixture
    result = parse(source)
    assert_equal [ "allow-web", "interzone-default" ], result.rules.sort_by(&:rule_number).map(&:name)
  end

  def test_unmodeled_nat_conditions_are_preserved_and_prevent_complete_analysis
    result = parse(fixture + "set rulebase nat rules outbound active-active-device-binding primary\n")
    assert_includes result.diagnostics.map(&:code), :unsupported_nat_condition
    assert_equal [ "primary" ], result.elements(E::DynamicNat).first.extra_conf.fetch("panos").fetch("active-active-device-binding")
    assert_raises(P::Error) { P::Snapshot.from_config(result) }
  end

  def test_nat_only_objects_and_service_groups_keep_dependencies_after_cache_restore
    result = parse(<<~CONFIG)
      set address real ip-netmask 10.0.0.1
      set address public ip-netmask 203.0.113.1
      set service web protocol tcp port 443
      set service-group web-group members web
      set rulebase nat rules publication from outside
      set rulebase nat rules publication to outside
      set rulebase nat rules publication destination public
      set rulebase nat rules publication service web-group
      set rulebase nat rules publication destination-translation translated-address real
    CONFIG
    assert result.complete?, result.diagnostics.inspect
    [ [ E::AddressObject, "real" ], [ E::AddressObject, "public" ], [ E::ServiceObject, "web" ], [ E::ServiceGroup, "web-group" ] ].each do |type, name|
      assert_equal 1, result.reference_counts.fetch(result.find(type, name: name).identity)
    end
    cache = Algosec::Config::Cache.new(store: ActiveSupport::Cache::MemoryStore.new)
    cache.save(result)
    assert_equal %w[public real web-group], cache.load(1).elements(E::DynamicNat).sole.dependencies.map(&:name).sort
  end
end
