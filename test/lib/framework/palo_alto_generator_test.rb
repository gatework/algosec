# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "support/policy_factory"

class PaloAltoGeneratorTest < Minitest::Test
  include PolicyFactory

  def parse(text)
    Algosec::Config::Parser.perform(text, vendor: :palo_alto, device_id: 1)
  end

  def generate_nat(type: :dynamic, mapped: "203.0.113.7", direction: :nat_sources, objects: [], **options)
    data = group(:palo_alto, **options)
    record = { real_ip: "10.0.0.1", nat: { type: type, address: mapped } }
    result = P::Result.new(**data, type: :ignore, snapshot: snapshot(:palo_alto, objects),
      actions: { new: { direction => { "10.0.0.1" => record } } })
    result.definition.build_generator(result).perform
  end

  def test_static_and_dynamic_source_nat_round_trip_with_exact_scope
    %i[static dynamic].each do |type|
      script = generate_nat(type: type, services: [ "tcp/443", "udp/53" ])
      parsed = parse(script)
      assert parsed.complete?, parsed.diagnostics.inspect
      nats = parsed.elements(E::DynamicNat)
      assert_equal 2, nats.size
      nats.each do |nat|
        assert_equal Algosec::IPAddr.parse("10.0.0.1"), nat.source_set
        assert_equal Algosec::IPAddr.parse("192.0.2.1"), nat.destination_set
        assert_equal Algosec::IPAddr.parse("203.0.113.7"), nat.source_targets
        assert_equal "inside", nat.from_zone
        assert_equal "outside", nat.to_zone
      end
      assert_equal P::Ranges.services([ "tcp/443", "udp/53" ]), nats.map(&:service_set).reduce(:|)
      assert_equal script, generate_nat(type: type, services: [ "tcp/443", "udp/53" ])
    end
  end

  def test_interface_source_nat_and_unsupported_destination_are_explicit
    assert_includes generate_nat(mapped: nil), 'interface-address interface "outside"'
    assert_raises(P::Error) { generate_nat(direction: :nat_destinations) }
    assert_raises(P::Error) { generate_nat(type: :static, mapped: "203.0.113.0/24") }
  end

  def test_nat_cannot_silently_follow_an_overlapping_rule
    nat = E::DynamicNat.new(**context(:palo_alto), name: "existing", direction: :source,
      source_set: Algosec::IPAddr.parse("10.0.0.0/24"), destination_set: Algosec::IPAddr.parse("0.0.0.0/0"),
      translated_source_set: Algosec::IPAddr.parse("203.0.113.8"), from_zone: "inside", to_zone: "outside")
    error = assert_raises(P::Error) { generate_nat(objects: [ nat ]) }
    assert_equal :nat_scope_conflict, error.code
  end

  def test_new_allow_rule_is_positioned_before_local_deny_but_not_before_default
    local = <<~CONFIG
      set rulebase security rules deny-web from inside
      set rulebase security rules deny-web to outside
      set rulebase security rules deny-web source any
      set rulebase security rules deny-web destination any
      set rulebase security rules deny-web service any
      set rulebase security rules deny-web application any
      set rulebase security rules deny-web action deny
    CONFIG
    [ local, "set rulebase default-security-rules rules interzone-default action deny\n" ].each_with_index do |text, index|
      config = snapshot(:palo_alto, parse(text).catalog.to_a)
      result = P::RuleMatcher.new(config).match(group(:palo_alto))
      script = result.definition.build_generator(result).perform
      if index.zero?
        assert_match(/move rulebase security rules "p_\w+" before "deny-web"/, script)
      else
        refute_includes script, "move rulebase"
      end
    end
  end

  def publication_result(combined: false, routes: nil, config: nil, services: [ { services: [ "tcp/443" ], translated_port: 8443 } ])
    routes ||= [
      E::Route.new(**context(:palo_alto), name: "internet", subnet: "0.0.0.0/0", zone: "outside", vrf: "default"),
      E::Route.new(**context(:palo_alto), name: "servers", subnet: "10.0.0.0/24", zone: "inside", vrf: "default")
    ]
    data = group(:palo_alto, from_zone: "outside", to_zone: "inside", sources: [ "198.51.100.9" ],
      destinations: [ "203.0.113.7" ], services: services)
    destination = { real_ip: "10.0.0.9", nat: { type: :static, address: "203.0.113.7" } }
    additions = { nat_destinations: { "203.0.113.7" => destination },
      sources: data[:sources].transform_values { nil }, destinations: data[:destinations].transform_values { nil },
      services: data[:services].transform_values { nil } }
    if combined
      additions[:nat_sources] = { "198.51.100.9" => { real_ip: "198.51.100.9", nat: { type: :dynamic, address: "10.0.0.1" } } }
    end
    P::Result.new(**data, type: :new, snapshot: config || snapshot(:palo_alto, routes), actions: { new: additions })
  end

  def test_destination_and_combined_nat_round_trip_use_pre_nat_zone_and_original_service
    [ false, true ].each do |combined|
      result = publication_result(combined: combined)
      script = result.definition.build_generator(result).perform
      parsed = parse(script)
      assert parsed.complete?, parsed.diagnostics.inspect
      nat = parsed.elements(E::DynamicNat).sole
      assert_equal "outside", nat.from_zone
      assert_equal "outside", nat.to_zone
      assert_equal Algosec::IPAddr.parse("203.0.113.7"), nat.destination_set
      assert_equal Algosec::IPAddr.parse("10.0.0.9"), nat.destination_targets
      assert_equal "8443", nat.translated_destination_port
      assert_equal Algosec::IPAddr.service("tcp/443"), nat.service_set
      assert_equal(combined ? :bidirectional : :destination, nat.direction)
      assert_equal Algosec::IPAddr.parse("10.0.0.1"), nat.source_targets if combined
      rule = parsed.rules.sole
      assert_equal [ "inside" ], rule.to_zones
      assert_equal nat.destination_set, rule.destinations.set
      assert_equal nat.service_set, rule.services.set
    end
  end

  def test_destination_nat_requires_routes_and_rejects_equal_cost_different_zones
    result = publication_result(routes: [])
    generator = result.definition.build_generator(result)
    error = assert_raises(P::Error) { generator.perform }
    assert_equal :ambiguous_zone, error.code
    assert_empty generator.commands
    ambiguous = %w[inside outside].map do |zone|
      E::Route.new(**context(:palo_alto), name: zone, subnet: "0.0.0.0/0", zone: zone, vrf: "default")
    end
    result = publication_result(routes: ambiguous)
    assert_raises(P::Error) { result.definition.build_generator(result).perform }
  end

  def test_destination_nat_original_service_reuse_and_ports_are_exact
    result = publication_result(services: [ { services: [ "tcp/443", "udp/443" ], translated_port: 8443 } ])
    parsed = parse(result.definition.build_generator(result).perform)
    assert_equal 2, parsed.elements(E::DynamicNat).size
    config = snapshot(:palo_alto, parsed.catalog.to_a)
    found = P::Nat::Resolver.new(config).find("10.0.0.9", zone: "outside", direction: :destination, flow: { from_zone: "outside", to_zone: "outside" },
      peers: { "198.51.100.9" => {} }, services: { "tcp/443" => { origin: "tcp/443", translated_port: "8443" } })
    assert_equal Algosec::IPAddr.parse("203.0.113.7"), Algosec::IPAddr.parse(found.fetch(:address))
    refute P::Nat::Resolver.new(config).find("10.0.0.9", zone: "outside", direction: :destination, flow: { from_zone: "outside", to_zone: "outside" },
      peers: { "198.51.100.9" => {} }, services: { "tcp/443" => { origin: "tcp/443", translated_port: "9443" } })
    invalid = publication_result(services: [ { services: [ "tcp/443-445" ], translated_port: 8443 } ])
    assert_raises(P::Error) { invalid.definition.build_generator(invalid).perform }
  end

  def test_search_to_design_preserves_public_address_and_combines_explicit_source_allocation
    base = publication_result
    topology = networks(:palo_alto, nat_mode: 1, address_type: :private)
    [ false, true ].each do |combined|
      source = combined ? { addresses: [ "198.51.100.9" ], nat: { type: :dynamic, address: "10.0.0.1" } } : "198.51.100.9"
      request = P::Request.new(sources: [ source ],
        destinations: [ { addresses: [ "10.0.0.9" ], nat: { type: :static, address: "203.0.113.7" } } ],
        services: [ { services: [ "tcp/443" ], translated_port: 8443 } ])
      report = P::Searcher.new(networks: topology, snapshots: { 1 => base.snapshot }).perform(request)
      assert report.success?, report.comment
      result = report.results.sole
      assert_equal [ "203.0.113.7/32" ], result.destinations.keys
      assert_equal "inside", result.to_zone
      script = P::Planner.new(report).perform.sole.fetch(:policy_contents).sole.fetch(:new).fetch(:content)
      parsed = parse(script)
      assert parsed.complete?, parsed.diagnostics.inspect
      assert_equal(combined ? :bidirectional : :destination, parsed.elements(E::DynamicNat).sole.direction)
    end
  end

  def test_destination_overlap_is_checked_in_pre_nat_zone_and_failure_is_atomic
    result = publication_result
    existing = E::DynamicNat.new(**context(:palo_alto), name: "earlier", direction: :destination,
      from_zone: "outside", to_zone: "outside", source_set: Algosec::IPAddr.parse("0.0.0.0/0"),
      destination_set: Algosec::IPAddr.parse("203.0.113.7"), translated_destination_set: Algosec::IPAddr.parse("10.0.0.8"))
    result.snapshot.catalog.add(existing)
    generator = result.definition.build_generator(result)
    error = assert_raises(P::Error) { generator.perform }
    assert_equal :nat_scope_conflict, error.code
    assert_empty generator.commands
  end

  def test_batch_publication_cannot_map_same_original_port_to_different_target_ports
    first = publication_result
    second = publication_result(config: first.snapshot, services: [ { services: [ "tcp/443" ], translated_port: 9443 } ])
    generator = first.definition.build_generator(first)
    assert_raises(P::Error) { generator.perform([ first, second ]) }
    assert_empty generator.commands
  end
end
