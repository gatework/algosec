# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "../framework/support/policy_factory"

class NatSelectionContractTest < Minitest::Test
  include PolicyFactory

  def test_first_original_destination_match_cannot_be_skipped_for_desired_target
    resolver = destination_resolver([ [ "first", "10.0.0.8" ], [ "later", "10.0.0.9" ] ])
    error = assert_raises(P::Error) { destination_lookup(resolver, original_dst: "203.0.113.9") }
    assert_equal :conditional_nat, error.code
  end

  def test_reverse_alias_is_rechecked_against_first_forward_rule
    resolver = destination_resolver([ [ "first", "10.0.0.8" ], [ "later", "10.0.0.9" ] ])
    assert_nil destination_lookup(resolver)
  end

  def test_source_nat_respects_provided_ingress_zone
    wrong = source_nat("dmz-only", from_zone: "dmz", translated_source_set: "203.0.113.1")
    right = source_nat("inside-only", from_zone: "inside", translated_source_set: "203.0.113.2")
    found = source_lookup([ wrong, right ], flow: { from_zone: "inside", to_zone: "outside", vrf: "default" })
    assert_same right, found.fetch(:rule)
  end

  def test_missing_ingress_zone_does_not_prove_constrained_source_nat
    error = assert_raises(P::Error) { source_lookup([ source_nat("inside-only", from_zone: "inside") ]) }
    assert_equal :conditional_nat, error.code
  end

  def test_mapped_source_port_is_validated_after_first_rule_selection
    first = source_nat("first", translated_source_port: "5000")
    later = source_nat("later", translated_source_port: "6000")
    error = assert_raises(P::Error) { source_lookup([ first, later ], mapped_source_port: "6000") }
    assert_equal :conditional_nat, error.code
  end

  def test_earlier_source_rule_blocks_destination_translation_on_same_packet
    first = source_nat("source-first", source_set: "0.0.0.0/0", destination_set: "203.0.113.9", to_zone: "inside")
    last = E::DynamicNat.new(**context(:palo_alto), name: "destination-later", direction: :destination,
                            from_zone: "outside", to_zone: "inside", source_set: "0.0.0.0/0", destination_set: "203.0.113.9",
                            translated_destination_set: "10.0.0.9")
    resolver = P::Nat::Resolver.new(snapshot(:palo_alto, [ first, last ]))
    assert_equal :conditional_nat, assert_raises(P::Error) { destination_lookup(resolver, original_dst: "203.0.113.9") }.code
  end

  def test_source_nat_respects_explicit_vrf
    first = source_nat("red", vrf: "red")
    later = source_nat("blue", vrf: "blue")
    found = source_lookup([ first, later ], flow: { from_zone: "inside", to_zone: "outside", vrf: "blue" })
    assert_same later, found.fetch(:rule)
  end

  def test_generic_source_nat_respects_both_zones_and_vrf
    %i[hillstone srx].each do |vendor|
      common = { **context(vendor), rule_set: "source", direction: :source, source_set: "10.0.0.1", destination_set: "0.0.0.0/0", translated_source_set: "203.0.113.1" }
      wrong_from = E::DynamicNat.new(**common, name: "wrong-from", id: "1", from_zone: "dmz", to_zone: "outside", vrf: "blue")
      wrong_to = E::DynamicNat.new(**common, name: "wrong-to", id: "2", from_zone: "inside", to_zone: "other", vrf: "blue")
      wrong_vrf = E::DynamicNat.new(**common, name: "wrong-vrf", id: "3", from_zone: "inside", to_zone: "outside", vrf: "red")
      right = E::DynamicNat.new(**common, name: "right", id: "4", from_zone: "inside", to_zone: "outside", vrf: "blue")
      resolver = P::Nat::Resolver.new(snapshot(vendor, [ wrong_from, wrong_to, wrong_vrf, right ]))
      found = resolver.find("10.0.0.1", zone: "outside", direction: :source, peers: { "192.0.2.1" => {} },
                            flow: { from_zone: "inside", to_zone: "outside", vrf: "blue" })
      assert_same right, found.fetch(:rule), vendor.to_s
    end
  end

  def test_generic_source_nat_missing_ingress_is_unknown
    nat = E::DynamicNat.new(**context(:hillstone), id: "1", direction: :source, from_zone: "inside", to_zone: "outside",
                            source_set: "10.0.0.1", destination_set: "0.0.0.0/0", translated_source_set: "203.0.113.1")
    resolver = P::Nat::Resolver.new(snapshot(:hillstone, [ nat ]))
    error = assert_raises(P::Error) { resolver.find("10.0.0.1", zone: "outside", direction: :source, peers: { "192.0.2.1" => {} }) }
    assert_equal :conditional_nat, error.code
  end

  def test_generic_first_original_destination_match_cannot_be_skipped
    resolver = generic_destination_resolver
    error = assert_raises(P::Error) { destination_lookup(resolver, original_dst: "203.0.113.9") }
    assert_equal :conditional_nat, error.code
  end

  def test_generic_reverse_alias_cannot_bypass_forward_shadowing
    error = assert_raises(P::Error) { destination_lookup(generic_destination_resolver) }
    assert_equal :conditional_nat, error.code
  end

  def test_generic_mapped_source_port_cannot_skip_first_original_rule
    common = { **context(:hillstone), direction: :source, to_zone: "outside", source_set: "10.0.0.1",
               destination_set: "0.0.0.0/0", translated_source_set: "203.0.113.1" }
    rows = [ "5000", "6000" ].map { |port| E::DynamicNat.new(**common, id: port, translated_source_port: port) }
    resolver = P::Nat::Resolver.new(snapshot(:hillstone, rows))
    error = assert_raises(P::Error) do
      resolver.find("10.0.0.1", zone: "outside", direction: :source, peers: { "192.0.2.1" => {} }, mapped_source_port: "6000")
    end
    assert_equal :conditional_nat, error.code
  end

  def test_generic_partial_original_destination_is_not_complete_mapping
    nat = E::DynamicNat.new(**context(:hillstone), id: "1", direction: :destination, from_zone: "outside",
                            source_set: "0.0.0.0/0", destination_set: "203.0.113.0/25", translated_destination_set: "10.0.0.9")
    error = assert_raises(P::Error) do
      destination_lookup(P::Nat::Resolver.new(snapshot(:hillstone, [ nat ])), original_dst: "203.0.113.0/24")
    end
    assert_equal :conditional_nat, error.code
  end

  def test_destination_pool_does_not_prove_one_fixed_internal_address
    nat = E::DynamicNat.new(**context(:hillstone), id: "1", direction: :destination, from_zone: "outside",
                            source_set: "0.0.0.0/0", destination_set: "203.0.113.9", translated_destination_set: "10.0.0.8-10.0.0.9")
    error = assert_raises(P::Error) { destination_lookup(P::Nat::Resolver.new(snapshot(:hillstone, [ nat ]))) }
    assert_equal :conditional_nat, error.code
  end

  def test_pan_interface_condition_without_route_evidence_remains_unknown
    nat = source_nat("interface-only", interface: "ethernet1/1")
    error = assert_raises(P::Error) { source_lookup([ nat ]) }
    assert_equal :conditional_nat, error.code
  end

  def test_asa_translator_forwards_original_zone_context
    nat = E::DynamicNat.new(**context(:asa), id: "1", acl_name: "", direction: :destination, from_zone: "outside", to_zone: "inside",
                            source_set: "0.0.0.0/0", destination_set: "203.0.113.9", translated_destination_set: "10.0.0.9")
    translator = P::Nat::Translator.build(snapshot(:asa, [ nat ], version: "9.1"))
    mapped, = translator.map({ "10.0.0.9/32" => { origin: "10.0.0.9/32", private: "10.0.0.9/32" } },
                              side: :destination, hit: :destination, mode: 1, zone: "outside", peers: { "192.0.2.1" => {} },
                              services: { "tcp/443" => {} }, flow: { from_zone: "outside", to_zone: "inside" })
    assert_same nat, mapped.fetch("10.0.0.9/32").fetch(:nat).fetch(:rule)
  end

  def test_pan_search_uses_original_destination_route_for_nat_and_internal_zone_for_security
    nat = E::DynamicNat.new(**context(:palo_alto), name: "publication", direction: :destination,
                            from_zone: "outside", to_zone: "outside", source_set: "0.0.0.0/0", destination_set: "203.0.113.9",
                            translated_destination_set: "10.0.0.9")
    access = rule(:palo_alto, source: "198.51.100.1", destination: "203.0.113.9", from_zones: "outside", to_zones: "inside")
    routes = [ E::Route.new(**context(:palo_alto), name: "external", subnet: "0.0.0.0/0", zone: "outside", vrf: "default", destination_interface: "outside"),
               E::Route.new(**context(:palo_alto), name: "internal", subnet: "10.0.0.0/8", zone: "inside", vrf: "default", destination_interface: "inside") ]
    config = snapshot(:palo_alto, [ nat, access, *routes ])
    report = P::Searcher.new(networks: networks(:palo_alto, nat_mode: 1, address_type: :private), snapshots: { 1 => config }).perform(
      sources: [ "198.51.100.1" ], destinations: [ "10.0.0.9" ], services: [ "tcp/443" ])
    assert report.success?, report.comment
    result = report.results.fetch(0)
    assert_equal :ignore, result.type
    assert_equal "inside", result.to_zone
    assert_equal [ "203.0.113.9/32" ], result.destinations.keys
    assert_same nat, result.destinations.values.first.fetch(:nat).fetch(:rule)
  end

  def test_pan_translator_does_not_guess_original_egress_from_internal_zone
    nat = E::DynamicNat.new(**context(:palo_alto), name: "publication", direction: :destination,
                            from_zone: "outside", to_zone: "outside", source_set: "0.0.0.0/0", destination_set: "203.0.113.9",
                            translated_destination_set: "10.0.0.9")
    translator = P::Nat::Translator.build(snapshot(:palo_alto, [ nat ]))
    error = assert_raises(P::Error) do
      translator.map({ "10.0.0.9/32" => { origin: "10.0.0.9/32", private: "10.0.0.9/32" } },
                     side: :destination, hit: :destination, mode: 1, zone: "outside", peers: { "198.51.100.1" => {} },
                     services: { "tcp/443" => {} }, flow: { from_zone: "outside", to_zone: "inside", vrf: "default" })
    end
    assert_equal :conditional_nat, error.code
  end

  def test_pan_interface_condition_uses_the_original_packet_route
    wrong = source_nat("wrong-interface", interface: "ethernet1/1")
    right = source_nat("right-interface", interface: "ethernet1/2")
    route = E::Route.new(**context(:palo_alto), name: "external", subnet: "0.0.0.0/0", zone: "outside",
                        vrf: "default", destination_interface: "ethernet1/2")
    resolver = P::Nat::Resolver.new(snapshot(:palo_alto, [ wrong, right, route ]))
    found = resolver.find("10.0.0.1", zone: "outside", direction: :source, peers: { "192.0.2.1" => {} },
                          flow: { from_zone: "inside", to_zone: "outside", vrf: "default" })
    assert_same right, found.fetch(:rule)
  end

  def test_generic_reverse_discovery_reports_distinct_public_aliases
    rows = [ "203.0.113.8", "203.0.113.9" ].map do |public_address|
      E::DynamicNat.new(**context(:hillstone), id: public_address, direction: :destination, from_zone: "outside",
                       source_set: "0.0.0.0/0", destination_set: public_address, translated_destination_set: "10.0.0.9")
    end
    error = assert_raises(P::Error) { destination_lookup(P::Nat::Resolver.new(snapshot(:hillstone, rows))) }
    assert_equal :ambiguous_nat, error.code
  end

  def test_explicit_multiaddress_static_mapping_requires_separate_pairs
    input = { addresses: [ "10.0.0.1", "10.0.0.2" ], nat: { type: :static, address: "203.0.113.1-203.0.113.2" } }
    assert_raises(ArgumentError) { request(input) }
    assert_equal :static, input[:nat][:type]
  end

  def test_multiaddress_static_without_translation_is_rejected
    assert_raises(ArgumentError) { request(addresses: [ "10.0.0.1", "10.0.0.2" ], nat: { type: :static }) }
  end

  def test_explicit_static_pairs_and_dynamic_pool_keep_their_modes
    pairs = P::Request.new(sources: [
      { addresses: [ "10.0.0.1" ], nat: { type: :static, address: "203.0.113.1" } },
      { addresses: [ "10.0.0.2" ], nat: { type: :static, address: "203.0.113.2" } }
    ], destinations: [ "192.0.2.1" ], services: [ "tcp/443" ])
    assert_equal [ :static, :static ], pairs.sources.values.map { |entry| entry[:nat][:type] }
    pool = request(addresses: [ "10.0.0.1", "10.0.0.2" ], nat: { type: :dynamic, address: "203.0.113.1-203.0.113.2" })
    assert_equal [ :dynamic, :dynamic ], pool.sources.values.map { |entry| entry[:nat][:type] }
  end

  def test_generic_destination_mapping_preserves_explicit_original_host
    nat = bounded_destination_nat
    resolver = P::Nat::Resolver.new(snapshot(:hillstone, [ nat ]))
    mapping = destination_lookup(resolver, original_dst: "203.0.113.9")
    assert_equal "203.0.113.9/32", mapping.fetch(:address)
    assert_same nat, mapping.fetch(:rule)
  end

  def test_generic_destination_search_reuses_exact_original_host_rule
    nat = bounded_destination_nat
    access = rule(:hillstone, source: "198.51.100.1", destination: "203.0.113.9", from_zones: "outside", to_zones: "inside")
    config = snapshot(:hillstone, [ nat, access ])
    report = P::Searcher.new(networks: networks(:hillstone, nat_mode: 1, address_type: :private), snapshots: { 1 => config }).perform(
      sources: [ "198.51.100.1" ],
      destinations: [ { addresses: [ "10.0.0.9" ], nat: { type: :static, address: "203.0.113.9" } } ], services: [ "tcp/443" ])
    assert report.success?, report.comment
    assert_equal :ignore, report.results.fetch(0).type
    assert_equal [ "203.0.113.9/32" ], report.results.fetch(0).destinations.keys
  end

  def test_generic_source_allocation_cannot_replace_first_matching_translation
    resolver = P::Nat::Resolver.new(snapshot(:hillstone, [ allocated_source_nat ]))
    error = assert_raises(P::Error) do
      resolver.find("10.0.0.9", zone: "outside", direction: :source, peers: { "192.0.2.1" => {} },
                    allocation: { type: :dynamic, address: "203.0.113.2" })
    end
    assert_equal :conditional_nat, error.code
  end

  def test_generic_source_translator_reuses_matching_allocation
    nat = allocated_source_nat
    mapped, = allocated_source_translation(nat, "203.0.113.1")
    entry = mapped.fetch("10.0.0.9/32")
    assert_same nat, entry.fetch(:nat).fetch(:rule)
    refute entry.key?(:action)
  end

  def test_generic_source_translator_rejects_conflicting_allocation
    error = assert_raises(P::Error) { allocated_source_translation(allocated_source_nat, "203.0.113.2") }
    assert_equal :conditional_nat, error.code
  end

  private

  def bounded_destination_nat
    E::DynamicNat.new(**context(:hillstone), id: "bounded", direction: :destination, from_zone: "outside", to_zone: "inside",
                     source_set: "0.0.0.0/0", destination_set: "203.0.113.0/24", translated_destination_set: "10.0.0.9")
  end

  def allocated_source_nat
    E::DynamicNat.new(**context(:hillstone), id: "first", direction: :source, nat_type: "dynamicport", to_zone: "outside", source_set: "10.0.0.9",
                     destination_set: "0.0.0.0/0", translated_source_set: "203.0.113.1")
  end

  def allocated_source_translation(nat, allocated)
    P::Nat::Translator.build(snapshot(:hillstone, [ nat ])).map(
      { "10.0.0.9/32" => { origin: "10.0.0.9/32", private: "10.0.0.9/32", nat: { type: :dynamic, address: allocated } } },
      side: :source, hit: :source, mode: 1, zone: "outside", peers: { "192.0.2.1" => {} }, services: { "tcp/443" => {} })
  end

  def request(input)
    P::Request.new(sources: [ input ], destinations: [ "192.0.2.1" ], services: [ "tcp/443" ])
  end

  def generic_destination_resolver
    common = { **context(:hillstone), direction: :destination, from_zone: "outside", to_zone: "inside",
               source_set: "0.0.0.0/0", destination_set: "203.0.113.9" }
    rows = [ "10.0.0.8", "10.0.0.9" ].map do |target|
      E::DynamicNat.new(**common, id: target, translated_destination_set: target)
    end
    P::Nat::Resolver.new(snapshot(:hillstone, rows))
  end

  def destination_resolver(rows)
    config = rows.flat_map do |name, internal|
      { "from" => "outside", "to" => "inside", "source" => "any", "destination" => "203.0.113.9",
        "service" => "any", "destination-translation translated-address" => internal }.map do |field, value|
        "set rulebase nat rules #{name} #{field} #{value}"
      end
    end.join("\n")
    parsed = Algosec::Config::Parser.perform(config, vendor: :palo_alto, device_id: 1)
    assert parsed.complete?, parsed.diagnostics.inspect
    P::Nat::Resolver.new(P::Snapshot.from_config(parsed))
  end

  def destination_lookup(resolver, **flow)
    resolver.find("10.0.0.9", zone: "outside", direction: :destination, peers: { "192.0.2.1" => {} }, services: { "tcp/443" => {} },
                  flow: { from_zone: "outside", to_zone: "inside", vrf: "default", **flow })
  end

  def source_nat(name, **attributes)
    E::DynamicNat.new(**context(:palo_alto), name: name, direction: :source, to_zone: "outside", source_set: "10.0.0.1",
                     destination_set: "0.0.0.0/0", translated_source_set: "203.0.113.1", **attributes)
  end

  def source_lookup(rows, **options)
    P::Nat::Resolver.new(snapshot(:palo_alto, rows)).find("10.0.0.1", zone: "outside", direction: :source,
                                                     peers: { "192.0.2.1" => {} }, services: { "tcp/443" => {} }, **options)
  end
end
