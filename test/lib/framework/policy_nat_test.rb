# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "support/policy_factory"

class PolicyNatTest < Minitest::Test
  include PolicyFactory

  def test_dynamic_nat_uses_configuration_order_and_skips_disabled_entries
    common = { direction: :source, to_zone: "outside", source_set: "10.0.0.0/8", destination_set: "0.0.0.0/0",
               service_set: Algosec::IPAddr.service("any") }
    disabled = E::DynamicNat.new(**context(:hillstone), **common, id: "0", translated_source_set: "203.0.113.2", extra_conf: { disabled: true })
    first = E::DynamicNat.new(**context(:hillstone), **common, id: "9", translated_source_set: "203.0.113.9")
    second = E::DynamicNat.new(**context(:hillstone), **common, id: "1", translated_source_set: "203.0.113.1")
    resolver = P::Nat::Resolver.new(snapshot(:hillstone, [ disabled, first, second ]))
    found = resolver.find("10.0.0.1", zone: "outside", direction: :source, peers: { "192.0.2.1" => {} })
    assert_same first, found.fetch(:rule)
    assert_equal "203.0.113.9/32", found.fetch(:address)
    assert_empty snapshot(:hillstone, [ disabled ]).active_dynamic_nats
  end

  def test_partial_dynamic_nat_cannot_be_skipped_for_a_later_mapping
    common = { direction: :source, to_zone: "outside", source_set: "10.0.0.0/24",
               destination_set: "192.0.2.0/24", translated_source_set: "203.0.113.1" }
    [ { source_set: "10.0.0.0/25" }, { destination_set: "192.0.2.0/25" },
      { service_set: Algosec::IPAddr.service("tcp/443") }, { protocol: "tcp" },
      { source_port: "1024-2048" } ].each do |constraint|
      first = E::DynamicNat.new(**context(:hillstone), **common, **constraint, id: "9")
      later = E::DynamicNat.new(**context(:hillstone), **common, id: "1", translated_source_set: "203.0.113.2")
      resolver = P::Nat::Resolver.new(snapshot(:hillstone, [ first, later ]))
      error = assert_raises(P::Error, constraint.inspect) do
        resolver.find("10.0.0.0/24", zone: "outside", direction: :source,
                      peers: { "192.0.2.0/24" => {} }, services: { "tcp/443" => {}, "udp/53" => {} }, source_port: "1024-4096")
      end
      assert_equal :ambiguous_nat, error.code
    end
  end

  def test_partial_address_with_disjoint_service_does_not_block_later_nat
    common = { direction: :source, to_zone: "outside", destination_set: "0.0.0.0/0" }
    first = E::DynamicNat.new(**context(:hillstone), **common, id: "9", source_set: "10.0.0.0/25",
                              service_set: Algosec::IPAddr.service("udp/53"), translated_source_set: "203.0.113.1")
    later = E::DynamicNat.new(**context(:hillstone), **common, id: "1", source_set: "10.0.0.0/24", translated_source_set: "203.0.113.2")
    resolver = P::Nat::Resolver.new(snapshot(:hillstone, [ first, later ]))
    found = resolver.find("10.0.0.0/24", zone: "outside", direction: :source,
                          peers: { "192.0.2.1" => {} }, services: { "tcp/443" => {} })
    assert_same later, found[:rule]
  end

  def test_partial_destination_nat_preserves_internal_address_direction
    common = { direction: :destination, from_zone: "outside", source_set: "0.0.0.0/0", destination_set: "203.0.113.0/24" }
    first = E::DynamicNat.new(**context(:hillstone), **common, id: "9", translated_destination_set: "10.0.0.0/25")
    later = E::DynamicNat.new(**context(:hillstone), **common, id: "1", translated_destination_set: "10.0.0.0/24")
    resolver = P::Nat::Resolver.new(snapshot(:hillstone, [ first, later ]))
    error = assert_raises(P::Error) do
      resolver.find("10.0.0.0/24", zone: "outside", direction: :destination, peers: { "192.0.2.1" => {} })
    end
    assert_equal :ambiguous_nat, error.code
    error = assert_raises(P::Error) do
      resolver.find("10.0.0.1", zone: "outside", direction: :destination, peers: { "192.0.2.1" => {} })
    end
    assert_equal :conditional_nat, error.code
  end

  def test_disjoint_protocol_and_service_constraints_have_no_common_match
    first = E::DynamicNat.new(**context(:hillstone), id: "9", direction: :source, to_zone: "outside",
                              source_set: "10.0.0.0/24", destination_set: "0.0.0.0/0", protocol: "tcp",
                              service_set: Algosec::IPAddr.service("udp/53"), translated_source_set: "203.0.113.1")
    resolver = P::Nat::Resolver.new(snapshot(:hillstone, [ first ]))
    assert_nil resolver.find("10.0.0.1", zone: "outside", direction: :source,
                             peers: { "192.0.2.1" => {} }, services: { "tcp/443" => {}, "udp/53" => {} })
  end

  def test_partial_nat_stops_search_before_a_new_nat_can_be_designed
    nat = E::DynamicNat.new(**context(:hillstone), id: "9", direction: :source, to_zone: "outside",
                            source_set: "10.0.0.0/25", destination_set: "0.0.0.0/0", translated_source_set: "203.0.113.1")
    snap = snapshot(:hillstone, [ nat ])
    searcher = P::Searcher.new(networks: networks(:hillstone, nat_mode: 1, address_type: :private), snapshots: { 1 => snap })
    report = searcher.perform(sources: [ "10.0.0.0/24" ], destinations: [ "192.0.2.1" ], services: [ "tcp/443" ])
    refute report.success?
    assert_equal :ambiguous_nat, report.error_code
    assert_empty report.results
  end

  def test_partial_translated_service_cannot_fall_through_to_later_destination_nat
    common = { direction: :destination, from_zone: "outside", source_set: "0.0.0.0/0",
               destination_set: "203.0.113.1", translated_destination_set: "10.0.0.1" }
    first = E::DynamicNat.new(**context(:hillstone), **common, id: "9", translated_destination_port: "443")
    later = E::DynamicNat.new(**context(:hillstone), **common, id: "1")
    resolver = P::Nat::Resolver.new(snapshot(:hillstone, [ first, later ]))
    error = assert_raises(P::Error) do
      resolver.find("10.0.0.1", zone: "outside", direction: :destination,
                    peers: { "192.0.2.1" => {} }, services: { "tcp/443-444" => {} })
    end
    assert_equal :ambiguous_nat, error.code
    error = assert_raises(P::Error) do
      resolver.find("10.0.0.1", zone: "outside", direction: :destination,
                    peers: { "192.0.2.1" => {} }, services: { "tcp/444" => {} })
    end
    assert_equal :conditional_nat, error.code
  end

  def test_missing_translation_cannot_fall_through_to_another_source_pool
    common = { direction: :source, to_zone: "outside", source_set: "10.0.0.0/24", destination_set: "0.0.0.0/0" }
    first = E::DynamicNat.new(**context(:hillstone), **common, id: "9")
    later = E::DynamicNat.new(**context(:hillstone), **common, id: "1", translated_source_set: "203.0.113.1")
    resolver = P::Nat::Resolver.new(snapshot(:hillstone, [ first, later ]))
    error = assert_raises(P::Error) do
      resolver.find("10.0.0.1", zone: "outside", direction: :source, peers: { "192.0.2.1" => {} })
    end
    assert_equal :conditional_nat, error.code
  end

  def test_protocol_independent_port_mapping_without_pools
    nat = E::DynamicNat.new(**context(:hillstone), id: "1", direction: :destination,
                            source_set: "0.0.0.0/0", destination_set: "203.0.113.9", translated_destination_set: "10.0.0.9",
                            destination_port: "8443", translated_destination_port: "443", from_zone: "outside")
    resolver = P::Nat::Resolver.new(snapshot(:hillstone, [ nat ]))
    %w[tcp udp].each do |protocol|
      found = resolver.find("10.0.0.9", zone: "outside", direction: :destination,
                            peers: { "192.0.2.1" => {} }, services: { "#{protocol}/443" => { origin: "#{protocol}/8443" } })
      assert found, protocol
      refute resolver.find("10.0.0.9", zone: "outside", direction: :destination,
                           peers: { "192.0.2.1" => {} }, services: { "#{protocol}/443" => { origin: "#{protocol}/9443" } })
    end
    source = E::DynamicNat.new(**context(:hillstone), id: "2", direction: :source, to_zone: "outside",
                               source_set: "10.0.0.9", destination_set: "0.0.0.0/0", translated_source_set: "203.0.113.9",
                               source_port: "1234", translated_source_port: "5678")
    resolver = P::Nat::Resolver.new(snapshot(:hillstone, [ source ]))
    options = { zone: "outside", direction: :source, peers: { "192.0.2.1" => {} } }
    assert resolver.find("10.0.0.9", **options, source_port: "1234", mapped_source_port: "5678")
    assert_equal :conditional_nat, assert_raises(P::Error) { resolver.find("10.0.0.9", **options) }.code
    refute resolver.find("10.0.0.9", **options, source_port: "4321", mapped_source_port: "5678")
  end

  def static_nat(vendor, device_id: 1, **attributes)
    E::StaticNat.new(**context(vendor, device_id: device_id), name: "static", id: "1", rule_set: "static",
                     real_ip: "10.0.0.0/24", mapped_ip: "203.0.113.0/24", real_zone: "inside", mapped_zone: "outside", source_nat_enabled: true,
                     real_set: Algosec::IPAddr.parse("10.0.0.0/24"), mapped_set: Algosec::IPAddr.parse("203.0.113.0/24"), interface: "outside", mask: "24", **attributes)
  end

  def test_static_nat_offsets_and_provenance_for_every_vendor
    VENDORS.each do |vendor|
      nat = static_nat(vendor)
      resolver = P::Nat::Resolver.new(snapshot(vendor, [ nat ]))
      found = resolver.find("10.0.0.42/32", zone: "outside", peers: { "192.0.2.1" => {} }, direction: :source)
      assert_equal "203.0.113.42/32", found[:address], vendor.to_s
      assert_equal :static, found[:type]
      assert_same nat, found[:rule]
      assert_equal [ "10.0.0.64/26", "inside" ], resolver.reverse("203.0.113.64/26")
      assert_nil resolver.find("10.0.1.1", zone: "outside")
      assert_nil resolver.find("10.0.0.1", zone: "other")
      assert resolver.used?("203.0.113.128/25", zone: "outside")
      assert_raises(P::Error) { resolver.reverse("198.51.100.1") }
    end
  end

  def test_reverse_static_nat_checks_partial_overlaps_for_conflicts
    broad = static_nat(:hillstone)
    partial = static_nat(:hillstone, id: "2", real_set: Algosec::IPAddr.parse("10.1.0.0/25"),
                         mapped_set: Algosec::IPAddr.parse("203.0.113.0/25"))
    resolver = P::Nat::Resolver.new(snapshot(:hillstone, [ broad, partial ]))
    assert_equal :ambiguous_nat, assert_raises(P::Error) { resolver.reverse("203.0.113.0/24") }.code
  end

  def test_reverse_static_nat_combines_complete_compatible_segments
    first = static_nat(:hillstone, id: "1", real_set: Algosec::IPAddr.parse("10.0.0.0/25"),
                       mapped_set: Algosec::IPAddr.parse("203.0.113.0/25"))
    second = static_nat(:hillstone, id: "2", real_set: Algosec::IPAddr.parse("10.0.0.128/25"),
                        mapped_set: Algosec::IPAddr.parse("203.0.113.128/25"))
    resolver = P::Nat::Resolver.new(snapshot(:hillstone, [ first, second ]))
    assert_equal [ "10.0.0.0/24", "inside" ], resolver.reverse("203.0.113.0/24")
    assert_equal :ambiguous_nat, assert_raises(P::Error) { resolver.reverse("203.0.113.0/23") }.code
    compatible = P::Nat::Resolver.new(snapshot(:hillstone, [ static_nat(:hillstone, id: "3"), first ]))
    assert_equal [ "10.0.0.0/24", "inside" ], compatible.reverse("203.0.113.0/24")
  end

  def test_reverse_static_nat_compares_mapping_correspondence_not_only_union
    ordinary = static_nat(:hillstone)
    swapped = E::StaticNat.new(**context(:hillstone), id: "2", real_ip: "10.0.0.0/24", mapped_ip: "203.0.113.0/24", real_zone: "inside",
                               mappings: [ [ "10.0.0.128/25", "203.0.113.0/25" ], [ "10.0.0.0/25", "203.0.113.128/25" ] ])
    resolver = P::Nat::Resolver.new(snapshot(:hillstone, [ ordinary, swapped ]))
    assert_equal :ambiguous_nat, assert_raises(P::Error) { resolver.reverse("203.0.113.0/24") }.code
  end

  def test_reverse_static_nat_rejects_mixed_zones_and_disconnected_outputs
    first = static_nat(:hillstone, id: "1", real_set: Algosec::IPAddr.parse("10.0.0.0/25"),
                       mapped_set: Algosec::IPAddr.parse("203.0.113.0/25"))
    [ { real_zone: "dmz", real_set: Algosec::IPAddr.parse("10.0.0.128/25") },
      { real_set: Algosec::IPAddr.parse("10.0.1.128/25") } ].each do |attributes|
      second = static_nat(:hillstone, id: "2", mapped_set: Algosec::IPAddr.parse("203.0.113.128/25"), **attributes)
      resolver = P::Nat::Resolver.new(snapshot(:hillstone, [ first, second ]))
      assert_equal :ambiguous_nat, assert_raises(P::Error) { resolver.reverse("203.0.113.0/24") }.code
    end
  end

  def test_asa_static_nat_partial_peer_and_acl_ranges_are_explicit
    peer_limited = static_nat(:asa, destination_set: Algosec::IPAddr.parse("192.0.2.0/25"))
    acl_limited = static_nat(:asa, acl_name: "nat_acl")
    acl = rule(:asa, rule_set: "nat_acl", source: "10.0.0.0/25", destination: "192.0.2.0/24", services: [ "any" ])
    [ [ peer_limited ], [ acl_limited, acl ] ].each do |objects|
      resolver = P::Nat::Resolver.new(snapshot(:asa, objects))
      error = assert_raises(P::Error) do
        resolver.find("10.0.0.0/24", zone: "outside", direction: :source, peers: { "192.0.2.0/24" => {} })
      end
      assert_equal :ambiguous_nat, error.code
      assert_nil resolver.find("10.0.0.0/24", zone: "outside", direction: :source, peers: { "198.51.100.1" => {} })
    end
  end

  def test_forward_static_nat_does_not_use_names_as_execution_priority
    broad = static_nat(:hillstone, id: "1")
    conflicting = static_nat(:hillstone, id: "2", mapped_set: Algosec::IPAddr.parse("198.51.100.0/24"))
    [ [ broad, conflicting ], [ conflicting, broad ] ].each do |rows|
      resolver = P::Nat::Resolver.new(snapshot(:hillstone, rows))
      error = assert_raises(P::Error) { resolver.find("10.0.0.1", zone: "outside") }
      assert_equal :ambiguous_nat, error.code
    end
  end

  def test_forward_static_nat_does_not_skip_partial_address_or_service_coverage
    matching = rule(:neteye, services: [ "tcp/443" ])
    partial = static_nat(:neteye, match_rule: matching)
    resolver = P::Nat::Resolver.new(snapshot(:neteye, [ partial ]))
    error = assert_raises(P::Error) do
      resolver.find("10.0.0.1", zone: "outside", direction: :source,
                    peers: { "192.0.2.1" => {} }, services: { "tcp/443" => {}, "udp/53" => {} })
    end
    assert_equal :ambiguous_nat, error.code
    resolver = P::Nat::Resolver.new(snapshot(:hillstone, [ static_nat(:hillstone) ]))
    assert_equal :ambiguous_nat, assert_raises(P::Error) { resolver.find("10.0.0.0/23", zone: "outside") }.code
  end

  def test_dynamic_destination_uses_canonical_before_and_after_ranges
    VENDORS.each do |vendor|
      metadata = vendor == :huawei ? { nat_order: [ 0, 1 ], extra_conf: { "match" => { "to_zone" => nil, "interface" => nil } } } : {}
      nat = E::DynamicNat.new(**context(vendor), name: "destination", id: "1", policy_id: "1", rule_set: "destination",
                              acl_name: vendor == :asa ? "" : "nat", direction: :destination, from_zone: "outside", to_zone: "inside",
                              source_set: Algosec::IPAddr.parse("0.0.0.0/0"), destination_set: Algosec::IPAddr.parse("203.0.113.9"),
                              translated_destination_set: Algosec::IPAddr.parse("10.0.0.9"), **metadata)
      resolver = P::Nat::Resolver.new(snapshot(vendor, [ nat ]))
      found = resolver.find("10.0.0.9", zone: "outside", direction: :destination, peers: { "192.0.2.1" => {} }, flow: { from_zone: "outside", to_zone: "inside" })
      assert_equal "203.0.113.9/32", found[:address], vendor.to_s
      assert_same nat, found[:rule]
      assert_nil resolver.find("10.0.0.10", zone: "outside", direction: :destination, peers: { "192.0.2.1" => {} }, flow: { from_zone: "outside", to_zone: "inside" })
    end
  end

  def test_srx_port_constrained_nat_checks_every_service
    pool = E::NatPool.new(**context(:srx), name: "pool", ip: "10.0.0.9", port: 443, direction: :destination)
    nat = E::DynamicNat.new(**context(:srx), name: "nat", direction: :destination, rule_set: "nat", from_zone: "outside",
                            source_set: Algosec::IPAddr.parse("0.0.0.0/0"), destination_set: Algosec::IPAddr.parse("203.0.113.9"), destination_pool: pool)
    resolver = P::Nat::Resolver.new(snapshot(:srx, [ nat, pool ]))
    args = { zone: "outside", direction: :destination, peers: { "192.0.2.1" => {} } }
    assert_equal :conditional_nat, assert_raises(P::Error) { resolver.find("10.0.0.9", **args, services: {}) }.code
    assert_equal :ambiguous_nat, assert_raises(P::Error) { resolver.find("10.0.0.9", **args, services: { "tcp/443" => {}, "udp/53" => {} }) }.code
    assert_equal "203.0.113.9/32", resolver.find("10.0.0.9", **args, services: { "tcp/443" => {}, "udp/443" => {} })[:address]
  end

  def test_destination_mapping_and_asa_version_boundary
    VENDORS.each do |vendor|
      config = snapshot(vendor, version: "9.1")
      mapper = P::Nat::Translator.build(config)
      entry = { origin: "10.0.0.9/32", private: "10.0.0.9/32", nat: { type: :static, address: "203.0.113.9/32" } }
      input = { "10.0.0.9/32" => entry }
      result, = mapper.map(input, side: :destination, hit: :destination, mode: 1, zone: "outside",
                           peers: { "192.0.2.1/32" => {} }, services: { "tcp/443" => {} })
      private_policy = %i[asa srx huawei topsec].include?(vendor)
      assert_equal [ private_policy ? "10.0.0.9/32" : "203.0.113.9/32" ], result.keys, vendor.to_s
      assert_equal :new_nat, result.values.first[:action]
      assert_equal "10.0.0.9/32", result.values.first[:real_ip]
      refute entry.key?(:action)
      refute_same entry[:nat], result.values.first[:nat]
    end
    %w[8.2 8.3 9.0].each do |version|
      mapper = P::Nat::Translator.build(snapshot(:asa, [ static_nat(:asa) ], version: version))
      result, = mapper.map({ "203.0.113.9/32" => { origin: "203.0.113.9/32", main: "203.0.113.9/32" } },
                           side: :destination, hit: :destination, mode: 1, zone: "outside", peers: {}, services: {})
      assert_equal [ (version == "8.2") ? "203.0.113.9/32" : "10.0.0.9/32" ], result.keys
    end
  end

  def test_default_source_nat_and_interface_metadata_are_per_address
    mapper = P::Nat::Translator.build(snapshot(:h3c))
    input = %w[10.0.0.1/32 10.0.0.2/32].to_h { |address| [ address, { origin: address, private: address } ] }
    result, = mapper.map(input, side: :source, hit: :source, mode: 1, zone: "outside", peers: { "192.0.2.1" => {} }, services: {})
    result.each_value do |entry|
      assert_equal :dynamic, entry[:nat][:type]
      assert_equal "outside", entry[:nat][:interface]
      assert_equal :new_nat, entry[:action]
    end
    refute_same(*result.values.map { |entry| entry[:nat] })
    assert input.values.none? { |entry| entry.key?(:nat) }
  end

  def test_cross_device_search_uses_external_source_only_on_remote_device
    first = snapshot(:hillstone, [ static_nat(:hillstone) ])
    second = snapshot(:hillstone, [], device_id: 2)
    rows = networks(:hillstone, nat_mode: 1, address_type: :private)
    rows.concat([
                  { device_id: 2, device_name: "remote", vendor: :hillstone, nat_mode: 0, zone: "inside", protected: true, address: "192.0.2.0/24" },
                  { device_id: 2, device_name: "remote", vendor: :hillstone, nat_mode: 0, zone: "outside", protected: false, address: "0.0.0.0/0" }
                ])
    searcher = P::Searcher.new(networks: rows, snapshots: { 1 => first, 2 => second })
    report = searcher.perform(sources: [ "10.0.0.9" ], destinations: [ "192.0.2.9" ], services: [ "tcp/443" ])
    assert report.success?, report.comment
    assert_equal 2, report.results.size
    assert_equal [ "10.0.0.9/32" ], report.results.find { |result| result.device_id == 1 }.sources.keys
    assert_equal [ "203.0.113.9/32" ], report.results.find { |result| result.device_id == 2 }.sources.keys
    assert_nil report.results.find { |result| result.device_id == 2 }.sources.values.first[:nat]
  end

  def test_static_nat_search_continues_after_an_unmatched_asa_acl
    wrong = static_nat(:asa, mapped_ip: "198.51.100.0/24", mapped_set: Algosec::IPAddr.parse("198.51.100.0/24"), acl_name: "blocked")
    correct = static_nat(:asa, acl_name: "allowed")
    acl = rule(:asa, rule_set: "allowed", services: [ "any" ])
    unrelated = rule(:asa, rule_set: "blocked", source: "10.1.0.0/24", services: [ "any" ])
    resolver = P::Nat::Resolver.new(snapshot(:asa, [ wrong, correct, unrelated, acl ]))
    found = resolver.find("10.0.0.9", zone: "outside", peers: { "192.0.2.1" => {} }, direction: :source)
    assert_same correct, found[:rule]
    assert_equal "203.0.113.0/24", found[:address]
    acl.action = "deny"
    error = assert_raises(P::Error) { resolver.find("10.0.0.9", zone: "outside", peers: { "192.0.2.1" => {} }, direction: :source) }
    assert_equal :conditional_nat, error.code
  end

  def test_srx_query_matches_internal_port_and_retains_the_external_mapping
    pool = E::NatPool.new(**context(:srx), name: "pool", ip: "10.0.0.9", port: 8443, direction: :destination)
    nat = E::DynamicNat.new(**context(:srx), name: "nat", direction: :destination, rule_set: "nat", from_zone: "outside",
                            source_set: Algosec::IPAddr.parse("0.0.0.0/0"), destination_set: Algosec::IPAddr.parse("203.0.113.9"), destination_pool: pool,
                            service_set: Algosec::IPAddr.service("tcp/443"), translated_service_set: Algosec::IPAddr.service("tcp/8443"))
    existing = rule(:srx, source: "192.0.2.1/32", destination: "10.0.0.9/32", services: [ "tcp/8443" ], from_zones: "outside", to_zones: "inside")
    config = snapshot(:srx, [ nat, pool, existing ])
    rows = networks(:srx, nat_mode: 1, address_type: :private)
    searcher = P::Searcher.new(networks: rows, snapshots: { 1 => config })
    report = searcher.perform(sources: [ "192.0.2.1" ], destinations: [ "10.0.0.9" ], services: [ { services: [ "tcp/443" ], translated_port: 8443 } ])
    assert report.success?, report.comment
    result = report.results.fetch(0)
    assert_equal :ignore, result.type
    assert_equal [ "tcp/8443" ], result.services.keys
    assert_equal "tcp/443", result.services.fetch("tcp/8443")[:origin]
    assert report.complete?, report.skipped.inspect
    assert_same nat, result.destinations.values.first[:nat][:rule]
    assert_empty Algosec::Vendors::Srx::Generator.new(result).perform
    wrong_port = searcher.perform(sources: [ "192.0.2.1" ], destinations: [ "10.0.0.9" ], services: [ { services: [ "udp/443" ], translated_port: 8443 } ])
    refute wrong_port.success?
    assert_empty wrong_port.results
    plain = P::Searcher.new(networks: networks(:srx), snapshots: { 1 => snapshot(:srx) })
    invalid = plain.perform(sources: [ "10.0.0.1" ], destinations: [ "192.0.2.1" ], services: [ { services: [ "tcp/443" ], translated_port: 8443 } ])
    assert_equal :nat_missing, invalid.error_code
  end

  def test_neteye_unrestricted_mip_does_not_become_an_empty_peer_constraint
    match_rule = E::SecurityRule.new(**context(:neteye), native_rule_id: "mip")
    nat = static_nat(:neteye, match_rule: match_rule)
    resolver = P::Nat::Resolver.new(snapshot(:neteye, [ nat ]))
    assert_equal "203.0.113.9/32", resolver.find("10.0.0.9", zone: "outside", peers: { "192.0.2.1" => {} }, direction: :destination)[:address]
    assert_nil resolver.find("10.0.0.9", zone: "outside", peers: { "192.0.2.1" => {} }, direction: :destination,
                             services: { "tcp/443" => { origin: "tcp/443", translated_port: "8443" } })
  end

  def test_port_fields_constrain_nat_even_without_a_materialized_service_set
    nat = E::DynamicNat.new(**context(:fortinet), name: "VIP", direction: :destination, from_zone: "outside",
                            source_set: Algosec::IPAddr.parse("0.0.0.0/0"), destination_set: Algosec::IPAddr.parse("203.0.113.9"),
                            translated_destination_set: Algosec::IPAddr.parse("10.0.0.9"), destination_port: 443, translated_destination_port: 8443, protocol: "tcp")
    resolver = P::Nat::Resolver.new(snapshot(:fortinet, [ nat ]))
    arguments = { zone: "outside", peers: { "192.0.2.1" => {} }, direction: :destination }
    services = { "tcp/443" => { origin: "tcp/443", translated_port: "8443" } }
    assert_same nat, resolver.find("10.0.0.9", **arguments, services: services)[:rule]
    assert_nil resolver.find("10.0.0.9", **arguments, services: { "udp/443" => { origin: "udp/443", translated_port: "8443" } })
  end
end
