# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "../framework/support/policy_factory"
require "algosec/policy/nat/service_query"

class NatServiceQueryTest < Minitest::Test
  include PolicyFactory

  def test_literal_protocol_zero_is_distinct_from_legacy_any
    zero = Algosec::Set.new(0..65_535)
    native = nat("zero", service_set: zero, nat_order: [ 1 ])
    baseline = snapshot(:palo_alto, [ native, nat("fallback", nat_order: [ 2 ]) ])
    query = P::Nat::ServiceQuery.new(pairs: [ [ zero, zero ] ])
    assert_same native, resolve(baseline, query).fetch(:rule)
    assert_raises(P::Error) { resolve(baseline, { "0" => {} }) }
    assert_raises(P::Error) { resolve(baseline, { "any" => {} }) }
  end

  def test_service_hole_excludes_only_tcp_443_and_preserves_other_protocols
    first = nat("first", service_set: Algosec::IPAddr.service("tcp/443"), nat_order: [ 1 ])
    fallback = nat("fallback", nat_order: [ 2 ])
    baseline = snapshot(:palo_alto, [ first, fallback ])
    all = Algosec::IPAddr.service("any")
    hole = all - Algosec::IPAddr.service("tcp/443")
    query = P::Nat::ServiceQuery.new(pairs: [ [ hole, hole ] ])
    assert query.original_set.include?(0)
    assert query.original_set.include?((17 << 16) + 443)
    refute query.original_set.include?((6 << 16) + 443)
    assert_same fallback, resolve(baseline, query).fetch(:rule)
    assert_raises(P::Error) { resolve(baseline, { "any" => {} }) }
  end

  def test_typed_query_retains_native_first_match_and_source_port_terms
    requested = Algosec::IPAddr.service("tcp/443")
    query = P::Nat::ServiceQuery.new(pairs: [ [ requested, requested ] ])
    first = nat("first", nat_order: [ 1 ])
    second = nat("second", service_set: requested, nat_order: [ 2 ])
    assert_same first, resolve(snapshot(:palo_alto, [ first, second ]), query).fetch(:rule)
    service = E::ServiceObject.new(**context(:palo_alto), name: "restricted", protocol: "tcp", source_port: "1024-2047", destination_port: "443")
    constrained = nat("restricted", service_set: requested, references: [ service ], nat_order: [ 1 ])
    baseline = snapshot(:palo_alto, [ constrained ])
    assert_raises(P::Error) { resolve(baseline, query) }
    assert_same constrained, resolve(baseline, query, source_port: "1024-2047").fetch(:rule)
  end

  def test_typed_service_pairs_are_owned_immutable_and_validate_ranges
    values = [ [ Algosec::IPAddr.service("tcp/443"), Algosec::IPAddr.service("tcp/8443") ] ]
    query = P::Nat::ServiceQuery.new(pairs: values)
    values.clear
    assert_equal 1, query.pairs.size
    assert query.translation?
    assert_predicate query, :frozen?
    assert JSON.generate(query.to_h)
    assert_raises(ArgumentError) { P::Nat::ServiceQuery.new(pairs: [ [ "any", "any" ] ]) }
    assert_raises(ArgumentError) { P::Nat::ServiceQuery.new(pairs: [ [ Algosec::IPAddr.service("tcp/443"), Algosec::IPAddr.service("udp/443") ] ]) }
    assert_raises(ArgumentError) { P::Nat::ServiceQuery.new(pairs: [ [ Algosec::Set.new(0..(1 << 32)), Algosec::Set.new ] ]) }
  end

  def test_interval_budget_applies_across_all_pairs
    service = Algosec::IPAddr.service("tcp/443")
    pairs = Array.new(P::TrafficSet::DEFAULT_LIMIT / 2 + 1) { [ service, service ] }
    assert_raises(P::TrafficSet::LimitExceeded) { P::Nat::ServiceQuery.new(pairs: pairs) }
  end

  def test_restrict_keeps_each_protocols_port_offset
    before = Algosec::IPAddr.service("tcp/443-444") | Algosec::IPAddr.service("udp/53-54")
    after = Algosec::IPAddr.service("tcp/8443-8444") | Algosec::IPAddr.service("udp/5353-5354")
    selected = Algosec::IPAddr.service("tcp/444") | Algosec::IPAddr.service("udp/53")
    query = P::Nat::ServiceQuery.new(pairs: [ [ before, after ] ]).restrict(selected)

    assert_equal selected, query.pairs.sole.original
    assert_equal Algosec::IPAddr.service("tcp/8444") | Algosec::IPAddr.service("udp/5353"), query.pairs.sole.translated
  end

  def test_restrict_preserves_constant_mapping_and_holes_in_offset_mapping
    before = Algosec::IPAddr.service("tcp/443") | Algosec::IPAddr.service("tcp/445")
    after = Algosec::IPAddr.service("tcp/8443") | Algosec::IPAddr.service("tcp/8445")
    selected = Algosec::IPAddr.service("tcp/445")
    query = P::Nat::ServiceQuery.new(pairs: [ [ before, after ] ]).restrict(selected)
    assert_equal Algosec::IPAddr.service("tcp/8445"), query.pairs.sole.translated

    constant = Algosec::IPAddr.service("tcp/9000")
    query = P::Nat::ServiceQuery.new(pairs: [ [ before, constant ] ]).restrict(selected)
    assert_equal constant, query.pairs.sole.translated
  end

  def test_unrestricted_icmp_type_zero_selects_first_nat_instead_of_fallback
    %w[icmp icmpv6].each do |protocol|
      service = E::ServiceObject.new(**context(:palo_alto), name: "messages", protocol: protocol, destination_port: "1-65535")
      first = nat("first", service_set: service.set, references: [ service ], nat_order: [ 1 ])
      baseline = snapshot(:palo_alto, [ first, nat("fallback", nat_order: [ 2 ]) ])
      type_zero = Algosec::IPAddr.service("#{protocol}/0")
      query = P::Nat::ServiceQuery.new(pairs: [ [ type_zero, type_zero ] ])

      assert_same first, resolve(baseline, query).fetch(:rule)
      assert_same first, resolve(baseline, { protocol => {} }).fetch(:rule)
    end
  end

  private

  def nat(name, **options)
    E::DynamicNat.new(**context(:palo_alto), name: name, direction: :source, from_zone: "inside", to_zone: "outside",
      source_set: "10.0.0.1", destination_set: "192.0.2.1", nat_type: "dynamic-ip-and-port", translated_source_set: "203.0.113.1", **options)
  end

  def resolve(baseline, services, source_port: nil)
    P::Nat::Resolver.new(baseline).find("10.0.0.1", zone: "outside", direction: :source,
      peers: { "192.0.2.1" => {} }, services: services, source_port: source_port, flow: { from_zone: "inside", to_zone: "outside" },
      allocation: { type: :dynamic, address: "203.0.113.1" })
  end
end
