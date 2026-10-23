# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "support/policy_factory"

class PolicyDomainHardeningTest < Minitest::Test
  include PolicyFactory

  def test_static_route_disambiguation_preserves_more_specific_partial_routes
    routes = [ E::Route.new(**context(:hillstone), subnet: "192.0.2.0/24", zone: "outside"),
               E::Route.new(**context(:hillstone), subnet: "192.0.2.0/25", zone: "narrow") ]
    config = snapshot(:hillstone, routes)
    locator = P::NetworkLocator.new([])

    error = assert_raises(P::Error) do
      locator.route_zone("192.0.2.0/24", snapshot: config, zones: %w[outside narrow])
    end
    assert_equal :conditional_route, error.code
    assert_equal "narrow", locator.route_zone("192.0.2.1", snapshot: config, zones: %w[outside narrow])
    assert_equal "outside", locator.route_zone("192.0.2.129", snapshot: config, zones: %w[outside narrow])
  end

  def test_static_route_zone_filter_does_not_select_a_less_specific_route
    routes = [ E::Route.new(**context(:hillstone), subnet: "192.0.2.0/24", zone: "outside"),
               E::Route.new(**context(:hillstone), subnet: "192.0.2.1/32", zone: "elsewhere") ]
    config = snapshot(:hillstone, routes)

    assert_nil P::NetworkLocator.new([]).route_zone("192.0.2.1", snapshot: config, zones: [ "outside" ])
  end

  def test_static_route_disambiguation_retains_external_router_vrf_escape
    routes = [ E::Route.new(**context(:hillstone), subnet: "192.0.2.0/24", zone: "outside", vrf: "tenant"),
               E::Route.new(**context(:hillstone), subnet: "192.0.2.1/32", zone: "exrouter", vrf: "external") ]
    config = snapshot(:hillstone, routes)

    assert_equal "exrouter", P::NetworkLocator.new([]).route_zone("192.0.2.1", snapshot: config, zones: [ "outside" ], vrf: "tenant")
  end

  def test_external_router_escape_excludes_unrelated_vrfs
    routes = [ E::Route.new(**context(:hillstone), subnet: "192.0.2.0/24", zone: "outside", vrf: "tenant"),
               E::Route.new(**context(:hillstone), subnet: "192.0.2.0/25", zone: "exrouter", vrf: "external"),
               E::Route.new(**context(:hillstone), subnet: "192.0.2.1/32", zone: "unrelated", vrf: "other") ]
    config = snapshot(:hillstone, routes)
    locator = P::NetworkLocator.new([])

    assert_equal "exrouter", locator.route_zone("192.0.2.1", snapshot: config, zones: %w[outside unrelated], vrf: "tenant")
    assert_equal "outside", locator.route_zone("192.0.2.129", snapshot: config, zones: %w[outside unrelated], vrf: "tenant")
    error = assert_raises(P::Error) do
      locator.route_zone("192.0.2.0/24", snapshot: config, zones: %w[outside unrelated], vrf: "tenant")
    end
    assert_equal :conditional_route, error.code
  end

  def test_static_route_ties_preserve_forwarding_ambiguity
    routes = [ E::Route.new(**context(:hillstone), name: "z", subnet: "192.0.2.0/24", zone: "outside"),
               E::Route.new(**context(:hillstone), name: "a", subnet: "192.0.2.0/24", zone: "other") ]
    config = snapshot(:hillstone, routes)

    error = assert_raises(P::Error) do
      P::NetworkLocator.new([]).route_zone("192.0.2.1", snapshot: config, zones: %w[outside other])
    end
    assert_equal :conditional_route, error.code
  end

  def test_nat_generation_does_not_reuse_a_currently_resolved_domain_as_a_fixed_host
    address = E::AddressObject.new(**context(:topsec), name: "dynamic_host", member: [ { type: "domain", value: "host.example.test" } ])
    answer = { "status" => "resolved", "addresses" => [ "10.0.0.1" ], "expires_at" => (Time.current + 3600).iso8601 }
    resolver = Object.new
    resolver.define_singleton_method(:resolve) { |_domain| answer }
    address.resolve_domains!(resolver)
    assert address.resolved?
    assert address.conditional?

    commands = nat_commands([ address ])

    refute_includes commands, "dynamic_host"
    assert_includes commands, "orig-src 'Host_10.0.0.1 '"
    assert_includes commands, "define host add name Host_10.0.0.1"
  end

  def test_nat_generation_skips_unresolved_objects_before_reusing_an_exact_host
    unresolved = E::AddressObject.new(**context(:topsec), name: "a_unresolved", member: [ { type: "domain", value: "host.example.test" } ])
    exact = E::AddressObject.new(**context(:topsec), name: "z_exact", member: [ { type: "host", value: "10.0.0.1" } ])

    commands = nat_commands([ unresolved, exact ])

    assert_includes commands, "orig-src 'z_exact '"
    refute_includes commands, "define host add name Host_10.0.0.1"
  end

  def test_dynamic_nat_without_peer_context_remains_unknown
    nat = E::DynamicNat.new(**context(:hillstone), id: "1", direction: :source, to_zone: "outside",
                            source_set: "10.0.0.0/24", destination_set: "192.0.2.0/24", translated_source_set: "203.0.113.1")
    resolver = P::Nat::Resolver.new(snapshot(:hillstone, [ nat ]))

    error = assert_raises(P::Error) { resolver.find("10.0.0.1", zone: "outside", direction: :source) }
    assert_equal :conditional_nat, error.code
    assert_nil resolver.find("10.0.1.1", zone: "outside", direction: :source)
    assert_same nat, resolver.find("10.0.0.1", zone: "outside", direction: :source, peers: { "192.0.2.1" => {} })[:rule]
  end

  def test_request_rejects_duplicate_normalized_fields_instead_of_overwriting_them
    assert_raises(ArgumentError) do
      P::Request.new(sources: [ { addresses: [ "10.0.0.1" ], "addresses" => [ "10.0.0.2" ] } ],
                     destinations: [ "192.0.2.1" ], services: [ "tcp/443" ])
    end
  end

  private

  def nat_commands(objects)
    record = { origin: "10.0.0.1", real_ip: "10.0.0.1", nat: { type: :static, address: "203.0.113.1" } }
    result = P::Result.new(**group(:topsec), type: :ignore, snapshot: snapshot(:topsec, objects),
                           actions: { new: { nat_sources: { "10.0.0.1" => record } } })
    P::Planner.new(P::Report.new(results: [ result ])).perform.first[:policy_contents].first[:new][:content]
  end
end
