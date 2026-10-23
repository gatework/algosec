# frozen_string_literal: true

require "minitest/autorun"
require "algosec"
require "algosec/policy"

class AlgosecPolicyTest < Minitest::Test
  Elements = Algosec::Elements
  Policy = Algosec::Policy

  def test_route_index_matches_source_policy_routes_without_a_destination
    static = Elements::Route.new(vendor: :hillstone, subnet: "192.0.2.0/24", zone: "outside")
    policy = Elements::Route.new(vendor: :hillstone, kind: :policy, name: "policy",
                                 source: "10.0.0.0/24", zone: "policy")
    snapshot = cache([ static, policy ], vendor: :hillstone)

    assert_equal "policy", Policy::NetworkLocator.new([]).route_zone("192.0.2.1", snapshot: snapshot,
                                                                      zones: %w[outside policy], source: "10.0.0.1")
    assert_equal "outside", Policy::NetworkLocator.new([]).route_zone("192.0.2.1", snapshot: snapshot,
                                                                      zones: %w[outside policy], source: "10.1.0.1")
  end

  def test_route_index_supports_host_routes_without_an_explicit_mask
    route = Elements::Route.new(vendor: :topsec, subnet: "192.0.2.1/32", zone: "host")
    snapshot = cache([ route ], vendor: :topsec)

    assert_equal "host", Policy::NetworkLocator.new([]).route_zone("192.0.2.1", snapshot: snapshot,
                                                                   zones: [ "host" ])
  end

  def test_cache_deduplicates_builtin_and_catalog_services_by_identity
    configured = Elements::ServiceObject.new(name: "web", vendor: :hillstone, device_id: 1,
                                       protocol: "tcp", destination_port: "443")
    builtin = Elements::ServiceObject.new(name: "web", vendor: :hillstone, device_id: 1,
                                    protocol: "tcp", destination_port: "443")
    snapshot = cache([ configured ], vendor: :hillstone, builtin_services: [ builtin ])

    assert_equal [ builtin.identity ], snapshot.services.map(&:identity)
  end

  def test_policy_boundaries_reject_invalid_enum_and_numeric_inputs
    assert_raises(ArgumentError) do
      Policy::Request.new(
        sources: [ { addresses: [ "10.0.0.1" ], nat: { type: 1 } } ],
        destinations: [ "192.0.2.1" ], services: [ "tcp/443" ]
      )
    end

    result_attributes = {
      device_id: 1, device_name: "firewall", vendor: :hillstone,
      from_zone: "inside", to_zone: "outside", type: :new, hit: :source,
      sources: { "10.0.0.1/32" => {} }, destinations: { "192.0.2.1/32" => {} },
      services: { "tcp/443" => {} }, actions: { new: {} }
    }
    assert_raises(ArgumentError) { Policy::Result.new(**result_attributes.merge(nat_mode: "1")) }
    assert_raises(ArgumentError) { Policy::Result.new(**result_attributes.merge(type: :ignore, rule: Object.new)) }
    assert_raises(ArgumentError) { Policy::Result.new(**result_attributes.merge(schedule: Object.new)) }

    assert_raises(ArgumentError) do
      Policy::NetworkLocator.new([]).matches("10.0.0.1", device_id: 1, protected: "true")
    end

    assert_raises(ArgumentError) do
      Policy::Searcher.new(networks: [], snapshots: {}).device_info(nil)
    end
  end

  private

  def cache(elements, vendor:, builtin_services: [])
    catalog = Elements::Catalog.new(elements, vendor: vendor, device_id: 1)
    Policy::Snapshot.new(device_id: 1, vendor: vendor, catalog: catalog, builtin_services: builtin_services)
  end
end
