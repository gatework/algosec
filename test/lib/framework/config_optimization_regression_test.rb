# frozen_string_literal: true

require "minitest/autorun"
require "algosec"
require "algosec/dns_resolver"

class ConfigOptimizationRegressionTest < Minitest::Test
  E = Algosec::Elements

  def test_partial_source_does_not_hide_a_disjoint_destination_or_interface
    route = E::Route.new(kind: :policy, source: "10.0.0.0/25", subnet: "192.0.2.0/24", source_interface: "inside")
    fallback = E::Route.new(subnet: "0.0.0.0/0", next_hop: "203.0.113.1")
    table = E::RoutingTable.new([ route, fallback ])

    assert_same fallback, table.lookup(source: "10.0.0.0/24", destination: "198.51.100.1", source_interface: "inside")
    assert_same fallback, table.lookup(source: "10.0.0.0/24", destination: "192.0.2.1", source_interface: "outside")
    assert_raises(E::RoutingTable::ConditionalRoute) do
      table.lookup(source: "10.0.0.0/24", destination: "192.0.2.1", source_interface: "inside")
    end
  end

  def test_missing_destination_reference_cannot_match_a_policy_route
    missing = E::AddressGroup.new(name: "destinations", members: { "absent" => nil })
    route = E::Route.new(kind: :policy, source: "10.0.0.0/24", destinations: missing)

    assert_equal :unknown, route.policy_match(source: "10.0.0.1", destination: "192.0.2.1")
    assert_equal :miss, route.policy_match(source: "10.1.0.1", destination: "192.0.2.1")
    assert_raises(E::RoutingTable::ConditionalRoute) do
      E::RoutingTable.new([ route ]).lookup(source: "10.0.0.1", destination: "192.0.2.1")
    end
  end

  def test_pbr_partial_source_keeps_definitive_binding_and_service_misses
    route = pbr_route

    assert_equal :miss, route.policy_match(**traffic(source_zone: "outside"))
    assert_equal :miss, route.policy_match(**traffic(destination_port: "80"))
    assert_equal :unknown, route.policy_match(**traffic)
    assert_equal :match, route.policy_match(**traffic(source: "10.0.0.1"))
  end

  def test_policy_route_does_not_repeatedly_expand_its_source_group
    route = pbr_route
    reads = 0
    original = route.sources.method(:address_projection)
    route.sources.define_singleton_method(:address_projection) { reads += 1; original.call }

    assert_equal :match, route.policy_match(**traffic(source: "10.0.0.1"))
    assert_operator reads, :<=, 2
  end

  def test_pbr_service_metadata_stays_unknown_without_its_match_context
    route = pbr_route
    route.services.replace("https", E::ServiceObject.new(name: "https", protocol: "tcp", destination_port: "443", uuid: "application"))

    assert_equal :unknown, route.policy_match(**traffic(source: "10.0.0.1"))
    assert_equal :miss, route.policy_match(**traffic(source_zone: "outside"))
    assert_equal :miss, route.policy_match(**traffic(protocol: "udp", destination_port: "53"))
  end

  def test_route_dependencies_cannot_come_from_another_device_or_vendor
    [ { vendor: :fortinet, device_id: 2 }, { vendor: :asa, device_id: 1 } ].each do |foreign|
      { sources: E::AddressGroup, destinations: E::AddressGroup, services: E::ServiceGroup }.each do |attribute, type|
        dependency = type.new(name: "foreign", **foreign)

        assert_raises(ArgumentError, "#{attribute}: #{foreign.inspect}") do
          E::Route.new(kind: :policy, vendor: :fortinet, device_id: 1, attribute => dependency)
        end
      end
    end
  end

  def test_dns_cache_restores_immutable_evidence_without_another_lookup
    now = Time.utc(2026, 10, 13)
    store = ActiveSupport::Cache::MemoryStore.new
    calls = 0
    options = { device_id: 1, servers: [ "192.0.2.53" ], store: store, clock: -> { now },
      transport: ->(*) { calls += 1; [ [ "192.0.2.1" ], 60 ] } }
    first = Algosec::DnsResolver.new(**options).resolve("example.test")
    resolver = Algosec::DnsResolver.new(**options)
    cached = resolver.resolve("EXAMPLE.test.")

    assert_equal first, cached
    assert_equal 1, calls
    assert_same cached, resolver.resolve("example.test")
    [ first, cached ].each do |answer|
      assert_raises(FrozenError) { answer["status"] = "unresolved" }
      assert_raises(FrozenError) { answer.fetch("addresses") << "192.0.2.2" }
      assert_raises(FrozenError) { answer.fetch("addresses").first.replace("192.0.2.2") }
      assert_raises(FrozenError) { answer.fetch("source").fetch("servers").first.replace("192.0.2.54") }
      assert_raises(FrozenError) { answer.fetch("expires_at").replace((now + 600).iso8601) }
    end

    now += 61
    resolver.resolve("example.test")
    assert_equal 2, calls
  end

  def test_failed_dns_cache_evidence_stays_failed_until_its_retry_time
    now = Time.utc(2026, 10, 13)
    store = ActiveSupport::Cache::MemoryStore.new
    calls = 0
    options = { device_id: 1, servers: [ "192.0.2.53" ], store: store, clock: -> { now },
      transport: ->(*) { calls += 1; raise Resolv::ResolvTimeout, "timeout" } }
    first = Algosec::DnsResolver.new(**options).resolve("example.test")
    cached = Algosec::DnsResolver.new(**options).resolve("example.test")

    assert_equal "unresolved", cached.fetch("status")
    assert_equal first, cached
    assert_equal 1, calls
    assert_raises(FrozenError) { cached.fetch("error").replace("success") }
    now += Algosec::DnsResolver::FAILURE_TTL + 1
    Algosec::DnsResolver.new(**options).resolve("example.test")
    assert_equal 2, calls
  end

  private

  def pbr_route
    sources = E::AddressGroup.new(name: "sources", members: {
      "clients" => E::AddressObject.new(name: "clients", member: [ { type: "subnet", value: "10.0.0.0/25" } ])
    })
    destinations = E::AddressGroup.new(name: "destinations", members: {
      "servers" => E::AddressObject.new(name: "servers", member: [ { type: "subnet", value: "192.0.2.0/24" } ])
    })
    services = E::ServiceGroup.new(name: "services", members: {
      "https" => E::ServiceObject.new(name: "https", protocol: "tcp", destination_port: "443")
    })
    E::Route.new(kind: :policy, sources: sources, destinations: destinations, services: services,
      next_hop: "203.0.113.1", destination_interface: "outside",
      extra_conf: { pbr: { bindings: [ { type: "zone", name: "inside" } ], services: [ "https" ] } })
  end

  def traffic(**overrides)
    { source: "10.0.0.0/24", destination: "192.0.2.1", source_zone: "inside",
      protocol: "tcp", source_port: "1024", destination_port: "443" }.merge(overrides)
  end
end
