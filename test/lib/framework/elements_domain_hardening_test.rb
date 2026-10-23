# frozen_string_literal: true

require_relative "../../test_helper"

class ElementsDomainHardeningTest < Minitest::Test
  E = Algosec::Elements

  def test_icmp_coverage_accepts_equivalent_full_ranges_without_accepting_restricted_types
    source = E::AddressObject.new(name: "source", member: [ { type: "subnet", value: "192.0.2.1" } ])
    destination = E::AddressObject.new(name: "destination", member: [ { type: "subnet", value: "198.51.100.1" } ])
    %w[icmp icmpv6].each do |protocol|
      [ [ "0-65535", true ], [ "0 65535", true ], [ "65535-0", true ],
        [ "1-65535", true ], [ "1 65535", true ], [ "8", false ], [ "8-9", false ] ].each do |ports, expected|
        service = E::ServiceObject.new(name: "messages", protocol: protocol, destination_port: ports)
        rule = E::SecurityRule.new(name: "messages", sources: E::AddressGroup.new(name: "sources", members: { source.name => source }),
          destinations: E::AddressGroup.new(name: "destinations", members: { destination.name => destination }),
          services: E::ServiceGroup.new(name: "services", members: { service.name => service }))

        assert_equal expected, rule.covers?(source: "192.0.2.1", destination: "198.51.100.1", service: "#{protocol}/8"),
                     "#{protocol}/#{ports}"
        assert_equal expected, rule.covers?(source: "192.0.2.1", destination: "198.51.100.1", service: "#{protocol}/0"),
                     "#{protocol}/#{ports} must preserve the unrestricted type marker"
      end
    end
  end

  def test_icmp_projection_classifies_equivalent_type_ranges_consistently
    %w[icmp icmpv6].each do |protocol|
      [ [ "0-65535", false ], [ "0 65535", false ], [ "65535-0", false ],
        [ "1-65535", false ], [ "1 65535", false ], [ "65535-1", false ], [ "8", true ] ].each do |ports, conditional|
        service = E::ServiceObject.new(name: "messages", protocol: protocol, destination_port: ports)
        group = E::ServiceGroup.new(name: "messages", members: { service.name => service })

        [ service, group ].each do |object|
          assert_equal conditional, object.service_projection.dig(:resolution, "conditional"), "#{protocol}/#{ports}"
        end
      end
    end
  end

  def test_service_definition_equality_uses_effective_icmp_types_without_erasing_restrictions
    %w[icmp icmpv6].each do |protocol|
      marked = E::ServiceObject.new(name: "marked", protocol: protocol, destination_port: "1-65535")
      full = E::ServiceObject.new(name: "full", protocol: protocol, destination_port: "0-65535")
      restricted = E::ServiceObject.new(name: "restricted", protocol: protocol, destination_port: "8")

      assert marked.same_definition?(full)
      refute marked.same_definition?(restricted)
      assert_equal "1-65535", marked.terms.sole.fetch(:destination_port)
    end
    tcp = E::ServiceObject.new(name: "tcp", protocol: "tcp", destination_port: "1-65535")
    refute tcp.same_definition?(E::ServiceObject.new(name: "tcp", protocol: "tcp", destination_port: "0-65535"))
  end

  def test_rule_coverage_does_not_drop_service_source_port_uuid_or_timeout_conditions
    source = E::AddressObject.new(name: "source", member: [ { type: "subnet", value: "192.0.2.1" } ])
    destination = E::AddressObject.new(name: "destination", member: [ { type: "subnet", value: "198.51.100.1" } ])
    [ { source_port: "1000-2000" }, { uuid: "rpc-identifier" }, { timeout: "60" } ].each do |restriction|
      service = E::ServiceObject.new(name: "restricted", protocol: "tcp", destination_port: "443", **restriction)
      rule = E::SecurityRule.new(name: "restricted", sources: E::AddressGroup.new(name: "sources", members: { source.name => source }),
        destinations: E::AddressGroup.new(name: "destinations", members: { destination.name => destination }),
        services: E::ServiceGroup.new(name: "services", members: { service.name => service }))

      refute rule.covers?(source: "192.0.2.1", destination: "198.51.100.1", service: "tcp/443"), restriction.inspect
      rule.services.add("unrestricted", E::ServiceObject.new(name: "unrestricted", protocol: "tcp", destination_port: "443"))
      assert rule.covers?(source: "192.0.2.1", destination: "198.51.100.1", service: "tcp/443")
    end
  end

  def test_any_service_rejects_port_restrictions_before_mutating_terms
    service = E::ServiceObject.new(name: "any", protocol: "any")
    [ "any", "0" ].each do |protocol|
      [ { destination_port: "443" }, { source_port: "1024", destination_port: "0-65535" } ].each do |ports|
        assert_raises(ArgumentError) { E::ServiceObject.new(name: "restricted-any", protocol: protocol, **ports) }
        assert_raises(ArgumentError) { service.add(protocol: protocol, **ports) }
      end
    end
    assert_equal 1, service.terms.size
    assert service.matches?(protocol: "udp", source_port: "12345", destination_port: "53")
  end

  def test_static_nat_retains_match_rule_dependencies_for_reference_counts_and_dns_refresh
    address = E::AddressObject.new(name: "client", member: [ { type: "domain", value: "client.example.test" } ])
    service = E::ServiceObject.new(name: "https", protocol: "tcp", destination_port: "443")
    schedule = E::Schedule.new(name: "window", end_at: Time.utc(2030))
    rule = E::SecurityRule.new(name: "nat-match", sources: E::AddressGroup.new(name: "sources", members: { "client" => address }),
      services: E::ServiceGroup.new(name: "services", members: { "https" => service }), schedule: schedule)
    nat = E::StaticNat.new(name: "mapping", real_ip: "10.0.0.1", mapped_ip: "192.0.2.1", match_rule: rule)
    catalog = E::Catalog.new([ nat, address, service, schedule ])
    result = Algosec::Config::Result.new(reader: Algosec::Config::Reader.new("", vendor: :fortinet), catalog: catalog,
      diagnostics: [], at: Time.utc(2026))

    assert_equal [ rule ], nat.dependencies
    [ address, service, schedule ].each { |element| assert_equal 1, result.reference_counts.fetch(element.identity, 0) }
    assert_includes result.address_objects, address
    assert result.dns_refresh_required?(nil, at: Time.utc(2026))
  end

  def test_nat_conditions_are_owned_immutable_values
    source_zones = [ +"inside" ]
    conditions = { "src_zones" => source_zones, "conditions" => { "application" => [ +"web" ] } }
    nat = E::DynamicNat.new(id: "nat", direction: :source, extra_conf: conditions)
    source_zones.first.replace("outside")
    conditions["conditions"]["application"] << "ssh"

    assert_equal [ "inside" ], nat.extra_conf.fetch("src_zones")
    assert_equal [ "web" ], nat.extra_conf.dig("conditions", "application")
    assert_raises(FrozenError) { nat.extra_conf["src_zones"] << "dmz" }
    assert_raises(FrozenError) { nat.extra_conf.dig("conditions", "application").first.replace("ssh") }
  end

  def test_route_conditions_cannot_be_changed_through_the_reader
    metadata = { pbr: { bindings: [ { type: "interface", name: "ethernet1" } ] } }
    route = E::Route.new(kind: :policy, name: "pbr", extra_conf: metadata)
    metadata[:pbr][:bindings].clear

    assert_equal "ethernet1", route.extra_conf.dig("pbr", "bindings", 0, "name")
    assert_raises(FrozenError) { route.extra_conf.fetch("pbr").fetch("bindings").clear }
    assert_raises(FrozenError) { route.extra_conf.dig("pbr", "bindings", 0, "name").replace("ethernet2") }
  end

  def test_routing_table_rejects_another_vendor_before_changing_its_routes
    current = E::Route.new(subnet: "192.0.2.0/24", vendor: :fortinet, device_id: 1)
    foreign = E::Route.new(subnet: "192.0.2.0/25", vendor: :asa, device_id: 1)
    table = E::RoutingTable.new([ current ])

    assert_raises(ArgumentError) { table.add(foreign) }
    assert_equal [ current ], table.to_a
    assert_same current, table.lookup(source: "10.0.0.1", destination: "192.0.2.1")
  end

  def test_route_match_dependencies_enforce_address_and_service_group_roles
    address = E::AddressGroup.new(name: "addresses")
    service = E::ServiceGroup.new(name: "services")
    { sources: service, destinations: service, services: address }.each do |role, wrong_group|
      assert_raises(ArgumentError, role.to_s) { E::Route.new(kind: :policy, role => wrong_group) }
    end
    { sources: E::AddressObject.new(name: "host"), services: E::ServiceObject.new(name: "https") }.each do |role, leaf|
      assert_raises(ArgumentError, role.to_s) { E::Route.new(kind: :policy, role => leaf) }
    end

    route = E::Route.new(kind: :policy, sources: address, destinations: address, services: service)
    assert_same address, route.sources
    assert_same address, route.destinations
    assert_same service, route.services
    assert_equal [ address, address, service ], route.dependencies
  end
end
