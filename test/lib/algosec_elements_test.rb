# frozen_string_literal: true

require "minitest/autorun"
require "algosec"

class AlgosecElementsTest < Minitest::Test
  Elements = Algosec::Elements

  def test_address_ranges_accept_the_same_separators_in_all_entry_points
    expected = Algosec::IPAddr.parse("192.0.2.1-192.0.2.3")

    assert_equal expected, Elements::AddressObject.new(name: "hyphen", member: [ { type: "iprange", value: "192.0.2.1-192.0.2.3" } ]).set
    assert_equal expected, Elements::AddressObject.new(name: "space", member: [ { type: "iprange", value: "192.0.2.1 192.0.2.3" } ]).set
  end

  def test_vlan_names_are_not_duplicated_when_a_link_is_readded
    parent = Elements::Interface.new(name: "port")
    vlan = Elements::Interface.new(name: "vlan1")

    parent.add_vlan(vlan).add_vlan(vlan)

    assert_equal [ "vlan1" ], parent.vlans
    assert_equal vlan.set, parent.set
  end

  def test_readding_a_zone_interface_replaces_its_old_reachability
    old = Elements::Interface.new(name: "port", reachable: "192.0.2.0/24")
    current = Elements::Interface.new(name: "port", reachable: "198.51.100.0/24")
    zone = Elements::Zone.new(name: "inside", interfaces: [ old ])

    assert_same zone, zone.add_interface(current)

    assert_same current, zone.interfaces.fetch(current.identity)
    assert_equal [ [ 3325256704, 3325256959 ] ], zone.set.map { |range| [ range.begin, range.end ] }
    assert_equal zone.set, zone.rebuild!.set
  end

  def test_readding_a_vlan_replaces_its_old_reachability
    parent = Elements::Interface.new(name: "port", reachable: "203.0.113.1")
    parent.add_vlan(Elements::Interface.new(name: "vlan1", reachable: "192.0.2.0/24"))
    current = Elements::Interface.new(name: "vlan1", reachable: "198.51.100.0/24")

    assert_same parent, parent.add_vlan(current)

    assert_equal [ "vlan1" ], parent.vlans
    assert_equal [ [ 3325256704, 3325256959 ], [ 3405803777, 3405803777 ] ], parent.set.map { |range| [ range.begin, range.end ] }
    assert_equal parent.set, parent.rebuild!.set
  end

  def test_zones_use_the_same_definition_default_vrf_as_interfaces_and_routes
    zone = Elements::Zone.new(name: "inside", vendor: :huawei)

    assert_equal "default", zone.vrf
  end

  def test_zones_can_mark_transparent_firewall_scope
    zone = Elements::Zone.new(name: "bridge", mode: :transparent)

    assert_equal :transparent, zone.mode
  end

  def test_static_routes_require_a_destination_at_construction
    assert_raises(ArgumentError) { Elements::Route.new }
    assert_equal :policy, Elements::Route.new(kind: :policy, source: "0.0.0.0/0").kind
  end

  def test_catalog_requires_explicit_resolution_options
    catalog = Elements::Catalog.new

    assert_raises(ArgumentError) { catalog.resolve!(strict: nil) }
    assert_raises(ArgumentError) { catalog.resolve!(on_missing: Object.new) }
    assert_raises(ArgumentError) { catalog.resolve!(on_missing: false) }
  end

  def test_catalog_and_routing_table_validate_collection_inputs
    assert_raises(ArgumentError) { Elements::Catalog.new(nil) }
    assert_raises(ArgumentError) { Elements::RoutingTable.new(nil) }
  end

  def test_reference_resolution_requires_a_boolean_strict_flag
    group = Elements::AddressGroup.new(name: "group")
    address = Elements::AddressObject.new(name: "host", member: [ { type: "host", value: "192.0.2.1" } ])

    assert_raises(ArgumentError) { group.resolve!(strict: nil) { nil } }
    address.add_reference("other")
    assert_raises(ArgumentError) { address.resolve!(strict: nil) { nil } }
  end

  def test_enum_options_reject_numeric_values
    assert_raises(ArgumentError) { Elements::Interface.new(name: "bad", mode: 1) }
    assert_raises(ArgumentError) { Elements::Route.new(kind: 1, subnet: "192.0.2.0/24") }
  end

  def test_route_identity_preserves_same_subnet_paths_and_vrf_boundaries
    routes = [
      Elements::Route.new(subnet: "192.0.2.1/24", next_hop: "10.0.0.1", vrf: "blue"),
      Elements::Route.new(subnet: "192.0.2.0/24", next_hop: "10.0.0.2", vrf: "blue"),
      Elements::Route.new(subnet: "192.0.2.0/24", next_hop: "10.0.0.1", vrf: "red"),
      Elements::Route.new(subnet: "192.0.2.128/25", next_hop: "10.0.0.3", vrf: "blue")
    ]
    table = Elements::RoutingTable.new(routes)
    assert_equal 4, table.count
    assert_equal "192.0.2.0/24", routes.first.subnet
    assert_same routes.last, table.lookup(source: "10.0.0.1", destination: "192.0.2.200", vrf: "blue")
    assert_same routes[2], table.lookup(source: "10.0.0.1", destination: "192.0.2.200", vrf: "red")
    assert_nil table.lookup(source: "10.0.0.1", destination: "192.0.2.200", vrf: "absent")
  end

  def test_address_projection_rebuilds_nested_groups_and_keeps_unknown_separate_from_empty
    address = Elements::AddressObject.new(name: "leaf", member: [ { type: "host", value: "192.0.2.1" } ])
    child = Elements::AddressGroup.new(name: "inner", members: { "leaf" => address })
    root = Elements::AddressGroup.new(name: "outer", members: { "inner" => child })
    assert_equal Algosec::IPAddr.parse("192.0.2.1"), root.resolved_set
    address.add(type: "ipv6", value: "2001:db8::1/128")
    refute root.resolved?
    assert_equal 2, root.member.size
    assert_raises(Elements::Group::UnresolvedReference) { root.resolved_set }
    replacement = Elements::AddressObject.new(name: "leaf", member: [ { type: "host", value: "192.0.2.2" } ])
    child.replace("leaf", replacement)
    assert_equal Algosec::IPAddr.parse("192.0.2.2"), root.resolved_set
    child.delete("leaf")
    assert root.resolved?
    assert_empty root.set
    child.add("missing")
    refute root.resolved?
    assert_empty root.set
    assert_raises(Elements::Group::CircularReference) { child.add("outer", root) }
  end

  def test_interface_layer_and_access_modes_have_a_single_consistent_contract
    assert_equal "default", Elements::Interface.new(name: "unknown").vrf
    assert_nil Elements::Interface.new(name: "unknown").access_mode
    assert_equal "access", Elements::Interface.new(name: "switch", vendor: :topsec).access_mode
    assert_equal "route", Elements::Interface.new(name: "routed", mode: :layer3, vendor: :topsec).access_mode
    assert_equal "trunk", Elements::Interface.new(name: "trunk", access_mode: "trunk").access_mode
    assert_raises(ArgumentError) { Elements::Interface.new(name: "bad", mode: :layer3, access_mode: "access") }
    assert_raises(ArgumentError) { Elements::Interface.new(name: "bad", access_mode: "route") }
  end

  def test_source_only_policy_routes_do_not_invent_interface_reachability
    route = Elements::Route.new(kind: :policy, source: "10.0.0.0/24", destination_interface: "out")
    interface = Elements::Interface.new(name: "out", routes: [ route ])
    assert_equal 1, interface.routes.size
    assert_empty interface.set
    assert_empty interface.rebuild!.set
    table = Elements::RoutingTable.new([ route ])
    assert_same route, table.lookup(source: "10.0.0.1", destination: "192.0.2.1")
  end

  def test_service_definitions_keep_protocol_source_port_uuid_and_timeout_distinctions
    service = Elements::ServiceObject.new(name: "web", vendor: :asa, terms: [
      { protocol: "tcp", source_port: "1024", destination_port: "443", timeout: "30" },
      { protocol: "tcp", source_port: "2048", destination_port: "443", timeout: "60" },
      { protocol: "udp", source_port: "0-65535", destination_port: "443" }
    ])
    assert_equal 3, service.terms.size
    assert_nil service.protocol
    assert_nil service.timeout
    refute service.add(**service.terms.first)
    assert service.matches?(protocol: "tcp", source_port: 1024, destination_port: 443)
    assert service.matches?(protocol: "tcp", source_port: 2048, destination_port: 443)
    refute service.matches?(protocol: "tcp", source_port: 4096, destination_port: 443)
    assert service.matches?(protocol: "udp", source_port: 4096, destination_port: 443)
    assert service.add(protocol: "tcp", source_port: "1024", destination_port: "443", uuid: "rpc")
    assert_equal 4, service.terms.size
    assert_equal Algosec::IPAddr.service("tcp/443") | Algosec::IPAddr.service("udp/443"), service.set
  end

  def test_service_data_is_frozen_and_mutations_are_atomic
    input = { "protocol" => "tcp", "destination_port" => +"443" }
    service = Elements::ServiceObject.new(name: "web", terms: [ input ])
    input["destination_port"].replace("80")
    assert_equal "443", service.destination_port
    original = service.terms
    assert_raises(FrozenError) { original.first[:destination_port].replace("80") }
    assert_raises(FrozenError) { original << {} }
    assert_raises(ArgumentError) { service.add(protocol: "tcp", destination_port: "65536") }
    assert_raises(ArgumentError) { service.add(protocol: "tcp", destination_port: "80", typo: true) }
    assert_same original, service.terms
    service.timeout = "60"
    assert_nil original.first[:timeout]
    assert_equal "60", service.timeout
    copy = Elements::ServiceObject.new(name: "copy", terms: service.terms)
    copy.timeout = "90"
    assert_equal "60", service.timeout
    refute service.same_definition?(copy)
    assert_raises(ArgumentError) { service.merge!(Elements::ServiceObject.new(name: "other", vendor: :hillstone)) }
  end

  def test_rpc_terms_survive_cloning_merging_and_nested_service_groups
    service = Elements::ServiceObject.new(name: "RPC", vendor: :srx, device_id: 1,
                                    protocol: "tcp", destination_port: "135", uuid: "application", term: "rpc", timeout: "60")
    copy = Elements::ServiceObject.new(name: "copy", vendor: :srx, device_id: 1, terms: service.terms)
    assert service.same_definition?(copy)
    assert_equal "ms-rpc-tcp", copy.protocol
    assert copy.matches?(protocol: "tcp", source_port: 1024, destination_port: 135, uuid: "application")
    refute copy.matches?(protocol: "tcp", source_port: 1024, destination_port: 135)
    group = Elements::ServiceGroup.new(name: "inner", vendor: :srx, members: { "RPC" => service })
    outer = Elements::ServiceGroup.new(name: "outer", vendor: :srx, members: { "inner" => group })
    service.add(protocol: "udp", destination_port: "53", term: "dns")
    assert outer.set.cover?(Algosec::IPAddr.service("udp/53"))
    copy.merge!(service)
    assert service.same_definition?(copy)
    group.add("missing")
    assert_raises(Elements::Group::UnresolvedReference) { outer.set }
  end

  def test_nested_service_ports_follow_current_members_and_leaf_changes
    service = Elements::ServiceObject.new(name: "web", protocol: "tcp", destination_port: "443")
    inner = Elements::ServiceGroup.new(name: "inner", members: { "web" => service })
    outer = Elements::ServiceGroup.new(name: "outer", members: { "inner" => inner })
    original = outer.ports

    service.add(protocol: "udp", destination_port: "53")
    assert_equal Algosec::IPAddr.ports("53"), outer.ports.fetch("udp")
    refute original.key?("udp")
    replacement = Elements::ServiceObject.new(name: "web", protocol: "tcp", destination_port: "8443")
    inner.add("web", replacement)
    assert_equal({ "tcp" => Algosec::IPAddr.ports("8443") }, outer.ports)
    assert_equal Algosec::IPAddr.service("tcp/8443"), outer.set
    inner.delete("web")
    assert_empty outer.ports
    assert_empty outer.set
  end

  def test_service_ports_keep_partial_evidence_without_claiming_resolved_ranges
    service = Elements::ServiceObject.new(name: "web", protocol: "tcp", destination_port: "443")
    inner = Elements::ServiceGroup.new(name: "inner", members: { "web" => service, "missing" => nil })
    outer = Elements::ServiceGroup.new(name: "outer", members: { "inner" => inner })

    assert_equal({ "tcp" => Algosec::IPAddr.ports("443") }, outer.ports)
    refute outer.resolved?
    assert_raises(Elements::Group::UnresolvedReference) { outer.set }
    inner.replace("web", nil)
    assert_empty outer.ports
    refute outer.service_projection.fetch(:resolution).fetch("complete")
  end
end
