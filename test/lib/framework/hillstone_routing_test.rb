# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "support/policy_factory"
require "algosec/dns_resolver"

class HillstoneRoutingTest < Minitest::Test
  include PolicyFactory

  def configuration
    <<~CONFIG
      pbr-policy forward vrouter trust-vr
      exit
      zone inside
        vrouter trust-vr
      exit
      zone outside
        vrouter trust-vr
      exit
      interface ethernet0/1
        zone inside
        bind pbr-policy forward
      exit
      interface ethernet0/2
        zone outside
        ip address 198.51.100.2/24
      exit
      address clients
        ip 10.0.0.0/24
      exit
      address servers
        ip 192.0.2.0/24
      exit
      service web
        tcp dst-port 443
      exit
      ip vrouter trust-vr
        ip route 0.0.0.0/0 198.51.100.1
      exit
      pbr-policy forward vrouter trust-vr
        match id 7
          src-addr clients
          dst-addr servers
          service web
          nexthop 198.51.100.3
        exit
        match id 2
          src-addr Any
          dst-addr Any
          service Any
          disable
          nexthop 198.51.100.4
        exit
      exit
    CONFIG
  end

  def parse(source = configuration, **options)
    Algosec::Config::Parser.perform(source, vendor: :hillstone, device_id: 1, **options)
  end

  def lookup(table, **overrides)
    table.lookup(**{ source: "10.0.0.1", destination: "192.0.2.1", vrf: "trust-vr",
                   source_interface: "ethernet0/1", protocol: "tcp", source_port: 12345, destination_port: 443 }.merge(overrides))
  end

  def test_pbr_retains_order_bindings_and_resolves_both_address_dimensions
    result = parse
    assert result.complete?, result.diagnostics.inspect
    routes = result.elements(E::Route).select(&:policy?)
    assert_equal %w[forward/7 forward/2], routes.map(&:name)
    first = routes.first
    assert_equal "ethernet0/1", first.source_interface
    assert_equal "ethernet0/2", first.destination_interface
    assert_equal "outside", first.zone
    assert_equal "10.0.0.0/24", first.source
    assert_equal [ { "type" => "interface", "name" => "ethernet0/1" } ], first.extra_conf.dig("pbr", "bindings")
    assert_equal [ "servers" ], first.extra_conf.dig("pbr", "destinations")
    assert_equal true, routes.last.extra_conf["disabled"]
    assert_includes first.config, "match id 7"
    table = E::RoutingTable.new(result.elements(E::Route))
    assert_equal first, lookup(table)
    assert_equal "198.51.100.1", lookup(table, destination: "203.0.113.1").next_hop
    assert_equal "198.51.100.1", lookup(table, source: "10.1.0.1").next_hop
    assert_equal "198.51.100.1", lookup(table, source_interface: "ethernet0/3").next_hop
    assert_equal "198.51.100.1", lookup(table, destination_port: 80).next_hop
    assert_raises(E::RoutingTable::ConditionalRoute) { lookup(table, source_interface: nil) }
    assert_raises(E::RoutingTable::ConditionalRoute) { lookup(table, protocol: nil) }
    assert_raises(E::RoutingTable::ConditionalRoute) { lookup(table, source: "10.0.0.0/16") }
  end

  def test_empty_policy_and_binding_are_complete_but_missing_policy_is_not
    result = parse("pbr-policy empty vrouter trust-vr\nexit\ninterface eth0\n bind pbr-policy empty\nexit\n")
    assert result.complete?, result.diagnostics.inspect
    assert_empty result.elements(E::Route)
    missing = parse("interface eth0\n bind pbr-policy missing\nexit\n")
    assert_equal [ :missing_reference ], missing.diagnostics.map(&:code)
  end

  def test_unrestricted_icmp_policy_route_includes_type_zero_after_document_restore
    parsed = parse(configuration.sub("tcp dst-port 443", "icmp"))
    assert parsed.complete?, parsed.diagnostics.inspect
    restored = Algosec::Config::Document.load(JSON.parse(JSON.generate(Algosec::Config::Document.dump(parsed))))

    [ parsed, restored ].each do |result|
      table = E::RoutingTable.new(result.elements(E::Route))
      [ 0, 8 ].each do |type|
        assert_equal "198.51.100.3", lookup(table, protocol: "icmp", source_port: 0, destination_port: type).next_hop
      end
      assert_equal "198.51.100.1", lookup(table, protocol: "tcp").next_hop
    end
  end

  def test_unsupported_pbr_conditions_remain_unknown_instead_of_matching
    result = parse(configuration.sub("    nexthop 198.51.100.3", "    user-group directory admins\n    nexthop 198.51.100.3"))
    assert_equal [ :unsupported_pbr_condition ], result.diagnostics.map(&:code)
    table = E::RoutingTable.new(result.elements(E::Route))
    assert_raises(E::RoutingTable::ConditionalRoute) { lookup(table) }
    assert_equal "198.51.100.1", lookup(table, destination: "203.0.113.1").next_hop
  end

  def test_static_routes_use_destination_longest_prefix_independently_of_source
    broad = E::Route.new(**context(:hillstone), subnet: "0.0.0.0/0", next_hop: "198.51.100.1")
    narrow = E::Route.new(**context(:hillstone), subnet: "192.0.2.0/24", next_hop: "198.51.100.2")
    table = E::RoutingTable.new([ broad, narrow ])
    assert_equal narrow, table.lookup(source: "10.0.0.1", destination: "192.0.2.8")
    assert_equal narrow, table.lookup(source: "172.16.1.1", destination: "192.0.2.8")
    assert_equal broad, table.lookup(source: "10.0.0.1", destination: "203.0.113.8")
  end

  def test_aggregate_members_inherit_zone_without_copying_ip_or_creating_vlans
    result = parse("interface eth0\n aggregate aggregate1\nexit\ninterface aggregate1\n zone outside\n ip address 198.51.100.2/24\nexit\nzone outside\n vrouter trust-vr\nexit\n")
    assert result.complete?, result.diagnostics.inspect
    member = result.find(E::Interface, name: "eth0")
    assert_equal "aggregate1", member.aggregate
    assert_equal "outside", member.zone
    assert_equal "trust-vr", member.vrf
    assert_nil member.ipaddr
    assert_empty member.vlans
    missing = parse("interface eth0\n aggregate absent\nexit\n")
    assert_equal [ :missing_reference ], missing.diagnostics.map(&:code)
  end

  def test_inline_host_domains_and_wildcards_keep_conditional_semantics
    resolver = Algosec::DnsResolver.new(device_id: 1, transport: ->(_name, _servers) { [ [ "192.0.2.9" ], 60 ] })
    source = "rule id 1\n action permit\n dst-host api.example.com\nexit\n"
    result = parse(source, dns_resolver: resolver)
    assert result.complete?, result.diagnostics.inspect
    assert_equal Algosec::IPAddr.parse("192.0.2.9"), result.rules.sole.destinations.set
    assert result.rules.sole.destinations.conditional?
    assert_equal [ { "type" => "domain", "value" => "api.example.com" } ], result.rules.sole.destinations.member
    wildcard = parse(source.sub("api.example.com", "*.example.com"))
    assert_empty wildcard.diagnostics
    refute wildcard.rules.sole.destinations.resolved?
    assert_empty wildcard.rules.sole.destinations.set
  end
end
