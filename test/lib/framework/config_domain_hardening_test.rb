# frozen_string_literal: true

require_relative "../../test_helper"

class ConfigDomainHardeningTest < Minitest::Test
  include Algosec
  include Algosec::Elements

  def parse(content, vendor:, **options)
    Config::Parser.perform(content, vendor: vendor, device_id: 1,
                           reference_time: Time.utc(2026, 9, 30, 12), **options)
  end

  def test_fortinet_port_ranges_put_destination_before_source
    result = parse(<<~CONFIG, vendor: :fortinet, strict: true)
      config firewall service custom
        edit restricted
          set tcp-portrange 443:1024-2048 8443
          set udp-portrange 53:4096
        next
      end
    CONFIG
    service = result.find(ServiceObject, name: "restricted")

    assert service.matches?(protocol: "tcp", source_port: 1024, destination_port: 443)
    assert service.matches?(protocol: "tcp", source_port: 2048, destination_port: 443)
    refute service.matches?(protocol: "tcp", source_port: 2049, destination_port: 443)
    refute service.matches?(protocol: "tcp", source_port: 443, destination_port: 1024)
    assert service.matches?(protocol: "tcp", source_port: 50000, destination_port: 8443)
    assert service.matches?(protocol: "udp", source_port: 4096, destination_port: 53)
  end

  def test_fortinet_vip_keeps_every_mapped_address
    result = parse(<<~CONFIG, vendor: :fortinet, strict: true)
      config firewall vip
        edit web
          set extip 203.0.113.10
          set extintf any
          set mappedip 10.0.0.10 10.0.0.20
          set portforward enable
          set extport 443
          set mappedport 8443
        next
      end
    CONFIG

    assert_equal IPAddr.parse("10.0.0.10") | IPAddr.parse("10.0.0.20"), result.elements(DynamicNat).sole.translated_destination_set
  end

  def test_h3c_service_keeps_source_port_constraints
    result = parse(<<~CONFIG, vendor: :h3c, strict: true)
      object-group service restricted
       service tcp source eq 100 destination range 10 100
       service tcp destination eq 443
      #
    CONFIG
    service = result.find(ServiceGroup, name: "restricted")

    assert service.matches?(protocol: "tcp", source_port: 100, destination_port: 10)
    assert service.matches?(protocol: "tcp", source_port: 100, destination_port: 100)
    refute service.matches?(protocol: "tcp", source_port: 101, destination_port: 10)
    assert service.matches?(protocol: "tcp", source_port: 50000, destination_port: 443)
  end

  def test_h3c_acl_keeps_source_port_conditions_and_port_groups
    result = parse(<<~CONFIG, vendor: :h3c, strict: true)
      object-group port clients
       port eq 1024
       port eq 2048
      #
      acl advanced 3000
       rule 10 permit tcp source any source-port object-group clients destination any destination-port eq 443
      #
    CONFIG
    services = result.rules.sole.services

    assert services.matches?(protocol: "tcp", source_port: 1024, destination_port: 443)
    assert services.matches?(protocol: "tcp", source_port: 2048, destination_port: 443)
    refute services.matches?(protocol: "tcp", source_port: 4096, destination_port: 443)
  end

  def test_h3c_nat_acl_projections_cannot_prove_rule_pairing_or_conditions
    [
      [ "rule 10 permit tcp source 10.0.0.1 0 destination 203.0.113.1 0 destination-port eq 80",
        "rule 20 permit tcp source 10.0.0.2 0 destination 203.0.113.2 0 destination-port eq 443" ],
      [ "rule 10 deny ip source any destination any" ],
      [ "rule 10 permit tcp source any source-port eq 1024 destination any destination-port eq 443" ]
    ].each do |rules|
      content = h3c_nat_acl(rules)
      result = parse(content, vendor: :h3c)

      refute result.complete?, rules.inspect
      assert result.diagnostics.any? { |entry| entry.code == :conditional_nat_acl }, rules.inspect
      assert_equal 1, result.elements(DynamicNat).size
      assert_raises(Config::IncompleteConfiguration) { parse(content, vendor: :h3c, strict: true) }
    end
  end

  def test_h3c_single_unconditional_nat_acl_remains_complete
    result = parse(h3c_nat_acl([ "rule 10 permit tcp source any destination any destination-port eq 443" ]), vendor: :h3c, strict: true)

    assert_equal IPAddr.service("tcp/443"), result.elements(DynamicNat).sole.service_set
  end

  def test_h3c_unknown_acl_conditions_remain_visible_to_policy_analysis
    %w[fragment established].each do |condition|
      result = parse(h3c_nat_acl([ "rule 10 permit tcp source any destination any destination-port eq 443 #{condition}" ]), vendor: :h3c)

      refute result.complete?, condition
      assert result.diagnostics.any? { |entry| entry.code == :unsupported_rule_condition }, condition
      assert result.diagnostics.any? { |entry| entry.code == :conditional_nat_acl }, condition
      assert_includes result.rules.sole.unparsed_commands.sole, condition
    end
  end

  def test_h3c_acl_metadata_and_keyword_like_names_are_not_unknown_conditions
    result = parse(<<~CONFIG, vendor: :h3c, strict: true)
      object-group port fragment
       port eq 443
      #
      acl advanced 3000
       rule 10 permit tcp source any destination any destination-port object-group fragment logging counting
      #
    CONFIG

    assert_equal "logging", result.rules.sole.log
    assert_equal IPAddr.service("tcp/443"), result.rules.sole.services.set
  end

  def test_h3c_acl_names_do_not_become_port_or_schedule_keywords
    result = parse(<<~CONFIG, vendor: :h3c, strict: true)
      object-group ip address source-port
       network subnet 10.0.0.0 255.255.255.0
      #
      object-group ip address destination-port
       network subnet 192.0.2.0 255.255.255.0
      #
      object-group port time-range
       port eq 443
      #
      acl advanced 3000
       rule 10 permit tcp source object-group source-port destination object-group destination-port destination-port object-group time-range
      #
    CONFIG

    rule = result.rules.sole
    assert_equal IPAddr.parse("10.0.0.0/24"), rule.sources.set
    assert_equal IPAddr.parse("192.0.2.0/24"), rule.destinations.set
    assert_equal IPAddr.service("tcp/443"), rule.services.set
    assert_nil rule.schedule_name
  end

  def test_h3c_server_and_static_nat_do_not_drop_acl_dimensions
    [
      "interface GigabitEthernet1\n ip address 198.51.100.1 255.255.255.0\n nat server protocol tcp global 198.51.100.10 443 inside 10.0.0.10 8443 3000\n#",
      "nat static outbound 10.0.0.10 198.51.100.10 acl 3000"
    ].each do |declaration|
      content = <<~CONFIG
        #{declaration}
        acl advanced 3000
         rule 10 permit tcp source any destination any destination-port eq 443
        #
      CONFIG
      result = parse(content, vendor: :h3c)

      refute result.complete?, declaration
      assert result.diagnostics.any? { |entry| entry.code == :conditional_nat_acl }, declaration
    end
  end

  def test_hillstone_inline_services_with_different_sources_do_not_overwrite
    result = parse(<<~CONFIG, vendor: :hillstone, strict: true)
      rule id 1
        action permit
        src-addr Any
        dst-addr Any
        service-rule tcp dst-port 443 src-port 1024
        service-rule tcp dst-port 443 src-port 2048
      exit
    CONFIG
    services = result.rules.sole.services

    assert services.matches?(protocol: "tcp", source_port: 1024, destination_port: 443)
    assert services.matches?(protocol: "tcp", source_port: 2048, destination_port: 443)
    refute services.matches?(protocol: "tcp", source_port: 4096, destination_port: 443)
  end

  def test_missing_explicit_route_interface_is_incomplete
    content = <<~CONFIG
      config router static
        edit 1
          set dst 198.51.100.0 255.255.255.0
          set device absent
        next
      end
    CONFIG
    result = parse(content, vendor: :fortinet)

    refute result.complete?
    assert result.diagnostics.any? { |entry| entry.code == :missing_interface && entry.message.include?("absent") }
    assert_raises(Config::IncompleteConfiguration) { parse(content, vendor: :fortinet, strict: true) }
  end

  def test_palo_alto_route_metrics_reject_non_numeric_input
    %w[metric admin-dist].each do |field|
      content = <<~CONFIG
        set network virtual-router default routing-table ip static-route outbound destination 198.51.100.0/24
        set network virtual-router default routing-table ip static-route outbound #{field} invalid
      CONFIG

      error = assert_raises(Config::ParseError) { parse(content, vendor: :palo_alto) }
      assert_equal 2, error.line_number
    end
  end

  def test_srx_point_to_point_prefix_keeps_both_endpoints_in_the_routing_table
    result = parse(<<~CONFIG, vendor: :srx, strict: true)
      set interfaces ge-0/0/0 unit 0 family inet address 198.51.100.1/31
      set routing-instances blue interface ge-0/0/0.0
      set security zones security-zone uplink interfaces ge-0/0/0.0
    CONFIG
    routes = result.elements(Route)
    assert_equal 1, routes.size
    route = routes.sole
    assert_equal "198.51.100.0/31", route.subnet
    assert_equal "ge-0/0/0.0", route.destination_interface
    assert_equal "blue", route.vrf
    assert_equal "uplink", route.zone
    assert_includes route.config, "address 198.51.100.1/31"
    assert_equal IPAddr.parse("198.51.100.0/31"), result.find(Interface, name: "ge-0/0/0.0").set

    table = RoutingTable.new(routes)
    %w[198.51.100.0 198.51.100.1].each do |destination|
      assert_same route, table.lookup(source: "192.0.2.1", destination: destination, vrf: "blue")
    end
    assert_nil table.lookup(source: "192.0.2.1", destination: "198.51.100.2", vrf: "blue")
    assert_nil table.lookup(source: "192.0.2.1", destination: "198.51.100.1", vrf: "default")
  end

  def test_srx_loopback_host_prefix_remains_a_single_host_route
    result = parse(<<~CONFIG, vendor: :srx, strict: true)
      set interfaces lo0 unit 0 family inet address 203.0.113.9/32
      set routing-instances blue interface lo0.0
    CONFIG
    routes = result.elements(Route)
    assert_equal 1, routes.size
    route = routes.sole
    assert_equal "203.0.113.9/32", route.subnet
    assert_equal "lo0.0", route.destination_interface
    assert_equal "blue", route.vrf
    assert_equal IPAddr.parse("203.0.113.9"), result.find(Interface, name: "lo0.0").set

    table = RoutingTable.new(routes)
    assert_same route, table.lookup(source: "192.0.2.1", destination: "203.0.113.9", vrf: "blue")
    assert_nil table.lookup(source: "192.0.2.1", destination: "203.0.113.10", vrf: "blue")
  end

  private

  def h3c_nat_acl(rules)
    <<~CONFIG
      interface GigabitEthernet1
       ip address 198.51.100.1 255.255.255.0
       nat outbound 3000
      #
      acl advanced 3000
       #{rules.join("\n ")}
      #
    CONFIG
  end
end
