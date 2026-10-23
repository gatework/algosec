# frozen_string_literal: true

require_relative "../../test_helper"

class ParserTest < Minitest::Test
  include Algosec
  include Algosec::Elements

  def parse(content, vendor: :srx, **options)
    Config::Parser.perform(content, vendor: vendor, device_id: 1,
                           reference_time: Time.utc(2026, 9, 14, 12), **options)
  end

  def test_perform_dispatches_from_reader_vendor_and_preserves_metadata
    reader = Config::Reader.new("set security address-book global address web 192.0.2.1/32\n",
                                vendor: :srx, device_id: 7, device_name: "source", created_at: Time.utc(2026, 9, 14, 12))
    result = Config::Parser.perform(reader)

    assert result.complete?, result.diagnostics.inspect
    refute_same reader, result.reader
    assert_equal reader.content, result.reader.content
    assert_equal reader.created_at, result.reader.created_at
    assert_equal [ false ], reader.parsed_flags
    address = result.find(AddressObject, name: "web", zone: "global")
    assert_equal 7, address.device_id
    assert_equal IPAddr.parse("192.0.2.1"), address.set
  end

  def test_asa_protocol_groups_are_nested_services_and_port_filters_are_intersections
    result = parse(<<~CONFIG, vendor: :asa, strict: true)
      object-group protocol transport
       group-object tcp-only
       protocol-object udp
      object-group protocol tcp-only
       protocol-object tcp
      object-group service ports tcp-udp
       port-object eq 53
       port-object eq 443
      access-list inbound extended permit object-group transport any any eq 53
      access-list inbound extended permit object-group tcp-only any any object-group ports
      access-list inbound extended permit object-group transport any any
      access-list inbound extended permit ip any any
    CONFIG
    transport = result.find(ServiceGroup, name: "transport")
    assert_equal %w[tcp udp], transport.leaves.flat_map(&:terms).map { |term| term[:protocol] }.sort
    first, second, third, fourth = result.rules
    assert_equal IPAddr.service("tcp/53") | IPAddr.service("udp/53"), first.services.set
    assert_equal IPAddr.service("tcp/53") | IPAddr.service("tcp/443"), second.services.set
    assert_same transport, third.services.members.fetch("transport")
    assert_equal IPAddr.service("any"), fourth.services.set
    snapshot = Policy::Snapshot.from_config(result)
    view = Policy::Analysis::RuleView.new(snapshot, first, at: Time.current)
    assert_equal first.services.set, view.ranges[:services]
  end

  def test_asa_service_unification_preserves_source_ports_and_unknown_conditions
    result = parse(<<~CONFIG, vendor: :asa)
      object-group service restricted
       service-object tcp source eq 1024 destination eq 443
       service-object tcp source eq 2048 destination eq 443
      access-list inbound extended permit object-group restricted any any
      access-list inbound extended permit tcp any gt 1024 any lt 443
      access-list inbound extended permit tcp any any eq 443 established
    CONFIG
    first, second, third = result.rules
    assert first.services.matches?(protocol: "tcp", source_port: 1024, destination_port: 443)
    assert first.services.matches?(protocol: "tcp", source_port: 2048, destination_port: 443)
    refute first.services.matches?(protocol: "tcp", source_port: 4096, destination_port: 443)
    assert second.services.matches?(protocol: "tcp", source_port: 1025, destination_port: 442)
    refute second.services.matches?(protocol: "tcp", source_port: 1024, destination_port: 442)
    refute second.services.matches?(protocol: "tcp", source_port: 1025, destination_port: 443)
    assert_empty Policy::Ranges.rule_services(first)
    refute result.complete?
    assert_includes third.unparsed_commands.first, "established"
    assert result.diagnostics.any? { |diagnostic| diagnostic.code == :unsupported_rule_condition }
  end

  def test_asa_missing_and_circular_protocol_groups_do_not_become_partial_services
    result = parse(<<~CONFIG, vendor: :asa)
      object-group protocol transport
       protocol-object tcp
       group-object missing
      access-list inbound extended permit object-group transport any any eq 53
    CONFIG
    refute result.complete?
    assert_raises(Group::UnresolvedReference) { result.rules.first.services.set }
    assert_raises(Group::UnresolvedReference) { Policy::Ranges.rule_services(result.rules.first) }
    assert_raises(Config::ParseError) do
      parse("object-group protocol a\n group-object b\nobject-group protocol b\n group-object a\n", vendor: :asa)
    end
  end

  def test_srx_named_terms_and_rpc_survive_as_service_data
    result = parse(<<~CONFIG, strict: true)
      set applications application app term web protocol tcp
      set applications application app term web destination-port 443
      set applications application app term dns protocol udp
      set applications application app term dns destination-port 53
      set applications application app term rpc protocol tcp
      set applications application app term rpc destination-port 135
      set applications application app term rpc uuid application
      set applications application app term rpc inactivity-timeout 60
    CONFIG
    service = result.find(ServiceObject, name: "app")
    assert_equal %w[web dns rpc], service.terms.map { |term| term[:term] }
    assert_equal "ms-rpc-tcp", service.terms.last[:protocol]
    assert_equal "application", service.terms.last[:uuid]
    assert_equal "60", service.terms.last[:timeout]
    assert_equal IPAddr.service("tcp/443") | IPAddr.service("udp/53") | IPAddr.service("tcp/135"), service.set
  end

  def test_h3c_port_operators_preserve_strict_boundaries
    result = parse(<<~CONFIG, vendor: :h3c, strict: true)
      acl advanced 3000
       rule 10 permit tcp source any destination any destination-port gt 1024
       rule 20 permit tcp source any destination any destination-port lt 443
       rule 30 permit tcp source any destination any destination-port range 80 443
      #
      object-group service high-ports
       service tcp destination gt 1024
      #
    CONFIG
    high, low, inclusive = result.rules
    assert_equal IPAddr.service("tcp/1025-65535"), high.services.set
    assert_equal IPAddr.service("tcp/0-442"), low.services.set
    assert_equal IPAddr.service("tcp/80-443"), inclusive.services.set
    assert_equal IPAddr.service("tcp/1025-65535"), result.find(ServiceGroup, name: "high-ports").set
  end

  def test_empty_strict_port_ranges_are_rejected
    [ :h3c, :asa ].each do |vendor|
      [ "gt 65535", "lt 0", "lt 65536" ].each do |condition|
        content = if vendor == :h3c
                    "acl advanced 3000\n rule 10 permit tcp source any destination any destination-port #{condition}\n#\n"
        else
                    "access-list inbound extended permit tcp any any #{condition}\n"
        end
        assert_raises(Config::ParseError) { parse(content, vendor: vendor) }
      end
    end
  end

  def test_rule_number_is_shared_across_acl_and_object_policies
    asa = parse(<<~CONFIG, vendor: :asa, strict: true)
      access-list inbound line 10 extended permit tcp any any eq 80
      access-list inbound extended permit tcp any any eq 443
      access-list outbound extended deny ip any any
    CONFIG
    assert_equal [ 10, 11, 1 ], asa.rules.map(&:rule_number)
    assert_equal [ "inbound", "10" ], asa.rules.first.identity_fields
    assert asa.rules.all? { |rule| rule.vendor_data.empty? }
    assert_equal "inbound/10", asa.rules.first.rule_id
    assert_equal "10", asa.rules.first.native_rule_id

    h3c = parse(<<~CONFIG, vendor: :h3c, strict: true)
      acl advanced 3000
       rule 10 permit tcp source any destination any destination-port eq 80
       rule 20 deny ip source any destination any
      #
    CONFIG
    assert_equal [ 10, 20 ], h3c.rules.map(&:rule_number)
    assert_equal %w[acl/3000/10 acl/3000/20], h3c.rules.map(&:rule_id)
    assert_equal [ "3000", "3000" ], h3c.rules.map(&:rule_set)
    assert_equal({ "acl_type" => "advanced" }, h3c.rules.first.vendor_data)

    fortinet = parse(File.read(TestPaths.root.join("test/fixtures/config/fortinet.cfg")), vendor: :fortinet)
    refute_empty fortinet.rules
    assert fortinet.rules.all? { |rule| rule.rule_number.is_a?(Integer) && rule.rule_id }
    assert_raises(ArgumentError) { SecurityRule.new(name: "bad", rule_number: -1) }
    assert_raises(ArgumentError) { SecurityRule.new(name: "bad", vendor: :asa, rule_set: "inbound", rule_number: 1,
                                            action: "permit", vendor_data: { acl_line_number: 1 }) }
  end

  def test_srx_network_forward_references_rules_and_report
    result = parse(<<~CONFIG)
      set security address-book global address-set servers address web
      set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24
      set security zones security-zone trust interfaces ge-0/0/0.0
      set routing-options static route 198.51.100.0/24 preference 20
      set routing-options static route 198.51.100.0/24 next-hop 192.0.2.2
      set applications application-set apps application https
      set applications application https protocol tcp
      set security address-book global address web 198.51.100.10/32
      set applications application https destination-port 443
      set security policies from-zone trust to-zone dmz policy web match source-address any
      set security policies from-zone trust to-zone dmz policy web match destination-address servers
      set security policies from-zone trust to-zone dmz policy web match application apps
      set security policies from-zone trust to-zone dmz policy web then permit
    CONFIG
    assert result.complete?, result.diagnostics.inspect
    rule = result.rules.fetch(0)
    assert rule.covers?(source: "10.1.2.3", destination: "198.51.100.10", service: "tcp/443")
    refute rule.covers?(source: "10.1.2.3", destination: "198.51.100.11", service: "tcp/443")
    assert_equal Algosec::Set.new(443..443), result.rule_projection.services.fetch("tcp").fetch(rule.identity)
    interface = result.find(Interface, name: "ge-0/0/0.0")
    assert_equal 2, interface.routes.size
    assert_equal "trust", result.elements(Route).find { |route| route.subnet == "198.51.100.0/24" }.zone
    assert_equal 2, result.find(ServiceObject, name: "https").config.lines.size
  end

  def test_partial_references_stay_visible_and_strict_import_returns_result
    content = <<~CONFIG
      set security address-book global address a 192.0.2.1/32
      set security address-book global address-set g address a
      set security address-book global address-set g address missing
      set system host-name fw
    CONFIG
    result = parse(content)
    refute result.complete?
    group = result.find(AddressGroup, name: "g", zone: "global")
    assert_equal IPAddr.parse("192.0.2.1"), group.set
    assert_nil group.members["missing"]
    assert_raises(Group::UnresolvedReference) { group.resolved_set }
    assert_equal [ "set system host-name fw\n" ], result.unparsed_lines
    error = assert_raises(Config::IncompleteConfiguration) { parse(content, strict: true) }
    assert_equal result.diagnostics, error.result.diagnostics
  end

  def test_srx_nat_context_is_per_rule_set_and_per_document
    content = <<~CONFIG
      set security nat source rule-set first from zone trust
      set security nat source rule-set second from zone dmz
      set security nat source rule-set first rule r match source-address 192.0.2.1/32
      set security nat source rule-set second rule r match source-address 192.0.3.1/32
      set security nat source rule-set first to zone internet
      set security nat source pool pool address 203.0.113.1/32
      set security nat source rule-set first rule r then source-nat pool pool
      set security nat destination pool web address 10.0.0.10/32
      set security nat destination pool web address port 80
      set security nat destination rule-set inbound from zone internet
      set security nat destination rule-set inbound rule web match destination-address 203.0.113.10/32
      set security nat destination rule-set inbound rule web match destination-port 8080
      set security nat destination rule-set inbound rule web then destination-nat pool web
    CONFIG
    parser = Vendors::Srx::Parser.new(device_id: 1)
    result = parser.perform(content)
    assert result.complete?, result.diagnostics.inspect
    first = result.elements(DynamicNat).find { |nat| nat.rule_set == "first" }
    assert_equal "trust", first.from_zone
    assert_equal "internet", first.to_zone
    assert_equal 4, first.config.lines.size
    assert_equal IPAddr.parse("203.0.113.1"), first.source_targets
    inbound = result.find(DynamicNat, name: "web")
    assert_equal "8080", inbound.destination_port
    assert_equal "80", inbound.translated_destination_port
    assert_equal IPAddr.parse("203.0.113.10"), inbound.destination_set
    assert_equal IPAddr.parse("10.0.0.10"), inbound.destination_targets
    other = parser.perform("set security nat source rule-set first rule r match source-address 192.0.2.1/32")
    assert_empty other.elements(DynamicNat)
    assert_equal :missing_nat_context, other.diagnostics.first.code
  end

  def test_srx_static_nat_and_cycle_detection
    result = parse(<<~CONFIG)
      set security nat static rule-set static from zone internet
      set security nat static rule-set static rule web match destination-address 203.0.113.10/32
      set security nat static rule-set static rule web then static-nat prefix 10.0.0.10/32
    CONFIG
    assert result.complete?, result.diagnostics.inspect
    nat = result.find(StaticNat, name: "web")
    assert_equal IPAddr.parse("203.0.113.10"), nat.translate("10.0.0.10")
    assert_raises(Config::ParseError) do
      parse("set security address-book global address-set a address-set b\nset security address-book global address-set b address-set a")
    end
  end

  def test_netscreen_local_builtin_override_and_policy_nat
    builtin = ServiceObject.new(vendor: :netscreen, name: "HTTP", protocol: :tcp,
                          source_port: "0-65535", destination_port: "80", timeout: "30")
    content = <<~CONFIG
      set interface "inside" zone "Trust"
      set interface inside ip 192.0.2.1/24
      set interface "outside" zone "Untrust"
      set interface outside ip 198.51.100.1/24
      set interface outside dip 1 198.51.100.100 198.51.100.110
      set service "HTTP" timeout 60
      set group service "web" add "HTTP"
      set policy id 1 from "Trust" to "Untrust" "Any" "Any" "web" nat src dip-id 1 permit
      exit
    CONFIG
    result = parse(content, vendor: :netscreen, builtin_services: { "HTTP" => builtin })
    assert result.complete?, result.diagnostics.inspect
    assert_equal "30", builtin.timeout
    assert_nil builtin.config
    assert_equal "60", result.find(ServiceObject, name: "HTTP").timeout
    assert_equal "60", result.rules.first.services.leaves.first.timeout
    refute result.rules.first.covers?(source: "10.1.2.3", destination: "203.0.113.1", service: "tcp/80"),
           "A timeout-restricted service cannot prove unconditional coverage"
    assert_equal IPAddr.parse("198.51.100.100-198.51.100.110"), result.elements(DynamicNat).first.source_targets
    assert_equal "exit", result.rules.first.config.lines.last.strip
  end

  def test_fortinet_nested_boundaries_and_source_port_defaults
    result = parse(<<~CONFIG, vendor: :fortinet)
      config system interface
      edit "port1"
      set ip 192.0.2.1 255.255.255.0
      config secondaryip
      edit 1
      set ip 198.51.100.1 255.255.255.0
      next
      end
      next
      edit "port2"
      set ip 203.0.113.1 255.255.255.0
      next
      end
      config firewall service custom
      edit "web"
      set tcp-portrange 80:123 443
      set udp-portrange 53
      next
      end
    CONFIG
    assert_equal "192.0.2.1", result.find(Interface, name: "port1").host
    assert_equal "203.0.113.1", result.find(Interface, name: "port2").host
    assert_includes result.find(Interface, name: "port1").config, "set ip 198.51.100.1"
    terms = result.find(ServiceObject, name: "web").terms.to_h { |term| [ term[:destination_port], term ] }
    assert_equal "123", terms.fetch("80")[:source_port]
    assert_equal "0-65535", terms.fetch("443")[:source_port]
    assert_equal "0-65535", terms.fetch("53")[:source_port]
    assert_raises(Config::ParseError) { parse("config firewall address\nedit A\nconfig metadata", vendor: :fortinet) }
  end

  def test_error_line_and_reference_counts_are_local_to_the_document
    error = assert_raises(Config::ParseError) do
      parse("\nset security address-book global address broken 300.0.0.1/32\n")
    end
    assert_equal 2, error.line_number
    parser = Vendors::Srx::Parser.new(device_id: 1)
    result = parser.perform(<<~CONFIG)
      set security address-book global address web 192.0.2.10/32
      set security address-book global address-set first address web
      set security address-book global address-set second address web
    CONFIG
    address = result.find(AddressObject, name: "web", zone: "global")
    assert_equal 2, result.reference_counts.fetch(address.identity)
    assert_empty parser.perform("").reference_counts
    assert_equal 2, result.reference_counts.fetch(address.identity)
  end

  def test_topsec_named_all_is_not_an_any_address_in_rules_or_nat
    result = parse(<<~CONFIG, vendor: :topsec)
      ID 1 define host add name all ipaddr '192.0.2.10'
      ID 2 define service add name https protocol 6 port 443
      ID 3 firewall policy add action accept srcarea 'trust' dstarea 'untrust' src 'all' dst 'any' service 'https' enable yes
      ID 4 nat policy add srcarea 'trust' dstarea 'untrust' orig-src 'all' orig-dst 'any' orig-service 'https' trans-src all
    CONFIG
    assert result.complete?, result.diagnostics.inspect
    assert_equal IPAddr.parse("192.0.2.10"), result.rules.first.sources.set
    assert_equal IPAddr.parse("192.0.2.10"), result.elements(DynamicNat).first.source_targets
    refute result.rules.first.covers?(source: "192.0.2.11", destination: "203.0.113.1", service: "tcp/443")
  end

  def test_netscreen_weekly_schedule_preserves_each_days_periods
    result = parse(<<~CONFIG, vendor: :netscreen)
      set scheduler work recurrent monday start 09:00 stop 10:00 start 16:00 stop 17:00
      set scheduler work recurrent tuesday start 14:00 stop 15:00
    CONFIG
    assert result.complete?, result.diagnostics.inspect
    schedule = result.find(Schedule, name: "work")
    assert schedule.active?(at: Time.utc(2026, 9, 14, 9, 30))
    refute schedule.active?(at: Time.utc(2026, 9, 14, 14, 30))
    assert schedule.active?(at: Time.utc(2026, 9, 14, 16, 30))
    assert schedule.active?(at: Time.utc(2026, 9, 15, 14, 30))
    refute schedule.active?(at: Time.utc(2026, 9, 15, 9, 30))
  end

  def test_asa_object_nat_uses_public_destination_and_port_before_translation
    result = parse(<<~CONFIG, vendor: :asa)
      object network server
       host 192.0.2.10
       nat (inside,outside) static 198.51.100.10 service tcp 443 8443
    CONFIG
    assert result.complete?, result.diagnostics.inspect
    nat = result.elements(DynamicNat).first
    assert_equal "outside", nat.from_zone
    assert_equal "inside", nat.to_zone
    assert_equal IPAddr.parse("198.51.100.10"), nat.destination_set
    assert_equal IPAddr.parse("192.0.2.10"), nat.destination_targets
    assert_equal IPAddr.service("tcp/8443"), nat.service_set
    assert_equal IPAddr.service("tcp/443"), nat.translated_service_set
  end

  def test_srx_ambiguous_pool_does_not_mix_directions
    result = parse(<<~CONFIG)
      set security nat source pool shared address 198.51.100.1/32
      set security nat destination pool shared address 192.0.2.10/32
      set security nat source rule-set outbound from zone trust
      set security nat source rule-set outbound to zone internet
      set security nat source rule-set outbound rule r match source-address 192.0.2.0/24
      set security nat source rule-set outbound rule r then source-nat pool shared
    CONFIG
    refute result.complete?
    assert_includes result.diagnostics.map(&:code), :ambiguous_nat_pool
    assert_empty result.elements(NatPool)
    assert_nil result.elements(DynamicNat).first.source_pool
  end

  def test_report_excludes_disabled_and_expired_rules_but_keeps_future_rules
    result = parse(<<~CONFIG)
      set schedulers scheduler expired start-date 2026-01-01.00:00 stop-date 2026-01-02.00:00
      set schedulers scheduler future start-date 2027-01-01.00:00 stop-date 2027-01-02.00:00
      set security policies from-zone trust to-zone dmz policy old then permit
      set security policies from-zone trust to-zone dmz policy old scheduler-name expired
      set security policies from-zone trust to-zone dmz policy later then permit
      set security policies from-zone trust to-zone dmz policy later scheduler-name future
      set security policies from-zone trust to-zone dmz policy disabled then permit
      deactivate security policies from-zone trust to-zone dmz policy disabled
    CONFIG
    assert result.complete?, result.diagnostics.inspect
    assert_equal 3, result.rules.size
    future = result.rules.find { |rule| rule.name == "later" }
    assert_equal [ future.identity ], result.rule_projection.sources.keys
    assert_equal [ future.identity ], result.rule_projection.destinations.keys
  end
end
