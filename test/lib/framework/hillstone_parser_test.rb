# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "support/policy_factory"
require "algosec/vendors/hillstone/predefined_services"

class HillstoneParserTest < Minitest::Test
  include PolicyFactory

  def test_unmodeled_multiline_ui_values_preserve_source_without_diagnostics
    source = <<~CONFIG
      value "first
      second"
      address "host"
        ip 192.0.2.1/32
      exit
    CONFIG
    result = parse(source)
    assert_equal source, result.reader.content
    assert_equal [ "value \"first\n", "second\"\n" ], result.unparsed_lines
    assert_empty result.diagnostics
    assert result.complete?
    assert_equal Algosec::IPAddr.parse("192.0.2.1"), result.find(Algosec::Elements::AddressObject, name: "host").set
    error = assert_raises(Algosec::Config::ParseError) { parse("address \"unterminated\n") }
    assert_equal 1, error.line_number
  end

  def test_periodic_schedule_accepts_explicit_zero_seconds_without_changing_boundaries
    result = parse(<<~CONFIG)
      schedule "work"
        periodic monday tuesday wednesday thursday friday 09:00:00 to 18:00:00
      exit
    CONFIG
    assert result.complete?, result.diagnostics.inspect
    schedule = result.find(Algosec::Elements::Schedule, name: "work")
    assert schedule.active?(at: Time.utc(2026, 9, 14, 9))
    assert schedule.active?(at: Time.utc(2026, 9, 14, 18, 0, 59))
    refute schedule.active?(at: Time.utc(2026, 9, 14, 18, 1))
    refute schedule.active?(at: Time.utc(2026, 9, 13, 12))
    invalid = parse("schedule work\n periodic monday 09:00:30 to 18:00:00\nexit\n")
    refute invalid.complete?
    refute invalid.find(E::Schedule, name: "work").resolved?
    incomplete = parse("schedule work\n periodic monday 09:00:00 to\nexit\n")
    refute incomplete.complete?
    refute incomplete.find(Algosec::Elements::Schedule, name: "work").resolved?
  end

  def test_weekly_span_crosses_week_boundary_and_monthly_entries_are_preserved
    result = parse("schedule work\n periodic friday 18:00:00 to monday 09:00:00\nexit\n")
    assert result.complete?, result.diagnostics.inspect
    schedule = result.find(E::Schedule, name: "work")
    assert schedule.active?(at: Time.utc(2026, 9, 19, 12))
    assert schedule.active?(at: Time.utc(2026, 9, 21, 9))
    refute schedule.active?(at: Time.utc(2026, 9, 21, 9, 1))
    refute schedule.active?(at: Time.utc(2026, 9, 18, 17, 59))

    result = parse("schedule work\n periodic daily 09:00:00 to 18:00:00\n periodic day-range 1 00:00:00 to 5 00:00:00\nexit\n")
    assert result.complete?, result.diagnostics.inspect
    schedule = result.find(E::Schedule, name: "work")
    assert_equal :periodic, schedule.kind
    assert schedule.resolved?
    assert schedule.active?(at: Time.utc(2026, 9, 4, 23, 59, 59))
    refute schedule.active?(at: Time.utc(2026, 9, 5))
    assert schedule.active?(at: Time.utc(2026, 9, 18, 12))
    refute schedule.expired?(at: Time.utc(2030))
  end

  def test_schedule_errors_are_diagnostics_and_do_not_discard_valid_windows
    [ "absolute start 02/30/2026 09:00 end 03/01/2026 18:00",
     "absolute start 09/20/2026 09:00 end 09/19/2026 18:00",
     "absolute start 09/20/2026 09:00",
     "periodic unknown 09:00 to 18:00",
     "periodic monday 18:00 to 09:00" ].each do |command|
      result = parse("schedule work\n periodic monday 09:00 to 18:00\n #{command}\nexit\naddress host\n ip 192.0.2.1/32\nexit\n")
      refute result.complete?, command
      assert result.diagnostics.any? { |entry| entry.line_number == 3 }, command
      schedule = result.find(E::Schedule, name: "work")
      refute schedule.resolved?, command
      assert_equal [ 540..1080 ], schedule.weekly_windows.fetch(1)
      assert result.find(E::AddressObject, name: "host")
    end
  end

  def test_diagnostics_keep_key_configuration_and_ignore_ancillary_settings
    result = parse(<<~CONFIG)
      hostname example
      zone trust l2
        bind vswitch1
        ad disable
      exit
      interface ethernet0/1
        zone trust
        manage ping
        lacp enable
        bind pbr-policy test
      exit
      pbr-policy test vrouter trust-vr
        rule 1
          action forward
        exit
      exit
      rule id 1
        action permit
        assistant enable
        dst-host example.com
      exit
    CONFIG
    assert_equal [ 13, 14 ], result.diagnostics.map(&:line_number)
    assert_empty result.rules.sole.unparsed_commands
    assert_equal [ { "type" => "domain", "value" => "example.com" } ], result.rules.sole.destinations.member
    refute result.complete?
  end

  def test_rule_start_time_is_not_expiry_and_limits_reuse
    result = parse("clock zone china\nrule id 1\n action permit\n start-time 9/20/2026 0:0:0\n expire-time 9/21/2026 0:0:0\nexit\n")
    assert result.complete?, result.diagnostics.inspect
    rule = result.rules.sole
    assert_equal Time.utc(2026, 9, 19, 16), rule.starts_at
    refute rule.active?(at: Time.utc(2026, 9, 19, 15, 59, 59))
    assert rule.active?(at: Time.utc(2026, 9, 19, 16))
    refute rule.expired?(at: Time.utc(2026, 9, 19))
    refute rule.active?(at: Time.utc(2026, 9, 20, 16, 0, 1))
    comparison = P::RuleMatcher.new(snapshot(:hillstone, [ rule ])).match(group(:hillstone))
    refute_equal :ignore, comparison.type
  end

  def test_future_rule_does_not_cover_permanent_or_earlier_rules
    future = rule(:hillstone, conditions: { starts_at: "2027-01-01T00:00:00Z" })
    permanent = rule(:hillstone, name: "r2")
    current = snapshot(:hillstone, [ future, permanent ])
    a, b = [ future, permanent ].map { |r| P::Analysis::RuleView.new(current, r, at: Time.utc(2026, 9, 19)) }
    refute a.covers?(b)
    assert b.covers?(a)
    matcher = P::RuleMatcher.new(snapshot(:hillstone, [ future ]), at: Time.utc(2026, 9, 19))
    assert_equal :new, matcher.match(group(:hillstone)).type
    assert_equal :new, matcher.match(group(:hillstone, sources: [ "10.1.0.1" ])).type
    hit = P::TrafficMatcher.new(current, at: Time.utc(2026, 9, 19)).perform(source: "10.0.0.1", destination: "192.0.2.1",
      protocol: "tcp", source_port: 12345, destination_port: 443, from_zone: "inside", to_zone: "outside")
    assert_equal permanent, hit.rule
  end

  def test_predefined_ipv6_icmp_has_numeric_protocol
    table = "Name Protocol Dst-Port/Type Src-Port/Code Timeout\nTotal configured: 1\nICMP6 IPv6-ICMP Any Any -\n"
    service = Algosec::Vendors::Hillstone::PredefinedServices.new(table).services.fetch("ICMP6")
    assert_equal "58", service.terms.first.fetch(:protocol).to_s
  end

  def test_rule_name_and_multiple_log_events_are_retained
    result = parse(<<~CONFIG)
      rule id 186
        action permit
        name "allow-web"
        log session-start
        log session-end
        src-ip 192.0.2.1/32
        dst-ip 198.51.100.1/32
      exit
    CONFIG
    assert result.complete?, result.diagnostics.inspect
    assert_equal "allow-web", result.rules.first.name
    assert_equal "186", result.rules.first.rule_id
    assert_equal "session-start\nsession-end", result.rules.first.log
  end

  def test_omitted_hillstone_zone_is_unrestricted_while_explicit_zones_still_match
    unscoped = rule(:hillstone, from_zones: nil, to_zones: nil)
    scoped = rule(:hillstone, name: "r2", from_zones: "dmz", to_zones: nil)
    matcher = P::RuleMatcher.new(snapshot(:hillstone, [ unscoped, scoped ]))
    assert_equal [ unscoped ], matcher.candidates(from_zone: "inside", to_zone: "outside")
    assert_equal [ unscoped, scoped ], matcher.candidates(from_zone: "dmz", to_zone: "outside")
    assert_equal :ignore, matcher.match(group(:hillstone)).type
    denied = rule(:hillstone, from_zones: nil, to_zones: nil, action: "deny")
    assert_empty P::RuleMatcher.new(snapshot(:hillstone, [ denied ])).candidates(from_zone: "inside", to_zone: "outside")
  end

  def test_predefined_service_table_preserves_continuations_and_icmp_restrictions
    table = <<~TABLE
      device# show service predefined
      Name Protocol Dst-Port/Type Src-Port/Code Timeout
      Total configured: 5
      Any Any - - -
      HTTP TCP 80 Any -
        --More-- \0\b\b  \b\b TCP 8080 Any -
      SMB TCP 139 Any -
          TCP 445 Any -
      PING ICMP type:8 code:0 -
      truncated~ TCP 1002 Any -
      device# exit
    TABLE
    imported = Algosec::Vendors::Hillstone::PredefinedServices.new(table)
    assert_equal [ "truncated~" ], imported.truncated_names
    refute imported.services.key?("truncated~")
    assert_equal Algosec::IPAddr.service("any"), imported.services.fetch("Any").set
    assert_equal Algosec::IPAddr.ports("80") | Algosec::IPAddr.ports("8080"), imported.services.fetch("HTTP").ports.fetch("tcp")
    assert_equal Algosec::IPAddr.ports("139") | Algosec::IPAddr.ports("445"), imported.services.fetch("SMB").ports.fetch("tcp")
    ping = imported.services.fetch("PING").terms.first
    assert_equal Algosec::Set.new(8..8), Algosec::IPAddr.ports(ping[:destination_port])
    assert_equal Algosec::Set.new(0..0), Algosec::IPAddr.ports(ping[:source_port])
    ping_rule = E::SecurityRule.new(native_rule_id: 1, vendor: :hillstone)
    ping_rule.services.add("PING", imported.services.fetch("PING"))
    assert_empty P::Ranges.rule_services(ping_rule)
    assert_raises(ArgumentError) { Algosec::Vendors::Hillstone::PredefinedServices.new(table.sub("configured: 5", "configured: 6")) }
  end

  def test_application_restricted_rules_do_not_claim_unrestricted_port_coverage
    result = parse(<<~CONFIG)
      service https
        tcp dst-port 443
      exit
      rule id 56
        action permit
        src-ip 192.0.2.1/32
        dst-ip 198.51.100.1/32
        service https
        application HTTPS
      exit
    CONFIG
    assert result.complete?, result.diagnostics.inspect
    assert_equal "HTTPS", result.rules.first.application_check
    analyzed = P::Snapshot.from_config(result)
    assert_empty P::RuleMatcher.new(analyzed).candidates(from_zone: "inside", to_zone: "outside")
  end

  def test_icmp_type_restriction_with_any_code_cannot_be_reused_as_whole_protocol
    imported = Algosec::Vendors::Hillstone::PredefinedServices.new(<<~TABLE)
      Name Protocol Dst-Port/Type Src-Port/Code Timeout
      Total configured: 2
      ICMP ICMP type:Any code:Any -
      echo ICMP type:8 code:Any -
    TABLE
    echo_rule = E::SecurityRule.new(native_rule_id: 1, vendor: :hillstone)
    echo_rule.services.add("echo", imported.services.fetch("echo"))
    assert_empty P::Ranges.rule_services(echo_rule)
    matcher = P::RuleMatcher.new(snapshot(:hillstone, imported.services.values))
    assert_equal({ "icmp" => [ "ICMP" ] }, matcher.names_for(:services, { "icmp" => {} }, "inside"))
    legacy_any = E::ServiceObject.new(name: "legacy_any", vendor: :hillstone, protocol: "icmp", destination_port: "1-65535")
    assert P::Ranges.unrestricted_term?(legacy_any.terms.first)
  end

  def test_empty_address_declarations_are_omitted_and_definition_keeps_its_exit
    result = parse(<<~CONFIG)
      address "host"
      exit
      address "unused"
      exit
      address "host"
        ip 192.0.2.9/32
      exit
      address "host"
      exit
      address "group"
        member "host"
      exit
    CONFIG
    assert result.complete?, result.diagnostics.inspect
    assert_nil result.find(E::AddressObject, name: "unused")
    address = result.find(E::AddressObject, name: "host")
    assert_equal [ { "type" => "host", "value" => "192.0.2.9" } ], address.member
    assert_equal "address \"host\"\n  ip 192.0.2.9/32\nexit", address.config
    assert_equal address.set, result.find(E::AddressObject, name: "group").resolved_set
  end

  def test_direct_snat_preserves_explicit_interface_any_service_and_disabled_options
    result = parse(<<~CONFIG)
      interface ethernet0/2
        zone outside
        ip address 203.0.113.2/24
      exit
      snatrule id 8 from ip 10.0.0.0/8 to ip 0.0.0.0/0 service Any eif ethernet0/2 trans-to ip 203.0.113.7 mode dynamicport sticky log disable
    CONFIG
    assert result.complete?, result.diagnostics.inspect
    nat = result.elements(E::DynamicNat).sole
    assert_equal "ethernet0/2", nat.interface
    assert_equal "outside", nat.to_zone
    assert_equal Algosec::IPAddr.service("any"), nat.service_set
    assert_equal "dynamicport", nat.nat_type
    assert nat.disabled?
    assert nat.extra_conf.fetch("sticky")
    assert nat.log_enabled
    assert_equal Algosec::IPAddr.parse("203.0.113.7"), nat.source_targets
    assert_empty snapshot(:hillstone, [ nat ]).active_dynamic_nats
  end

  def test_nat_translation_accepts_explicit_ip_operand
    result = parse("snatrule id 8 from ip 10.0.0.0/8 to ip 0.0.0.0/0 service Any trans-to ip 203.0.113.7 mode dynamicport\n")
    assert result.complete?, result.diagnostics.inspect
    nat = result.elements(E::DynamicNat).sole
    assert_equal Algosec::IPAddr.parse("203.0.113.7"), nat.source_targets
    assert_equal Algosec::IPAddr.parse("10.0.0.0/8"), nat.source_set
  end

  def test_nat_keeps_all_protocols_in_a_multi_term_service
    assert_nat_service_matches("mixed")
  end

  def test_nat_accepts_nested_service_groups_and_keeps_source_ports
    assert_nat_service_matches("outer")
  end

  def test_destination_nat_translates_ports_for_every_service_protocol
    %w[mixed outer].each do |name|
      result = parse(nat_service_config + "dnatrule id 1 from ip 0.0.0.0/0 to ip 203.0.113.10 service #{name} trans-to ip 10.0.0.10 port 8443\n")
      assert result.complete?, result.diagnostics.inspect
      resolver = P::Nat::Resolver.new(P::Snapshot.from_config(result))
      %w[tcp/443 udp/53].each do |service|
        match = resolver.find("10.0.0.10", direction: :destination, zone: "outside",
          peers: { "192.0.2.1" => {} }, source_port: 4096,
          services: { service => { translated_port: "8443" } })
        refute_nil match, service
        assert_equal "203.0.113.10/32", match[:address]
      end
    end
  end

  def test_vrouters_keep_distinct_routes_interfaces_and_nat_egress
    result = parse(<<~CONFIG)
      zone mgt
        vrouter mgt-vr
      exit
      zone trust
        vrouter trust-vr
      exit
      interface MGT0
        zone mgt
        ip address 192.0.2.2 255.255.255.0
      exit
      interface ethernet0/1
        zone trust
        ip address 198.51.100.2 255.255.255.0
      exit
      ip vrouter mgt-vr
        ip route 0.0.0.0/0 192.0.2.1
      exit
      ip vrouter trust-vr
        ip route 0.0.0.0/0 198.51.100.1
        snatrule id 1 from ip 10.0.0.1/32 to ip 203.0.113.1/32 service Any trans-to eif-ip mode dynamicport
      exit
    CONFIG
    assert result.complete?, result.diagnostics.inspect
    assert_equal 4, result.elements(E::Route).size
    defaults = result.elements(E::Route).select { |route| route.prefix.zero? }
    assert_equal %w[mgt-vr trust-vr], defaults.map(&:vrf)
    assert_equal "trust-vr", result.find(E::Interface, name: "ethernet0/1").vrf
    assert_equal "zone trust\n  vrouter trust-vr\nexit", result.find(E::Zone, name: "trust").config
    assert_equal Algosec::IPAddr.parse("198.51.100.2"), result.elements(E::DynamicNat).sole.source_targets
  end

  def test_security_profiles_and_unmodeled_rule_conditions_survive_parsing
    result = parse("rule id 8\n action permit\n av antivirus\n ips default\n url filtering\n user role1\nexit\n")
    rule = result.rules.sole
    assert_equal({ "av" => "antivirus", "ips" => "default", "url" => "filtering" }, rule.security_profiles)
    assert_equal [ "user role1" ], rule.unparsed_commands
    refute result.complete?
  end

  def test_first_deny_prevents_reuse_of_later_allow_and_remains_visible_in_plan
    denied = rule(:hillstone, name: "r9", action: "deny", rule_number: 0)
    allowed = rule(:hillstone, name: "r1", rule_number: 1)
    result = P::RuleMatcher.new(snapshot(:hillstone, [ denied, allowed ])).match(group(:hillstone))
    assert_equal :new, result.type
    assert_equal [ "r9" ], result.conflicting_rules.map(&:rule_id)
    assert_nil result.rule
  end

  def test_security_profiles_prevent_unconditional_reuse_or_extension
    restricted = rule(:hillstone, conditions: { security_profiles: { url: "allow-list" } }, rule_number: 0)
    matcher = P::RuleMatcher.new(snapshot(:hillstone, [ restricted ]))
    error = assert_raises(P::Error) { matcher.match(group(:hillstone)) }
    assert_equal :conditional_policy, error.code
  end

  def test_disjoint_member_extension_generates_an_existing_rule_id_command
    current = snapshot(:hillstone, [ rule(:hillstone) ])
    result = P::RuleMatcher.new(current).match(group(:hillstone, sources: [ "10.1.0.1" ]))
    assert_equal :modify, result.type
    script = result.definition.build_generator(result).perform
    assert_includes script, "rule id r1\n"
  end

  def test_combined_schedule_retains_both_definitions_and_multiple_weekly_windows
    result = parse(<<~CONFIG)
      schedule work
        absolute start 01/01/2026 00:00 end 12/31/2026 23:59
        periodic monday 09:00 to 10:00
        periodic monday 14:00 to 15:00
      exit
    CONFIG
    schedule = result.find(E::Schedule, name: "work")
    assert_equal :mixed, schedule.kind
    assert_equal 2, schedule.weekly_windows.fetch(1).size
    assert_equal 2026, schedule.start_at.year
    assert result.complete?, result.diagnostics.inspect
    assert schedule.resolved?
    assert schedule.active?(at: Time.utc(2026, 9, 21, 9, 30))
    refute schedule.active?(at: Time.utc(2026, 9, 21, 12))
    refute schedule.active?(at: Time.utc(2027, 1, 4, 9, 30))
    assert schedule.expired?(at: Time.utc(2027, 1, 4))
  end

  def test_unknown_hostname_is_not_treated_as_a_disjoint_empty_address
    result = parse(<<~CONFIG)
      address domain
        host example.test
      exit
      rule id 1
        action permit
        src-ip 10.0.0.1/32
        dst-addr domain
        service-rule tcp dst-port 443
      exit
    CONFIG
    current = P::Snapshot.new(device_id: 1, vendor: :hillstone, catalog: result.catalog)
    error = assert_raises(P::Error) { P::RuleMatcher.new(current).match(group(:hillstone)) }
    assert_equal :conditional_policy, error.code
  end

  def test_protocol_services_keep_any_and_numeric_protocol_ranges
    result = parse("service all\n protocol any\nexit\nservice ospf\n protocol 89\nexit\n")
    assert result.complete?, result.diagnostics.inspect
    assert_equal Algosec::IPAddr.service("any"), result.find(E::ServiceObject, name: "all").set
    assert_equal Algosec::IPAddr.service("89/0-65535"), result.find(E::ServiceObject, name: "ospf").set
    refute result.find(E::ServiceObject, name: "ospf").set.overlap?(Algosec::IPAddr.service("tcp/443"))
  end

  def test_nested_management_interface_does_not_create_a_network_interface
    result = parse("webauth\n  interface global-default enable\nexit\ninterface ethernet0/1\n zone trust\nexit\n")
    assert result.complete?
    assert_equal [ "ethernet0/1" ], result.elements(E::Interface).map(&:name)
    assert_includes result.unparsed_lines.join, "interface global-default enable"
  end

  def test_aggregate_containers_keep_metadata_but_do_not_match_or_enter_analysis
    result = parse(<<~CONFIG)
      rule id 10
        name group
        aggregate-type
        disable
      exit
      rule id 11
        action permit
        aggregate-rule 10
      exit
      rule id 12
        action deny
      exit
    CONFIG
    assert result.complete?, result.diagnostics.inspect
    container, member, = result.rules
    assert container.container?
    assert container.ignored?
    assert member.disabled?
    assert_equal "enable", member.status
    assert_equal "10", member.vendor_data["aggregate_rule_id"]
    current = P::Snapshot.from_config(result)
    assert_equal %w[11 12], current.rules.map(&:rule_id)
    assert_empty P::RuleMatcher.new(current).candidates(from_zone: "inside", to_zone: "outside")
    assessment = P::Reclaimer.new(current).perform
    refute assessment.findings.any? { |finding| finding.rule_id == current.signature(container) }
    orphan = parse("rule id 11\n aggregate-rule 10\nexit\n")
    assert_includes orphan.diagnostics.map(&:code), :unsupported_aggregate
    assert_equal [ "aggregate-rule 10" ], orphan.rules.first.unparsed_commands
  end

  def test_rule_expiry_uses_device_timezone_and_preserves_schedule_intersection
    result = Algosec::Config::Parser.perform(<<~CONFIG, vendor: :hillstone, device_id: 1, time_zone: "Asia/Hong_Kong")
      schedule work
        periodic monday 09:00 to 18:00
      exit
      rule id 11
        action permit
        schedule work
        expire-time 9/14/2026 12:00:3
      exit
    CONFIG
    assert result.complete?, result.diagnostics.inspect
    rule = result.rules.first
    assert_equal "2026-09-14T12:00:03+08:00", rule.conditions["expires_at"]
    assert rule.active?(at: Time.utc(2026, 9, 14, 4, 0, 3))
    refute rule.active?(at: Time.utc(2026, 9, 14, 4, 0, 4))
    refute rule.active?(at: Time.utc(2026, 9, 14, 0))
    assert rule.ignored?(at: Time.utc(2026, 9, 14, 5))
    view = P::Analysis::RuleView.new(P::Snapshot.from_config(result), rule, at: Time.utc(2026, 9, 14, 5))
    assert view.expired?
    invalid = parse("rule id 1\n expire-time 2/30/2026 12:00:00\nexit\n")
    assert_equal [ :invalid_rule_time ], invalid.diagnostics.map(&:code)
    assert_equal [ "expire-time 2/30/2026 12:00:00" ], invalid.rules.sole.unparsed_commands
  end

  def test_unexpired_temporary_rule_cannot_cover_or_extend_a_permanent_request
    temporary = rule(:hillstone, conditions: { expires_at: "2027-01-01T00:00:00Z" })
    matcher = P::RuleMatcher.new(snapshot(:hillstone, [ temporary ]), at: Time.utc(2026, 9, 15))
    assert_equal :new, matcher.match(group(:hillstone)).type
    assert_equal :new, matcher.match(group(:hillstone, sources: [ "10.1.0.1" ])).type
    permanent = rule(:hillstone, name: "r2")
    current = snapshot(:hillstone, [ temporary, permanent ])
    a, b = [ temporary, permanent ].map { |r| P::Analysis::RuleView.new(current, r, at: Time.utc(2026, 9, 15)) }
    refute a.covers?(b)
    assert b.covers?(a)
  end

  private

  def nat_service_config
    <<~CONFIG
      interface ethernet0/1
        zone outside
        ip address 192.0.2.2/24
      exit
      service mixed
        tcp dst-port 443
        udp dst-port 53 src-port 4096
      exit
      servgroup inner
        service mixed
      exit
      servgroup outer
        service inner
      exit
    CONFIG
  end

  def assert_nat_service_matches(name)
    result = parse(nat_service_config + "snatrule id 1 from ip 10.0.0.0/24 to ip 192.0.2.1 service #{name} eif ethernet0/1 trans-to ip 203.0.113.10\n")
    assert result.complete?, result.diagnostics.inspect
    resolver = P::Nat::Resolver.new(P::Snapshot.from_config(result))
    options = { direction: :source, zone: "outside", peers: { "192.0.2.1" => {} } }
    %w[tcp/443 udp/53].each do |service|
      match = resolver.find("10.0.0.10", **options, services: { service => {} }, source_port: 4096)
      refute_nil match, service
      assert_equal "203.0.113.10/32", match[:address]
    end
    assert_nil resolver.find("10.0.0.10", **options, services: { "udp/53" => {} }, source_port: 8192)
    assert_nil resolver.find("10.0.0.10", **options, services: { "tcp/53" => {} }, source_port: 4096)
  end

  def parse(source)
    Algosec::Config::Parser.perform(source, vendor: :hillstone, device_id: 1,
                                    reference_time: Time.utc(2026, 9, 15))
  end
end
