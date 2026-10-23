# frozen_string_literal: true

require_relative "../../test_helper"
require "algosec/policy"

class VendorMatchConditionsTest < Minitest::Test
  E = Algosec::Elements
  P = Algosec::Policy

  def test_fortinet_any_interface_deny_precedes_specific_allow
    [ [ "any", "outside" ], [ "inside", "any" ], [ "any", "any" ] ].each do |source, destination|
      parsed = fortinet(source, destination)
      assert parsed.complete?, parsed.diagnostics.inspect
      match = traffic(parsed)
      assert_equal :deny, match.decision, [ source, destination, match ].inspect
      assert_equal "1", match.rule.native_rule_id
    end
  end

  def test_fortinet_standalone_interfaces_are_exact_query_zones
    parsed = fortinet("port1 port3", "port2", zones: false)
    assert parsed.complete?, parsed.diagnostics.inspect
    assert_equal [ "port1", "port3" ], parsed.rules.first.from_zones
    assert_equal [ "port2" ], parsed.rules.first.to_zones
    assert_equal :deny, traffic(parsed, from_zone: "port1", to_zone: "port2").decision
    assert_equal :deny, traffic(parsed, from_zone: "port3", to_zone: "port2").decision
    assert_equal :permit, traffic(parsed, from_zone: "port4", to_zone: "port2").decision
  end

  def test_fortinet_partial_zone_interfaces_remain_unknown
    parsed = fortinet("port1", "outside", zone_members: "port1 port3")
    current = P::Snapshot.new(vendor: :fortinet, device_id: 1, catalog: parsed.catalog)
    match = traffic(parsed, snapshot: current)
    assert_equal :unknown, match.status
    assert_equal "1", match.rule.native_rule_id
  end

  def test_fortinet_complete_zone_members_can_prove_a_match
    parsed = fortinet("port1 port3", "outside", zone_members: "port1 port3")
    assert parsed.complete?, parsed.diagnostics.inspect
    assert_equal :deny, traffic(parsed).decision
  end

  def test_fortinet_unknown_interface_does_not_disappear
    parsed = fortinet("missing", "outside")
    refute parsed.complete?
    assert_includes parsed.diagnostics.map(&:code), :missing_interface
    current = P::Snapshot.new(vendor: :fortinet, device_id: 1, catalog: parsed.catalog)
    assert_equal :unknown, traffic(parsed, snapshot: current).status
  end

  def test_asa_identity_nat_exempts_the_source_before_object_nat
    resolver = asa_resolver("nat (inside,outside) source static private private")
    result = resolver.find("10.0.0.1", **asa_query)
    assert_equal "10.0.0.1/32", result.fetch(:address)
    assert_equal :static, result.fetch(:type)
  end

  def test_asa_after_auto_identity_does_not_preempt_object_nat
    resolver = asa_resolver("nat (inside,outside) after-auto source static private private")
    assert_equal "203.0.113.1/32", resolver.find("10.0.0.1", **asa_query).fetch(:address)
  end

  def test_asa_manual_dynamic_precedes_a_later_static_exemption
    resolver = asa_resolver(<<~CONFIG)
      nat (inside,outside) source dynamic private public
      nat (inside,outside) source static private private
    CONFIG
    assert_equal "203.0.113.1/32", resolver.find("10.0.0.1", **asa_query).fetch(:address)
  end

  def test_asa_inactive_identity_nat_is_retained_without_exempting_traffic
    resolver = asa_resolver("nat (inside,outside) source static private private inactive")
    assert_equal "203.0.113.1/32", resolver.find("10.0.0.1", **asa_query).fetch(:address)
    assert resolver.snapshot.static_nats.sole.disabled?
    assert_empty resolver.snapshot.active_static_nats
    refute resolver.used?("10.0.0.1", zone: "outside")
    error = assert_raises(P::Error) { resolver.reverse("10.0.0.1") }
    assert_equal :nat_missing, error.code
  end

  def test_asa_inactive_manual_dynamic_does_not_hide_an_active_identity_rule
    resolver = asa_resolver(<<~CONFIG)
      nat (inside,outside) source dynamic private public inactive
      nat (inside,outside) source static private private
    CONFIG
    assert_equal "10.0.0.1/32", resolver.find("10.0.0.1", **asa_query).fetch(:address)
    assert_equal 2, resolver.snapshot.dynamic_nats.size
    assert_equal 1, resolver.snapshot.active_dynamic_nats.size
  end

  def test_asa_unidirectional_static_nat_cannot_be_treated_as_a_complete_bidirectional_mapping
    %w[private public].each do |mapped|
      error = assert_raises(Algosec::Config::IncompleteConfiguration) do
        asa_resolver("nat (inside,outside) source static private #{mapped} unidirectional")
      end
      assert_includes error.result.diagnostics.map(&:code), :unsupported_nat_condition
      assert_raises(P::Error) { P::Snapshot.from_config(error.result) }
    end
  end

  def test_asa_description_text_does_not_add_a_unidirectional_condition
    resolver = asa_resolver('nat (inside,outside) source static private private description "unidirectional"')
    assert_equal [ "10.0.0.1/32", "inside" ], resolver.reverse("10.0.0.1")
  end

  def test_asa_static_auto_nat_precedes_dynamic_auto_nat_and_sorts_by_object_name
    objects = <<~CONFIG
      object network z_last
       host 10.0.0.1
       nat (inside,outside) static public
      !
      object network a_first
       host 10.0.0.1
       nat (inside,outside) static 10.0.0.1
      !
    CONFIG
    resolver = asa_resolver("", extra_objects: objects)
    result = resolver.find("10.0.0.1", **asa_query)
    assert_equal "10.0.0.1/32", result.fetch(:address)
    assert_equal "a_first", result.fetch(:rule).real_ip
  end

  def test_asa_distinct_rules_using_the_same_mapped_object_survive_parsing
    resolver = asa_resolver(<<~CONFIG)
      nat (inside,outside) source static private public
      nat (inside,outside) after-auto source static internal public
    CONFIG
    assert_equal 2, resolver.snapshot.static_nats.size
    assert_equal 2, resolver.snapshot.static_nats.map(&:identity).uniq.size
    assert_equal "203.0.113.1/32", resolver.find("10.0.0.1", **asa_query).fetch(:address)
  end

  def test_nat_order_is_optional_validated_and_independent_of_caller_mutation
    [ E::StaticNat, E::DynamicNat ].each do |type|
      attributes = type == E::StaticNat ? { mapped_ip: "203.0.113.1", real_ip: "10.0.0.1" } : { id: "1", direction: :source }
      assert_nil type.new(**attributes).nat_order
      order = [ 1, 2 ]
      nat = type.new(**attributes, nat_order: order)
      order << 3
      assert_equal [ 1, 2 ], nat.nat_order
      assert nat.nat_order.frozen?
      [ [], false, "1", [ -1 ], [ nil ], [ 1.5 ] ].each do |invalid|
        assert_raises(ArgumentError) { type.new(**attributes, nat_order: invalid) }
      end
    end
  end

  def test_palo_alto_nat_checks_source_port_and_preserves_the_service_reference
    parsed = palo_alto_nat
    assert parsed.complete?, parsed.diagnostics.inspect
    nat = parsed.elements(E::DynamicNat).sole
    assert_same parsed.find(E::ServiceObject, name: "restricted"), nat.service
    resolver = P::Nat::Resolver.new(P::Snapshot.from_config(parsed))
    options = { zone: "outside", direction: :source, flow: { from_zone: "inside", to_zone: "outside" }, peers: { "192.0.2.1" => {} }, services: { "tcp/443" => {} } }
    assert_equal "203.0.113.1/32", resolver.find("10.0.0.1", **options, source_port: "1024").fetch(:address)
    assert_nil resolver.find("10.0.0.1", **options, source_port: "50000")
    error = assert_raises(P::Error) { resolver.find("10.0.0.1", **options) }
    assert_equal :conditional_nat, error.code
    cache = Algosec::Config::Cache.new(store: ActiveSupport::Cache::MemoryStore.new)
    cache.save(parsed)
    restored = cache.load(1)
    assert_same restored.find(E::ServiceObject, name: "restricted"), restored.elements(E::DynamicNat).sole.service
  end

  def test_palo_alto_explicit_any_nat_zone_matches_the_requested_zone
    parsed = palo_alto_nat(to_zone: "any")
    assert parsed.complete?, parsed.diagnostics.inspect
    resolver = P::Nat::Resolver.new(P::Snapshot.from_config(parsed))
    result = resolver.find("10.0.0.1", zone: "outside", direction: :source, flow: { from_zone: "inside", to_zone: "outside" }, peers: { "192.0.2.1" => {} },
      services: { "tcp/443" => {} }, source_port: "1024")
    assert_equal "203.0.113.1/32", result.fetch(:address)
  end

  def test_palo_alto_nat_service_groups_keep_source_and_destination_port_pairs
    parsed = palo_alto_nat(service_name: "group", services: <<~CONFIG)
      set service alternate protocol tcp port 8443
      set service alternate protocol tcp source-port 2048
      set service-group group members [ restricted alternate ]
    CONFIG
    assert parsed.complete?, parsed.diagnostics.inspect
    resolver = P::Nat::Resolver.new(P::Snapshot.from_config(parsed))
    query = { zone: "outside", direction: :source, flow: { from_zone: "inside", to_zone: "outside" }, peers: { "192.0.2.1" => {} } }
    [ [ "1024", "443" ], [ "2048", "8443" ] ].each do |source, destination|
      assert resolver.find("10.0.0.1", **query, source_port: source, services: { "tcp/#{destination}" => {} })
    end
    [ [ "2048", "443" ], [ "1024", "8443" ] ].each do |source, destination|
      assert_nil resolver.find("10.0.0.1", **query, source_port: source, services: { "tcp/#{destination}" => {} })
    end
    assert_includes parsed.elements(E::DynamicNat).sole.references, parsed.find(E::ServiceGroup, name: "group")
    cache = Algosec::Config::Cache.new(store: ActiveSupport::Cache::MemoryStore.new)
    cache.save(parsed)
    restored = cache.load(1)
    assert_same restored.find(E::ServiceGroup, name: "group"), restored.elements(E::DynamicNat).sole.service
  end

  def test_palo_alto_nat_service_group_does_not_cross_pair_protocols
    parsed = palo_alto_nat(service_name: "group", services: <<~CONFIG)
      set service dns protocol udp port 53
      set service dns protocol udp source-port 2048
      set service-group group members [ restricted dns ]
    CONFIG
    assert parsed.complete?, parsed.diagnostics.inspect
    resolver = P::Nat::Resolver.new(P::Snapshot.from_config(parsed))
    query = { zone: "outside", direction: :source, flow: { from_zone: "inside", to_zone: "outside" }, peers: { "192.0.2.1" => {} } }
    assert resolver.find("10.0.0.1", **query, source_port: "2048", services: { "udp/53" => {} })
    assert_nil resolver.find("10.0.0.1", **query, source_port: "1024", services: { "udp/53" => {} })
    assert_nil resolver.find("10.0.0.1", **query, source_port: "2048", services: { "tcp/443" => {} })
  end

  def test_palo_alto_nat_missing_service_group_member_blocks_complete_snapshot
    parsed = palo_alto_nat(service_name: "group", services: "set service-group group members [ restricted missing ]\n")
    refute parsed.complete?
    assert_includes parsed.diagnostics.map(&:code), :missing_reference
    assert_raises(P::Error) { P::Snapshot.from_config(parsed) }
  end

  private

  def traffic(parsed, from_zone: "inside", to_zone: "outside", snapshot: nil)
    P::TrafficMatcher.new(snapshot || P::Snapshot.from_config(parsed)).perform(source: "10.0.0.2", destination: "192.0.2.2",
      protocol: "tcp", source_port: "12345", destination_port: "443", from_zone: from_zone, to_zone: to_zone)
  end

  def fortinet(source, destination, zones: true, zone_members: "port1")
    interfaces = <<~CONFIG
      config system interface
        edit port1
          set ip 10.0.0.1 255.255.255.0
        next
        edit port2
          set ip 192.0.2.1 255.255.255.0
        next
        edit port3
          set ip 10.0.1.1 255.255.255.0
        next
        edit port4
          set ip 10.0.2.1 255.255.255.0
        next
      end
    CONFIG
    if zones
      interfaces += <<~CONFIG
        config system zone
          edit inside
            set interface #{zone_members}
          next
          edit outside
            set interface port2
          next
        end
      CONFIG
    end
    config = interfaces + <<~CONFIG
      config firewall policy
        edit 1
          set srcintf #{source}
          set dstintf #{destination}
          set srcaddr all
          set dstaddr all
          set service ALL
          set schedule always
          set action deny
        next
        edit 2
          set srcintf #{zones ? 'inside' : 'any'}
          set dstintf #{zones ? 'outside' : 'any'}
          set srcaddr all
          set dstaddr all
          set service ALL
          set schedule always
          set action accept
        next
      end
    CONFIG
    builtin = E::ServiceObject.new(name: "ALL", vendor: :fortinet, protocol: "any")
    Algosec::Config::Parser.perform(config, vendor: :fortinet, device_id: 1, builtin_services: { "ALL" => builtin })
  end

  def asa_query = { zone: "outside", direction: :source, flow: { from_zone: "inside", to_zone: "outside" }, peers: { "192.0.2.1" => {} } }

  def asa_resolver(manual, extra_objects: "")
    config = <<~CONFIG
      object network private
       host 10.0.0.1
      !
      object network public
       host 203.0.113.1
      !
      object network internal
       subnet 10.0.0.0 255.0.0.0
       nat (inside,outside) dynamic public
      !
      #{extra_objects}
      #{manual}
    CONFIG
    parsed = Algosec::Config::Parser.perform(config, vendor: :asa, device_id: 1, strict: true)
    P::Nat::Resolver.new(P::Snapshot.from_config(parsed, software_version: "9.12(4)"))
  end

  def palo_alto_nat(to_zone: "outside", service_name: "restricted", services: "")
    config = <<~CONFIG
      set service restricted protocol tcp port 443
      set service restricted protocol tcp source-port 1024
      #{services}
      set rulebase nat rules snat from inside
      set rulebase nat rules snat to #{to_zone}
      set rulebase nat rules snat source 10.0.0.1
      set rulebase nat rules snat destination any
      set rulebase nat rules snat service #{service_name}
      set rulebase nat rules snat source-translation dynamic-ip-and-port translated-address 203.0.113.1
    CONFIG
    Algosec::Config::Parser.perform(config, vendor: :palo_alto, device_id: 1)
  end
end
