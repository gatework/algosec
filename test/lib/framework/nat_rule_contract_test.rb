# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "support/policy_factory"

class NatRuleContractTest < Minitest::Test
  include PolicyFactory

  def test_translation_directions_are_siblings_with_shared_value_constraints
    source = E::Nat::SourceTranslation.new(mode: :static_ip, addresses: Algosec::IPAddr.parse("203.0.113.1"))
    destination = E::Nat::DestinationTranslation.new(mode: :static, addresses: Algosec::IPAddr.parse("10.0.0.1"))
    assert_kind_of E::Nat::Translation, source
    assert_kind_of E::Nat::Translation, destination
    refute_kind_of E::Nat::SourceTranslation, destination
    assert_equal :static, source.allocation_mode
    assert_equal :static, destination.allocation_mode
    assert_predicate source, :frozen?
    assert_predicate destination, :frozen?
    assert_raises(ArgumentError) { E::Nat::SourceTranslation.new(mode: :static) }
    assert_raises(ArgumentError) { E::Nat::DestinationTranslation.new(mode: :dynamic_ip_and_port) }
  end

  def test_ten_vendors_expose_same_nat_instance_and_immutable_packet
    VENDORS.each do |vendor|
      nat = dynamic(vendor)
      assert_kind_of E::NatRule, nat, vendor.to_s
      assert_equal :dynamic_nat, nat.element_type
      assert_kind_of E::Nat::OriginalPacket, nat.original_packet
      assert_kind_of E::Nat::SourceTranslation, nat.source_translation
      assert_kind_of E::Nat::DestinationTranslation, nat.destination_translation
      assert_same nat.source_set, nat.original_packet.source_addresses
      assert_same nat.destination_set, nat.original_packet.destination_addresses
      assert_same nat.translated_source_set, nat.source_translation.addresses
      assert_predicate nat.original_packet, :frozen?
      assert_predicate nat.source_translation, :frozen?
      assert_respond_to nat, :stage
      assert_respond_to nat, :position
      assert_same nat, snapshot(vendor, [ nat ]).nat_rules.first
    end
  end

  def test_static_mapping_keeps_positional_pairs_and_legacy_aliases
    nat = E::StaticNat.new(**context(:generic), real_ip: "10.0.0.1", mapped_ip: "203.0.113.9",
                           mappings: [ [ "10.0.0.2", "203.0.113.8" ], [ "10.0.0.1", "203.0.113.9" ] ])
    assert_kind_of E::NatRule, nat
    assert_same nat.mappings, nat.source_translation.mappings
    assert_same nat.real_set, nat.original_packet.source_addresses
    assert_same nat.mapped_set, nat.source_translation.addresses
    assert_nil nat.destination_translation.addresses
    assert_equal :none, nat.destination_translation.mode
    refute_predicate nat, :dual_translation?
    assert_equal Algosec::IPAddr.parse("203.0.113.9"), nat.translate("10.0.0.1")
    assert_equal Algosec::IPAddr.parse("10.0.0.2"), nat.reverse_translate("203.0.113.8")
    assert_nil nat.stage
  end

  def test_native_stage_and_order_are_separate_from_identity
    first = dynamic(:asa, nat_order: [ 1, 4 ])
    last = dynamic(:asa, nat_order: [ 3, 9 ])
    assert_equal :before_auto, first.stage
    assert_equal :after_auto, last.stage
    assert_equal [ 1, 4 ], first.position
    assert_equal first.identity, last.identity
    assert_equal :policy, dynamic(:palo_alto).stage
    assert_equal :source, dynamic(:srx, rule_set: "source-rules").stage
    assert_equal :policy, dynamic(:fortinet, policy_id: "7").stage
  end

  def test_unknown_mode_is_retained_and_cannot_be_successful_translation
    nat = dynamic(:palo_alto, nat_type: "arbitrary-mode")
    assert_equal :unknown, nat.source_translation.mode
    assert_equal "arbitrary-mode", nat.source_translation.native_mode
    refute_predicate nat.source_translation, :known?
    error = assert_raises(P::Error) do
      P::Nat::Resolver.new(snapshot(:palo_alto, [ nat ])).find("10.0.0.1", zone: "outside", direction: :source,
        peers: { "192.0.2.1" => {} }, flow: { from_zone: "inside", to_zone: "outside" })
    end
    assert_equal :conditional_nat, error.code
  end

  def test_translation_modes_validate_input_and_preserve_exemption
    assert_raises(ArgumentError) { E::Nat::SourceTranslation.new(mode: :imaginary) }
    nat = dynamic(:palo_alto, translated_source_set: nil, extra_conf: { "no_translation" => true })
    assert_predicate nat, :exempt?
    assert_equal :none, nat.source_translation.mode
    assert_equal :none, nat.destination_translation.mode
    assert_predicate nat.source_translation, :known?
  end

  def test_both_transformations_are_distinct_from_reverse_rule_generation
    nat = dynamic(:palo_alto, direction: :bidirectional, nat_type: "static-ip",
                   translated_destination_set: "192.0.2.8", extra_conf: {
                     "panos" => { "translations" => [ %w[source-translation static-ip bi-directional no] ] }
                   })
    assert_equal :bidirectional, nat.direction
    assert_predicate nat, :dual_translation?
    refute_predicate nat, :bidirectional?
    assert_equal false, nat.bidirectional
    assert_equal :static_ip, nat.source_translation.mode
    assert_equal :static, nat.destination_translation.mode
    assert_equal Algosec::IPAddr.parse("192.0.2.8"), nat.destination_translation.addresses
  end

  def test_cache_roundtrip_preserves_published_nat_values_and_shared_match_rule
    require "algosec/config/cache/entry"
    parsed = Algosec::Config::Parser.perform("policy mip 9 10.0.0.1 203.0.113.9\npolicy mip 9 matching protocol tcp port 443\n", vendor: :neteye, device_id: 1)
    assert parsed.complete?, parsed.diagnostics.inspect
    entry = Algosec::Config::Cache.const_get(:Entry).new(parsed)
    restored = Marshal.load(Marshal.dump(entry)).restore
    nat = restored.elements(E::NatRule).sole
    assert_predicate nat, :sealed?
    assert_predicate nat.original_packet, :frozen?
    assert_predicate nat.source_translation, :frozen?
    assert_predicate nat.destination_translation, :frozen?
    assert_same nat.match_rule, nat.original_packet.match_rule
    assert_same nat.real_set, nat.original_packet.source_addresses
    assert_same nat.mapped_set, nat.source_translation.addresses
  end

  def test_same_zone_explicit_rules_run_before_native_intrazone_default
    deny = rule(:palo_alto, name: "deny-local", from_zones: [ "inside" ], to_zones: [ "inside" ],
                rule_number: 1, rule_set: "vsys1/rulebase", action: "deny", rule_type: :intrazone)
    base = snapshot(:palo_alto, [ deny ]).rulebase(from_zone: "inside", to_zone: "inside")
    assert_kind_of E::Rulebase, base
    assert_equal "allow", base.default_action
    assert_same deny, base.first_match { true }
    assert_equal "deny", base.action_for { true }
    assert_equal "allow", base.action_for { false }
    assert_equal [ deny ], base.ordered_rules
    assert_equal 1, base.scope.device_id
  end

  def test_explicit_default_rule_precedes_native_fallback
    explicit = rule(:palo_alto, name: "explicit", from_zones: "inside", to_zones: "inside",
                    rule_number: 1, rule_set: "vsys1/rulebase")
    default = rule(:palo_alto, name: "intrazone-default", from_zones: "any", to_zones: "any",
                   rule_number: 2, rule_set: "vsys1/rulebase/default-security-rules", rule_type: :intrazone,
                   action: "deny", vendor_data: { "panos" => '{"family":"default-security-rules"}' })
    base = snapshot(:palo_alto, [ default, explicit ]).rulebase(from_zone: "inside", to_zone: "inside")
    assert_equal [ explicit, default ], base.ordered_rules
    assert_equal "deny", base.action_for { |candidate| candidate.equal?(default) }
    scoped = snapshot(:palo_alto, [ default, explicit ]).rulebase(from_zone: "inside", to_zone: "inside", rule_set: "vsys1/rulebase")
    assert_equal [ explicit, default ], scoped.ordered_rules
    assert_equal "deny", scoped.action_for { |candidate| candidate.equal?(default) }
  end

  def test_unknown_predicate_or_explicit_action_never_falls_back_to_allow
    unknown = rule(:palo_alto, name: "unknown", action: "unrecognized", from_zones: "inside", to_zones: "inside")
    base = snapshot(:palo_alto, [ unknown ]).rulebase(from_zone: "inside", to_zone: "inside")
    assert_nil base.action_for { true }
    assert_equal :conditional_policy, assert_raises(P::Error) { base.action_for { nil } }.code
    assert_nil snapshot(:hillstone).rulebase(from_zone: "inside", to_zone: "inside").default_action
    assert_equal "deny", snapshot(:palo_alto).rulebase(from_zone: "inside", to_zone: "outside").default_action
  end

  def test_address_only_translation_preserves_unknown_allocation_mode
    nat = dynamic(:palo_alto)
    assert_nil nat.source_translation.mode
    assert_nil nat.source_translation.allocation_mode
    resolver = P::Nat::Resolver.new(snapshot(:palo_alto, [ nat ]))
    options = { zone: "outside", direction: :source, peers: { "192.0.2.1" => {} },
                flow: { from_zone: "inside", to_zone: "outside" } }
    found = resolver.find("10.0.0.1", **options)
    assert_predicate nat.source_translation, :address_targets_known?
    assert_same nat, found.fetch(:rule)
    error = assert_raises(P::Error) { resolver.find("10.0.0.1", **options, allocation: { type: :dynamic, address: "203.0.113.1" }) }
    assert_equal :conditional_nat, error.code
  end

  def test_pan_parser_records_native_nat_position_independent_of_name
    parsed = Algosec::Config::Parser.perform(<<~CONFIG, vendor: :palo_alto, device_id: 1)
      set rulebase nat rules z-first from any
      set rulebase nat rules z-first to any
      set rulebase nat rules z-first source 10.0.0.1
      set rulebase nat rules z-first destination any
      set rulebase nat rules z-first source-translation dynamic-ip translated-address 203.0.113.1
      set rulebase nat rules a-second from any
      set rulebase nat rules a-second to any
      set rulebase nat rules a-second source 10.0.0.1
      set rulebase nat rules a-second destination any
      set rulebase nat rules a-second source-translation dynamic-ip translated-address 203.0.113.2
    CONFIG
    assert parsed.complete?, parsed.diagnostics.inspect
    nats = parsed.elements(E::NatRule)
    assert_equal %w[z-first a-second], nats.map(&:name)
    assert_equal [ [ 1 ], [ 2 ] ], nats.map(&:position)
    assert_equal [ :dynamic, :dynamic ], nats.map { |nat| nat.source_translation.allocation_mode }
  end

  def test_scope_does_not_merge_different_virtual_systems
    rows = [ "vsys1", "vsys2" ].each_with_index.map do |system, index|
      rule(:palo_alto, name: "rule#{index}", rule_number: index + 1, rule_set: "shared-name",
        scope: E::Scope.new(device_id: 1, virtual_system: system))
    end
    snap = snapshot(:palo_alto, rows)
    error = assert_raises(P::RuleOrder::Unproven) { snap.rulebase(from_zone: "inside", to_zone: "outside").ordered_rules }
    assert_equal :chains, error.reason
    base = snap.rulebase(from_zone: "inside", to_zone: "outside", scope: E::Scope.new(device_id: 1, virtual_system: "vsys2"))
    assert_equal [ rows.last ], base.ordered_rules
    assert_raises(ArgumentError) { snap.rulebase(from_zone: "inside", to_zone: "outside", scope: E::Scope.new(device_id: 2)) }
  end

  def test_translation_value_rejects_mutable_or_invalid_members
    assert_raises(ArgumentError) { E::Nat::SourceTranslation.new(mode: :static_ip, mappings: [ "invalid" ].freeze) }
    assert_raises(ArgumentError) { E::Nat::OriginalPacket.new(source_zones: [ nil ]) }
    assert_raises(ArgumentError) { E::Nat::SourceTranslation.new(mode: :static_ip, port: "65536") }
  end

  def test_unknown_native_mode_is_not_ignored_on_destination_translation
    nat = dynamic(:palo_alto, direction: :destination, translated_source_set: nil,
                  nat_type: "arbitrary-mode", translated_destination_set: "192.0.2.8")
    refute_predicate nat, :translation_known?
    refute_predicate nat.source_translation, :address_targets_known?
  end

  def test_fortinet_vip_original_packet_matches_the_public_destination
    nat = E::StaticNat.new(**context(:fortinet), name: "vip", real_ip: "10.0.0.9", mapped_ip: "203.0.113.9",
                           interface: "outside", mapped_zone: "outside", real_zone: "inside", source_nat_enabled: false)
    assert_same nat.mapped_set, nat.original_packet.destination_addresses
    assert_nil nat.original_packet.source_addresses
    assert_equal [ "outside" ], nat.original_packet.source_zones
    assert_equal [ "inside" ], nat.original_packet.destination_zones
    assert_equal :none, nat.source_translation.mode
    assert_same nat.real_set, nat.destination_translation.addresses
  end

  def test_source_modes_follow_pan_names_and_keep_interface_selection_separate
    { "static-ip" => :static_ip, "dynamic-ip" => :dynamic_ip,
      "dynamic-ip-and-port" => :dynamic_ip_and_port }.each do |native, canonical|
      nat = dynamic(:palo_alto, nat_type: native)
      assert_equal canonical, nat.source_translation.mode
      assert_equal native, nat.source_translation.native_mode
    end
    nat = dynamic(:palo_alto, interface: "matching-interface", nat_type: "dynamic-ip-and-port", extra_conf: {
      "panos" => { "translations" => [ %w[source-translation dynamic-ip-and-port interface-address interface translated-interface] ] }
    })
    assert_equal "translated-interface", nat.source_translation.interface
    assert_equal "matching-interface", nat.original_packet.interface
    easy_ip = dynamic(:huawei, interface: "outside", extra_conf: { "source_mode" => "easy-ip" })
    assert_equal :dynamic_ip_and_port, easy_ip.source_translation.mode
    assert_equal "outside", easy_ip.source_translation.interface
  end

  def test_native_default_requires_the_selected_local_execution_context
    deny = rule(:palo_alto, name: "deny", action: "deny", rule_number: 1,
                rule_set: "vsys1/rulebase", from_zones: "inside", to_zones: "inside")
    snap = snapshot(:palo_alto, [ deny ])
    missing = snap.rulebase(from_zone: "inside", to_zone: "inside", rule_set: "missing-chain")
    assert_nil missing.action_for { true }
    assert_equal "missing-chain", missing.rule_set
    [ E::Scope.new(device_id: 1, virtual_system: "vsys2"),
      E::Scope.new(device_id: 1, rulebase: "pre-rulebase"),
      E::Scope.new(device_id: 1, virtual_system: "vsys1") ].each do |scope|
      assert_nil snap.rulebase(from_zone: "inside", to_zone: "inside", scope: scope).action_for { true }
    end
    assert_equal "deny", snap.rulebase(from_zone: "inside", to_zone: "inside", rule_set: "vsys1/rulebase").action_for { true }
    assert_nil snapshot(:palo_alto).rulebase(from_zone: "inside", to_zone: "inside", rule_set: "missing-chain").default_action
  end

  def test_explicit_allocation_uses_canonical_mode_instead_of_legacy_nat_class
    nat = dynamic(:palo_alto, nat_type: "static-ip")
    resolver = P::Nat::Resolver.new(snapshot(:palo_alto, [ nat ]))
    options = { zone: "outside", direction: :source, peers: { "192.0.2.1" => {} },
                flow: { from_zone: "inside", to_zone: "outside" } }
    assert_same nat, resolver.find("10.0.0.1", **options, allocation: { type: :static, address: "203.0.113.1" }).fetch(:rule)
    error = assert_raises(P::Error) { resolver.find("10.0.0.1", **options, allocation: { type: :dynamic, address: "203.0.113.1" }) }
    assert_equal :conditional_nat, error.code
  end

  def test_asa_forward_static_nat_does_not_invent_simultaneous_destination_translation
    parsed = Algosec::Config::Parser.perform("object network REAL\n host 10.0.0.1\n nat (inside,outside) static 203.0.113.1\n", vendor: :asa, device_id: 1)
    assert parsed.complete?, parsed.diagnostics.inspect
    nat = parsed.elements(E::StaticNat).sole
    assert_equal :none, nat.destination_translation.mode
    assert_nil nat.destination_translation.addresses
    assert_same nat.real_set, nat.original_packet.source_addresses
    refute_predicate nat, :dual_translation?
    assert_equal Algosec::IPAddr.parse("10.0.0.1"), nat.reverse_translate("203.0.113.1")
  end

  def test_proven_disabled_rules_do_not_poison_active_rule_order
    deny = rule(:palo_alto, name: "deny", action: "deny", rule_number: 1, rule_set: "vsys1/rulebase")
    inactive = rule(:palo_alto, name: "inactive", rule_number: nil, rule_set: "other", disabled: true,
                    scope: E::Scope.new(device_id: 1, virtual_system: "vsys2"))
    snap = snapshot(:palo_alto, [ deny, inactive ])
    base = snap.rulebase(from_zone: "inside", to_zone: "outside")
    assert_equal [ deny ], base.ordered_rules
    assert_equal "deny", base.action_for { true }
    assert_includes snap.rules, inactive
  end

  def test_temporal_filter_requires_known_status_schedule_and_command_semantics
    now = Time.utc(2030, 1, 1, 12)
    deny = rule(:palo_alto, name: "deny", action: "deny", rule_number: 1, rule_set: "vsys1/rulebase")
    future = rule(:palo_alto, name: "future", conditions: { starts_at: (now + 3600).iso8601 }, rule_number: nil, rule_set: "vsys1/rulebase")
    base = snapshot(:palo_alto, [ deny, future ]).rulebase(from_zone: "inside", to_zone: "outside")
    assert_raises(P::RuleOrder::Unproven) { base.ordered_rules }
    assert_equal [ deny ], base.ordered_rules(at: now)
    assert_raises(P::RuleOrder::Unproven) { base.ordered_rules(at: now + 7200) }
    [ { status: "unrecognized", conditions: { expires_at: (now - 1).iso8601 } },
      { schedule_name: "missing", conditions: { expires_at: (now - 1).iso8601 } },
      { disabled: true, conditions: { unparsed_commands: [ "unrecognized status command" ] } } ].each_with_index do |attributes, index|
      unknown = rule(:palo_alto, name: "unknown#{index}", rule_number: nil, rule_set: "vsys1/rulebase", **attributes)
      current = snapshot(:palo_alto, [ deny, unknown ], resolve_references: false).rulebase(from_zone: "inside", to_zone: "outside")
      assert_raises(P::RuleOrder::Unproven) { current.ordered_rules(at: now) }
    end
  end

  def test_destination_allocation_also_uses_canonical_mode
    nat = dynamic(:palo_alto, direction: :destination, from_zone: "outside", to_zone: "inside",
                  source_set: "0.0.0.0/0", destination_set: "203.0.113.9", translated_source_set: nil,
                  translated_destination_set: "10.0.0.9")
    resolver = P::Nat::Resolver.new(snapshot(:palo_alto, [ nat ]))
    options = { zone: "outside", direction: :destination, peers: { "198.51.100.1" => {} },
                flow: { from_zone: "outside", to_zone: "inside", original_dst: "203.0.113.9" } }
    assert_same nat, resolver.find("10.0.0.9", **options, allocation: { type: :static, address: "203.0.113.9" }).fetch(:rule)
    error = assert_raises(P::Error) { resolver.find("10.0.0.9", **options, allocation: { type: :dynamic, address: "203.0.113.9" }) }
    assert_equal :conditional_nat, error.code
  end

  def test_proven_local_scope_can_apply_native_default_after_explicit_rules
    scope = E::Scope.new(device_id: 1, virtual_system: "vsys1", rulebase: "rulebase")
    deny = rule(:palo_alto, name: "deny", action: "deny", rule_number: 1,
                rule_set: "vsys1/rulebase", from_zones: "inside", to_zones: "inside", scope: scope)
    base = snapshot(:palo_alto, [ deny ]).rulebase(from_zone: "inside", to_zone: "inside", rule_set: "vsys1/rulebase", scope: scope)
    assert_equal "deny", base.action_for { true }
    assert_equal "allow", base.action_for { false }
  end

  def test_known_expired_and_resolved_inactive_schedule_do_not_poison_order
    now = Time.utc(2030, 1, 1, 12)
    deny = rule(:palo_alto, name: "deny", action: "deny", rule_number: 1, rule_set: "vsys1/rulebase")
    expired = rule(:palo_alto, name: "expired", rule_number: nil, rule_set: "vsys1/rulebase",
                   conditions: { expires_at: (now - 1).iso8601 })
    schedule = E::Schedule.new(**context(:palo_alto), name: "future", start_at: now + 3600, end_at: now + 7200)
    later = rule(:palo_alto, name: "later", rule_number: nil, rule_set: "vsys1/rulebase", schedule: schedule)
    base = snapshot(:palo_alto, [ deny, expired, later ]).rulebase(from_zone: "inside", to_zone: "outside")
    assert_equal [ deny ], base.ordered_rules(at: now)
    assert_equal "deny", base.action_for(at: now) { true }
  end

  def test_explicit_pan_chain_cannot_treat_missing_chain_evidence_as_empty
    deny = rule(:palo_alto, name: "implicit-local-deny", action: "deny", rule_number: 1,
                from_zones: "inside", to_zones: "inside")
    snap = snapshot(:palo_alto, [ deny ])
    assert_equal "deny", snap.rulebase(from_zone: "inside", to_zone: "inside").action_for { true }
    selected = snap.rulebase(from_zone: "inside", to_zone: "inside", rule_set: "vsys1/rulebase")
    assert_nil selected.default_action
    assert_nil selected.action_for { true }
  end

  def test_selected_reverse_static_mapping_accepts_static_intent_without_forward_dnat
    parsed = Algosec::Config::Parser.perform("object network REAL\n host 10.0.0.1\n nat (inside,outside) static 203.0.113.1\n", vendor: :asa, device_id: 1)
    assert parsed.complete?, parsed.diagnostics.inspect
    nat = parsed.elements(E::StaticNat).sole
    resolver = P::Nat::Resolver.new(snapshot(:asa, [ nat ]))
    options = { zone: "outside", direction: :destination, peers: { "198.51.100.1" => {} },
                flow: { original_dst: "203.0.113.1", from_zone: "outside", to_zone: "inside" } }
    assert_same nat, resolver.find("10.0.0.1", **options).fetch(:rule)
    matched = resolver.find("10.0.0.1", **options, allocation: { type: :static, address: "203.0.113.1" })
    assert_same nat, matched.fetch(:rule)
    assert_equal "203.0.113.1/32", matched.fetch(:address)
    assert_equal :none, nat.destination_translation.mode
    assert_nil nat.destination_translation.addresses
    refute_predicate nat, :dual_translation?
    [ { type: :dynamic, address: "203.0.113.1" }, { type: :static, address: "203.0.113.2" },
      { type: :static, address: "203.0.113.1", direction: :source } ].each do |allocation|
      assert_equal :conditional_nat, assert_raises(P::Error) { resolver.find("10.0.0.1", **options, allocation: allocation) }.code
    end
  end

  private

  def dynamic(vendor, **attributes)
    E::DynamicNat.new(**context(vendor), name: "nat1", id: "1", policy_id: "1", rule_set: "nat-rules", direction: :source,
      from_zone: "inside", to_zone: "outside", source_set: "10.0.0.1", destination_set: "0.0.0.0/0",
      translated_source_set: "203.0.113.1", **attributes)
  end
end
