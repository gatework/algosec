# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "support/policy_factory"
require_relative "support/policy_config"
require "algosec/config"

class PolicyMigrationTest < Minitest::Test
  include PolicyFactory
  include PolicyConfig

  # 此矩阵使用一个真实入口 ACL；共享 ACL 的额外入口另有扩大范围阻断回归。
  def snapshot(vendor, objects = [], **options)
    graph = super
    return graph unless vendor == :asa
    outside = graph.zone("outside")
    replacement = E::Zone.new(name: "outside", vrf: outside.vrf, interfaces: outside.interfaces.values,
      **context(vendor, device_id: graph.device_id))
    graph.with_catalog(E::Catalog.new(graph.catalog.to_a - [ outside ] + [ replacement ], **context(vendor, device_id: graph.device_id)))
  end

  def migrate(source, target, **options)
    options[:source_zone_pairs] = [ [ "inside", "outside" ] ] if source.vendor == :asa
    P::Migration.new(source: source, target: target, zones: { "inside" => "inside", "outside" => "outside" }, **options).perform
  end

  def target(vendor)
    settings = (vendor == :h3c) ? { policy_bindings: [ { name: "objects", from_zone: "inside", to_zone: "outside" } ] } : {}
    snapshot(vendor, device_id: 2, settings: settings)
  end

  def test_all_vendor_pairs_use_target_syntax_and_keep_exact_ranges
    VENDORS.each do |source_vendor|
      original = rule(source_vendor, rule_number: 1)
      source = snapshot(source_vendor, [ original ])
      VENDORS.each do |target_vendor|
        plan = migrate(source, target(target_vendor))
        if %i[asa hillstone].include?(target_vendor)
          refute plan.ready?, "#{source_vendor} -> #{target_vendor} lost zone scope or unspecified logging"
          assert_equal target_vendor == :asa ? :unsupported_zone_scope : :unsupported_logging, plan.issues.first.evidence[:code]
          assert_raises(P::Error) { plan.script }
          next
        end
        assert plan.ready?, "#{source_vendor} -> #{target_vendor}: #{plan.issues.map(&:message).join('; ')}"
        assert_equal source.signature(original), plan.changes.first[:source_rule_id]
        parsed = Algosec::Config::Parser.perform(saved_config(target_vendor, plan.script), vendor: target_vendor, device_id: 2)
        assert parsed.complete?, "#{target_vendor}: #{parsed.diagnostics.map(&:message).join('; ')}"
        assert_equal 1, parsed.rules.size, target_vendor.to_s
        assert_equal P::Ranges.projection(original), P::Ranges.projection(parsed.rules.first), target_vendor.to_s
        assert_equal original.action, parsed.rules.first.action, target_vendor.to_s
        assert_nil parsed.rules.first.log, target_vendor.to_s
        assert_nil parsed.rules.first.log_enabled, target_vendor.to_s
        refute_match(/\bX{3,}\b/, plan.script)
      end
    end
  end

  def test_deny_actions_round_trip_for_each_target
    original = rule(:fortinet, action: "deny", rule_number: 1)
    source = snapshot(:fortinet, [ original ])
    VENDORS.each do |vendor|
      destination = target(vendor)
      plan = migrate(source, destination)
      if %i[asa h3c hillstone].include?(vendor)
        refute plan.ready?
        assert_equal({ asa: :unsupported_zone_scope, h3c: :unsupported_action, hillstone: :unsupported_logging }.fetch(vendor), plan.issues.first.evidence[:code])
        assert_raises(P::Error) { plan.script }
        next
      end
      assert plan.ready?, "#{vendor}: #{plan.issues.map(&:message).join('; ')}"
      parsed = Algosec::Config::Parser.perform(saved_config(vendor, plan.script), vendor: vendor, device_id: 2)
      assert parsed.complete?, "#{vendor}: #{parsed.diagnostics.map(&:message).join('; ')}"
      assert_equal 1, parsed.rules.size
      assert_equal :deny, destination.behavior.rule_decision(parsed.rules.first), vendor.to_s
    end
  end

  def test_prepend_and_append_preserve_final_device_priority
    deny = rule(:fortinet, name: "20", action: "deny", rule_number: 1, source: "10.0.0.1/32")
    allow = rule(:fortinet, name: "1", rule_number: 2, source: "10.0.0.0/24")
    source = snapshot(:fortinet, [ allow, deny ])
    VENDORS.each do |vendor|
      destination = target(vendor)
      plan = migrate(source, destination)
      if %i[asa h3c hillstone].include?(vendor)
        refute plan.ready?
        assert_equal({ asa: :unsupported_zone_scope, h3c: :unsupported_action, hillstone: :unsupported_logging }.fetch(vendor), plan.issues.first.evidence[:code])
        next
      end
      assert plan.ready?, plan.issues.map(&:message).join("; ")
      assert_equal [ :deny, :permit ], plan.changes.map { |change| change[:decision] }
      assert_equal plan.script, migrate(source, target(vendor)).script
      parsed = Algosec::Config::Parser.perform(saved_config(vendor, plan.script), vendor: vendor, device_id: 2)
      assert parsed.complete?, "#{vendor}: #{parsed.diagnostics.map(&:message).join('; ')}"
      assert_equal [ :deny, :permit ], parsed.rules.map { |rule| destination.behavior.rule_decision(rule) }, vendor.to_s
      { "10.0.0.1" => :deny, "10.0.0.2" => :permit }.each do |address, expected|
        first = parsed.rules.find { |rule| rule.sources.resolved_set.include?(Algosec::IPAddr.to_i(address)) }
        assert_equal expected, destination.behavior.rule_decision(first), "#{vendor}: #{address}"
      end
    end
  end

  def test_palo_alto_zone_types_are_filtered_before_zone_mapping
    destination = snapshot(:fortinet, [], device_id: 2)
    { "interzone" => [ [ "inside", "outside" ], [ "outside", "inside" ] ],
      "intrazone" => [ [ "inside", "inside" ], [ "outside", "outside" ] ] }.each do |kind, expected|
      config = <<~CONFIG
        set shared service web protocol tcp port 443
        set rulebase security rules scoped from [ trusted untrusted ]
        set rulebase security rules scoped to [ trusted untrusted ]
        set rulebase security rules scoped source 0.0.0.0/0
        set rulebase security rules scoped destination 0.0.0.0/0
        set rulebase security rules scoped service web
        set rulebase security rules scoped application any
        set rulebase security rules scoped rule-type #{kind}
        set rulebase security rules scoped action allow
      CONFIG
      parsed = Algosec::Config::Parser.perform(config, vendor: :palo_alto, device_id: 1)
      assert parsed.complete?, parsed.diagnostics.map(&:message).join("; ")
      source = P::Snapshot.from_config(parsed)
      plan = P::Migration.new(source: source, target: destination,
                              zones: { "trusted" => "inside", "untrusted" => "outside" }).perform
      assert plan.ready?, plan.issues.map(&:message).join("; ")
      assert_equal expected, plan.changes.first[:results].map { |result| result.values_at(:from_zone, :to_zone) }, kind
      zone_config = "config system zone\n edit inside\n next\n edit outside\n next\nend\n"
      generated = Algosec::Config::Parser.perform(zone_config + saved_config(:fortinet, plan.script), vendor: :fortinet, device_id: 2)
      assert generated.complete?, generated.diagnostics.map(&:message).join("; ")
      assert_equal expected, generated.rules.map { |rule| [ rule.from_zones.sole, rule.to_zones.sole ] }, kind
    end
  end

  def test_independent_source_rules_keep_distinct_target_identities
    originals = (1..3).map { |id| rule(:fortinet, name: id.to_s, rule_number: id, source: "10.0.#{id}.0/24") }
    source = snapshot(:fortinet, originals)
    # ASA 的相同 ACL 命令按既有语义去重；其他厂商以名称或编号区分规则。
    (VENDORS - [ :asa ]).each do |vendor|
      plan = migrate(source, target(vendor))
      if vendor == :hillstone
        refute plan.ready?
        assert_equal :unsupported_logging, plan.issues.first.evidence[:code]
        next
      end
      assert plan.ready?, plan.issues.map(&:message).join("; ")
      assert_equal originals.map { |rule| source.signature(rule) }, plan.changes.map { |change| change[:source_rule_id] }
      parsed = Algosec::Config::Parser.perform(saved_config(vendor, plan.script), vendor: vendor, device_id: 2)
      assert parsed.complete?, "#{vendor}: #{parsed.diagnostics.map(&:message).join('; ')}"
      assert_equal 3, parsed.rules.size, vendor.to_s
      assert_equal 3, parsed.rules.map(&:identity).uniq.size, vendor.to_s
      expected = originals.map { |rule| P::Ranges.projection(rule) }
      assert parsed.rules.all? { |rule| expected.include?(P::Ranges.projection(rule)) }
    end
  end

  def test_migration_reuses_target_objects_by_exact_range
    objects = [ E::AddressObject.new(**context(:srx, device_id: 2), name: "existing-source", zone: "inside", member: [ { type: "subnet", value: "10.0.0.0/24" } ]),
               E::AddressObject.new(**context(:srx, device_id: 2), name: "existing-destination", zone: "outside", member: [ { type: "host", value: "192.0.2.1" } ]),
               E::ServiceObject.new(**context(:srx, device_id: 2), name: "existing-service", protocol: "tcp", destination_port: "443") ]
    original = rule(:fortinet, rule_number: 1)
    plan = migrate(snapshot(:fortinet, [ original ]), snapshot(:srx, objects, device_id: 2))

    assert plan.ready?, plan.issues.map(&:message).join("; ")
    assert_includes plan.script, "match source-address existing-source"
    assert_includes plan.script, "match destination-address existing-destination"
    assert_includes plan.script, "match application existing-service"
    refute_includes plan.script, "address-book address"
    refute_includes plan.script, "set applications application"
  end

  def test_numbered_targets_keep_multiple_members_in_one_rule_without_placeholders
    original = rule(:fortinet, rule_number: 1, services: [ "tcp/443", "udp/53" ])
    original.sources.add("second", E::AddressObject.new(**context(:fortinet), name: "second", member: [ { type: "host", value: "10.2.0.1" } ]))
    source = snapshot(:fortinet, [ original ])
    %i[h3c netscreen].each do |vendor|
      plan = migrate(source, target(vendor))
      assert plan.ready?, plan.issues.map(&:message).join("; ")
      assert_equal 1, plan.changes.first[:results].size
      refute_match(/\bX{3,}\b/, plan.script)
      parsed = Algosec::Config::Parser.perform(saved_config(vendor, plan.script), vendor: vendor, device_id: 2)
      assert parsed.complete?, parsed.diagnostics.map(&:message).join("; ")
      assert_equal 1, parsed.rules.size
      assert_equal P::Ranges.projection(original), P::Ranges.projection(parsed.rules.first)
    end
  end

  def test_unknown_action_or_logging_blocks_entire_plan_without_partial_script
    allowed = rule(:srx, name: "1", rule_number: 1)
    rejected = rule(:srx, name: "2", rule_number: 2, action: "reject")
    source = snapshot(:srx, [ allowed, rejected ])
    plan = migrate(source, target(:fortinet))
    refute plan.ready?
    assert_equal :unsupported_action, plan.issues.first.evidence[:code]
    assert_equal source.signature(rejected), plan.issues.first.rule_id
    assert_equal 1, plan.changes.size
    assert_raises(P::Error) { plan.script }
    logged = rejected.with(action: "permit", log: "session-init")
    assert_equal :unsupported_logging, migrate(snapshot(:srx, [ allowed, logged ]), target(:fortinet)).issues.first.evidence[:code]
  end

  def test_explicit_logging_state_requires_target_mapping_even_without_legacy_options
    [ true, false ].each do |enabled|
      original = rule(:hillstone, rule_number: 1, log_enabled: enabled)
      assert_nil original.log
      plan = migrate(snapshot(:hillstone, [ original ]), target(:fortinet))
      refute plan.ready?
      assert_equal :unsupported_logging, plan.issues.first.evidence[:code]
      assert_raises(P::Error) { plan.script }
    end
  end

  def test_hillstone_disabled_logging_round_trips_without_losing_the_state
    content = <<~CONFIG
      zone inside
      exit
      zone outside
      exit
      service web
        tcp dst-port 443
      exit
      rule id 7
        src-zone inside
        dst-zone outside
        src-ip 10.0.0.0/24
        dst-ip 192.0.2.1/32
        service web
        action permit
      exit
    CONFIG
    parsed = Algosec::Config::Parser.perform(content, vendor: :hillstone, device_id: 1)
    source = P::Snapshot.from_config(parsed)
    assert_equal false, source.rules.sole.log_enabled
    plan = migrate(source, target(:hillstone))
    assert plan.ready?, plan.issues.map(&:message).join("; ")
    assert_equal false, plan.changes.sole[:log_enabled]
    roundtrip = Algosec::Config::Parser.perform(saved_config(:hillstone, plan.script), vendor: :hillstone, device_id: 2)
    assert roundtrip.complete?
    assert_equal false, roundtrip.rules.sole.log_enabled
    assert_equal P::Ranges.projection(source.rules.sole), P::Ranges.projection(roundtrip.rules.sole)
  end

  def test_hillstone_does_not_infer_mapping_for_enabled_or_detailed_logging
    [ { log_enabled: true }, { log_enabled: false, log: "session-end" } ].each do |attributes|
      source = snapshot(:hillstone, [ rule(:hillstone, rule_number: 1, **attributes) ])
      plan = migrate(source, target(:hillstone))
      refute plan.ready?
      assert_equal :unsupported_logging, plan.issues.first.evidence[:code]
    end
  end

  def test_native_h3c_drop_round_trips_as_drop_in_an_object_policy
    parsed = Algosec::Config::Parser.perform(<<~CONFIG, vendor: :h3c, device_id: 1)
      security-zone name inside
      #
      security-zone name outside
      #
      object-group ip address clients
       network subnet 10.0.0.0 255.255.255.0
      #
      object-group ip address server
       network host address 192.0.2.1
      #
      object-group service web
       service tcp destination eq 443
      #
      object-policy ip ingress
       rule 10 drop source-ip clients destination-ip server service web
      #
      zone-pair security source inside destination outside
       object-policy apply ip ingress
      #
    CONFIG
    assert parsed.complete?, parsed.diagnostics.map(&:message).join("; ")
    assert_equal "drop", parsed.rules.sole.action
    source = P::Snapshot.from_config(parsed)
    plan = migrate(source, target(:h3c))
    assert plan.ready?, plan.issues.map(&:message).join("; ")
    readback = Algosec::Config::Parser.perform(saved_config(:h3c, plan.script), vendor: :h3c, device_id: 2)
    assert readback.complete?, readback.diagnostics.map(&:message).join("; ")
    assert_equal "drop", readback.rules.sole.action
    assert_equal P::Ranges.projection(parsed.rules.sole), P::Ranges.projection(readback.rules.sole)
  end

  def test_source_and_target_constraints_are_explicit
    original = rule(:fortinet, name: "1", rule_number: 1)
    source = snapshot(:fortinet, [ original ])
    occupied = snapshot(:srx, [ rule(:srx) ])
    assert migrate(source, occupied).ready?, "same-action existing target is compatible"
    no_order = snapshot(:fortinet, [ rule(:fortinet) ])
    assert_equal :unknown_order, migrate(no_order, target(:srx)).issues.first.evidence[:code]
    nat = E::DynamicNat.new(**context(:fortinet), policy_id: "1", direction: :source, match_rule: original)
    with_nat = snapshot(:fortinet, [ original, nat ])
    assert_equal :unsupported_nat_migration, migrate(with_nat, target(:srx)).issues.first.evidence[:code]
    inactive = snapshot(:fortinet, [ original.with(status: "disable") ])
    assert_equal :inactive_rule, migrate(inactive, target(:srx)).issues.first.evidence[:code]
  end

  def test_zone_mapping_is_required_injective_and_exists_in_target
    source = snapshot(:fortinet, [ rule(:fortinet, rule_number: 1) ])
    [ [ {}, :missing_zone_mapping ],
     [ { "inside" => "inside", "outside" => "inside" }, :ambiguous_zone_mapping ],
     [ { "inside" => "missing", "outside" => "outside" }, :missing_target_zone ] ].each do |zones, code|
      plan = P::Migration.new(source: source, target: target(:srx), zones: zones).perform
      assert_equal code, plan.issues.first.evidence[:code]
      assert_raises(P::Error) { plan.script }
    end
  end

  def test_once_schedule_keeps_window_and_unsupported_target_fails
    now = Time.utc(2026, 9, 16, 12)
    schedule = E::Schedule.new(**context(:fortinet), name: "window", start_at: now + 3600, end_at: now + 7200)
    original = rule(:fortinet, rule_number: 1, schedule: schedule)
    source = snapshot(:fortinet, [ original ])
    plan = migrate(source, target(:srx), at: now)
    assert plan.ready?, plan.issues.map(&:message).join("; ")
    parsed = Algosec::Config::Parser.perform(plan.script, vendor: :srx, device_id: 2)
    assert_equal schedule.window, parsed.rules.first.schedule.window
    plan = migrate(source, target(:neteye), at: now)
    assert_equal :unsupported_schedule, plan.issues.first.evidence[:code]
    assert_raises(P::Error) { plan.script }
  end

  def test_inline_nat_without_a_pool_is_retained_by_parser_and_blocks_migration_and_reclaim
    config = File.read(TestPaths.root.join("test/fixtures/config/fortinet.cfg"))
    config = config.sub("set action accept", "set action accept\n        set nat enable")
    parsed = Algosec::Config::Parser.perform(config, vendor: :fortinet, device_id: 1)
    assert parsed.complete?, parsed.diagnostics.map(&:message).join("; ")
    source = P::Snapshot.from_config(parsed)
    assert_equal 1, source.dynamic_nats.size
    assert_nil source.dynamic_nats.sole.source_pool
    assert_equal Algosec::IPAddr.parse("198.51.100.1"), source.dynamic_nats.sole.source_targets
    assert source.rules.first.nat?
    assert_equal :unsupported_nat_migration, migrate(source, target(:srx)).issues.first.evidence[:code]
    disabled = Algosec::Config::Parser.perform(config.sub("set action accept", "set action accept\n        set status disable"), vendor: :fortinet, device_id: 1)
    source = P::Snapshot.from_config(disabled)
    assert_equal :nat_dependency, P::Reclaimer.new(source).plan(rule_ids: [ source.signature(source.rules.first) ]).issues.first.evidence[:code]
  end

  def test_srx_application_services_are_not_silently_consumed_as_plain_permit
    config = <<~CONFIG
      set security policies from-zone inside to-zone outside policy p match source-address any
      set security policies from-zone inside to-zone outside policy p match destination-address any
      set security policies from-zone inside to-zone outside policy p match application any
      set security policies from-zone inside to-zone outside policy p then permit application-services idp
    CONFIG
    parsed = Algosec::Config::Parser.perform(config, vendor: :srx, device_id: 1, strict: false)
    refute parsed.complete?
    assert_raises(P::Error) { P::Snapshot.from_config(parsed) }
  end
end
