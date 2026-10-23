# frozen_string_literal: true

require "test_helper"
require "algosec/policy/plan_document"
require_relative "../framework/support/policy_factory"
require_relative "../framework/support/policy_config"

class MigrationSemanticsTest < ActiveSupport::TestCase
  include PolicyFactory
  include PolicyConfig

  def migrate(source, target, at: Time.utc(2026, 10, 22))
    P::Migration.new(source: source, target: target, zones: { "inside" => "inside", "outside" => "outside" }, at: at).perform
  end

  def destination(vendor = :palo_alto, rules = [])
    snapshot(vendor, rules)
  end

  test "unrelated existing target rule is retained and outside widening fails independent readback" do
    source = snapshot(:fortinet, [ rule(:fortinet, rule_number: 1) ])
    existing = rule(:palo_alto, name: "existing", rule_number: 1, source: "10.9.0.0/24")
    # Factory accepts contextual fields through the rule owner constructor.
    target = destination(:palo_alto, [ existing ])
    plan = migrate(source, target)
    assert plan.ready?, plan.issues.map(&:message).join("; ")
    assert_same existing, plan.change_set.apply.rules.find { |entry| entry.name == "existing" }
    assert_equal source.device_id, plan.source_baseline.fetch(:device_id)
    assert_equal target.device_id, plan.target_baseline.fetch(:device_id)
    candidate = plan.change_set.apply
    changed = candidate.rules.find { |entry| entry.name != "existing" }
    broad = rule(:palo_alto, name: changed.name, native_rule_id: changed.native_rule_id,
      rule_number: changed.rule_number, source: "10.0.0.0/8")
    readback = candidate.with_catalog(E::Catalog.new(candidate.catalog.to_a - [ changed ] + [ broad ], **context(:palo_alto)))
    refute plan.verify_readback(readback).verified?
    assert plan.verify_readback(readback).differences.any? { |item| item.kind == :outside_target }
  end

  test "earlier target deny blocks actual append with a concrete difference" do
    source = snapshot(:fortinet, [ rule(:fortinet, rule_number: 1) ])
    deny = rule(:palo_alto, name: "deny", action: "deny", rule_number: 1)
    plan = migrate(source, destination(:palo_alto, [ deny ]))
    refute plan.ready?
    refute_nil plan.proof
    difference = plan.proof.differences.find { |entry| entry.kind == :target }
    refute_nil difference
    assert_equal "deny", difference.after.action
    refute difference.traffic_set.empty?
    assert_raises(P::Error) { plan.script }
  end

  test "effective source regions retain paired holes instead of cross products" do
    deny = rule(:fortinet, name: "deny", action: "deny", rule_number: 1, source: "10.0.0.1", destination: "192.0.2.1")
    allow = rule(:fortinet, name: "allow", rule_number: 2, source: "10.0.0.0/30", destination: "192.0.2.0/30")
    plan = migrate(snapshot(:fortinet, [ allow, deny ]), destination)
    assert plan.ready?, plan.issues.map(&:message).join("; ")
    candidate = plan.change_set.apply
    { [ "10.0.0.1", "192.0.2.1" ] => "deny", [ "10.0.0.1", "192.0.2.2" ] => "allow",
      [ "10.0.0.2", "192.0.2.1" ] => "allow" }.each do |(from, to), action|
      packet = P::Packet.new(source: from, destination: to, protocol: 6, source_port: 12345, destination_port: 443)
      evaluation = P::Evaluation.new(candidate).perform(packet, from_zone: "inside", to_zone: "outside")
      assert_equal action, evaluation.partitions.sole.action
    end
  end

  test "shadowed source declarations do not create duplicate target identities" do
    source = snapshot(:fortinet, [ rule(:fortinet, name: "first", rule_number: 1), rule(:fortinet, name: "shadowed", rule_number: 2) ])
    plan = migrate(source, destination)
    assert plan.ready?, plan.issues.map(&:message).join("; ")
    assert_equal 1, plan.change_set.intents.count { |item| item.operation == :create }
    assert_empty plan.changes.find { |item| item[:source_rule_id].end_with?("shadowed") }.fetch(:results)
  end

  test "canonical deny is not silently converted into H3C drop" do
    plan = migrate(snapshot(:fortinet, [ rule(:fortinet, action: "deny", rule_number: 1) ]), destination(:h3c))
    refute plan.ready?
    assert_equal :unsupported_action, plan.issues.first.evidence[:code]
  end

  test "drop remains drop when target native action can express it" do
    source = snapshot(:palo_alto, [ rule(:palo_alto, action: "drop", rule_number: 1) ])
    target = snapshot(:h3c, [], settings: { policy_bindings: [ { name: "objects", from_zone: "inside", to_zone: "outside" } ] })
    plan = migrate(source, target)
    assert plan.ready?, plan.issues.map(&:message).join("; ")
    assert_equal "drop", plan.change_set.targets.sole.action
    assert_equal "drop", plan.change_set.apply.rules.sole.action
  end

  test "source ports application user and security profile restrictions never disappear" do
    service = E::ServiceObject.new(**context(:palo_alto), name: "restricted", protocol: "tcp", source_port: "1024-2048", destination_port: "443")
    restricted = rule(:palo_alto, rule_number: 1).with(services: E::ServiceGroup.new(**context(:palo_alto), name: "services", members: { "restricted" => service }))
    [ restricted, rule(:palo_alto, rule_number: 1, applications: [ "web-browsing" ]),
      rule(:palo_alto, rule_number: 1, source_users: [ "alice" ]),
      rule(:palo_alto, rule_number: 1, conditions: { security_profiles: { antivirus: "strict" } }) ].each do |entry|
      plan = migrate(snapshot(:palo_alto, [ entry ]), destination)
      refute plan.ready?
      assert_raises(P::Error) { plan.script }
    end
  end

  test "future once schedule is proven over its window and missing readback timing fails" do
    now = Time.utc(2026, 10, 22, 12)
    schedule = E::Schedule.new(**context(:fortinet), name: "future", start_at: now + 3600, end_at: now + 7200)
    source = snapshot(:fortinet, [ rule(:fortinet, rule_number: 1, schedule: schedule) ])
    plan = migrate(source, destination(:srx), at: now)
    assert plan.ready?, plan.issues.map(&:message).join("; ")
    assert plan.effect_proofs.fetch(:time).verified?
    assert plan.effect_proofs.fetch(:time).checks.any? { |check| check.at > now + 7200 }
    candidate = plan.change_set.apply
    entry = candidate.rules.sole
    readback = candidate.with_catalog(E::Catalog.new(candidate.catalog.to_a - [ entry ] + [ entry.with(schedule: nil, schedule_name: nil) ], **context(:srx)))
    refute plan.verify_readback(readback).verified?
  end

  test "native PAN defaults are not materialized as ordinary migration rules" do
    text = <<~CONFIG
      set rulebase default-security-rules rules intrazone-default action allow
      set rulebase default-security-rules rules interzone-default action deny
    CONFIG
    parsed = Algosec::Config::Parser.perform(text, vendor: :palo_alto, device_id: 1)
    assert parsed.complete?, parsed.diagnostics.map(&:message).join("; ")
    plan = migrate(P::Snapshot.from_config(parsed), destination(:fortinet))
    refute plan.ready?
    assert_equal :no_migratable_policy, plan.issues.first.evidence[:code]
    assert_raises(P::Error) { plan.script }
  end
  test "different overlapping once windows block instead of permanently shadowing later traffic" do
    now = Time.utc(2026, 10, 22, 12)
    window = E::Schedule.new(**context(:fortinet), name: "future", start_at: now + 3600, end_at: now + 7200)
    first = rule(:fortinet, name: "temporary-deny", rule_number: 1, action: "deny", schedule: window)
    later = rule(:fortinet, name: "permanent-allow", rule_number: 2)
    plan = migrate(snapshot(:fortinet, [ first, later ]), destination, at: now)
    refute plan.ready?
    assert_equal :unsupported_temporal_overlap, plan.issues.first.evidence[:code]
    assert_raises(P::Error) { plan.script }
  end

  test "shared target ingress ACL is rejected when it widens another ingress" do
    source = snapshot(:fortinet, [ rule(:fortinet, rule_number: 1) ])
    plan = migrate(source, destination(:asa))
    refute plan.ready?
    assert plan.proof.differences.any? { |difference| difference.kind == :outside_target && difference.context[:from_zone] == "outside" }
  end

  test "dual family any never silently narrows to the generator IPv4 scope" do
    parsed = Algosec::Config::Parser.perform(<<~CONFIG, vendor: :palo_alto, device_id: 1)
      set rulebase security rules all from inside
      set rulebase security rules all to outside
      set rulebase security rules all source any
      set rulebase security rules all destination any
      set rulebase security rules all service any
      set rulebase security rules all application any
      set rulebase security rules all action allow
    CONFIG
    plan = migrate(P::Snapshot.from_config(parsed), destination(:fortinet))
    refute plan.ready?
    assert_equal :unsupported_gap, plan.issues.first.evidence[:code]
  end

  test "PAN terminal defaults permit native before-terminal insertion without materializing source defaults" do
    content = <<~CONFIG
      set zone inside network layer3 ethernet1/1
      set zone outside network layer3 ethernet1/2
      set rulebase default-security-rules rules intrazone-default action allow
      set rulebase default-security-rules rules interzone-default action deny
    CONFIG
    parsed = Algosec::Config::Parser.perform(content, vendor: :palo_alto, device_id: 1)
    source = snapshot(:fortinet, [ rule(:fortinet, rule_number: 1) ])
    target = P::Snapshot.from_config(parsed)
    plan = migrate(source, target)
    assert plan.ready?, plan.issues.map(&:message).join("; ")
    assert_equal :before_terminal, plan.change_set.intents.sole.placement
    assert_equal 3, plan.change_set.apply.rules.size
    readback = P::Snapshot.from_config(Algosec::Config::Parser.perform(content + plan.script, vendor: :palo_alto, device_id: 1))
    assert plan.verify_readback(readback).verified?
  end

  test "migration approval round trips both baselines and explicit logging metadata" do
    source_graph = snapshot(:fortinet, [ rule(:fortinet, rule_number: 1) ])
    source = P::Snapshot.new(**context(:fortinet), catalog: source_graph.catalog, revision: "a" * 64)
    target_graph = destination
    target = P::Snapshot.new(**context(:palo_alto), catalog: target_graph.catalog, revision: "b" * 64)
    plan = migrate(source, target)
    assert plan.ready?, plan.issues.map(&:message).join("; ")
    document = P::PlanDocument.dump(plan)
    restored = P::PlanDocument.load(JSON.parse(JSON.generate(document)), source: source, target: target)
    assert restored.ready?, restored.issues.map(&:message).join("; ")
    assert_equal document, P::PlanDocument.dump(restored)
    assert_equal({ log: nil, log_enabled: nil }, restored.change_set.targets.sole.metadata)
    assert_equal 2, document.fetch("schema_version")
    assert_raises(ArgumentError) { P::PlanDocument.load(document.merge("schema_version" => 1), source: source, target: target) }
    [ { "log_enabled" => "false" }, { "log" => false }, { "permit_unknown_logging" => true } ].each do |metadata|
      invalid = document.deep_dup
      invalid.fetch("targets").sole["metadata"] = metadata
      assert_raises(ArgumentError) { P::PlanDocument.load(invalid, source: source, target: target) }
    end
    wrong = restored.change_set.apply
    entry = wrong.rules.sole
    wrong = wrong.with_catalog(E::Catalog.new(wrong.catalog.to_a - [ entry ] + [ entry.with(log_enabled: true) ], **context(:palo_alto)))
    refute restored.verify_readback(wrong).verified?
  end
  test "native Hillstone logging readback preserves explicit false and rejects enablement" do
    source = snapshot(:hillstone, [ rule(:hillstone, rule_number: 1, log_enabled: false) ])
    base = "zone inside\nexit\nzone outside\nexit\n"
    target = P::Snapshot.from_config(Algosec::Config::Parser.perform(base, vendor: :hillstone, device_id: 1))
    plan = migrate(source, target)
    assert plan.ready?, plan.issues.map(&:message).join("; ")
    config = base + saved_config(:hillstone, plan.script)
    parsed = Algosec::Config::Parser.perform(config, vendor: :hillstone, device_id: 1)
    assert parsed.complete?, parsed.diagnostics.map(&:message).join("; ")
    assert plan.verify_readback(P::Snapshot.from_config(parsed)).verified?, plan.verify_readback(P::Snapshot.from_config(parsed)).to_h.inspect
    wrong = Algosec::Config::Parser.perform(config.sub("action permit", "action permit\nlog session-end"), vendor: :hillstone, device_id: 1)
    assert wrong.complete?, wrong.diagnostics.map(&:message).join("; ")
    refute plan.verify_readback(P::Snapshot.from_config(wrong)).verified?
  end
  test "ingress-only source needs explicit caller migration scope" do
    source = snapshot(:asa, [ rule(:asa, rule_number: 1) ])
    plan = migrate(source, destination)
    refute plan.ready?
    assert_equal :missing_migration_scope, plan.issues.first.evidence[:code]
    assert_raises(P::Error) { plan.script }
  end

  test "explicit ingress-only scope retains all requested native bindings in provenance" do
    source = snapshot(:asa, [ rule(:asa, rule_number: 1) ])
    pairs = [ [ "inside", "outside" ], [ "outside", "inside" ] ]
    plan = P::Migration.new(source: source, target: destination, zones: { "inside" => "inside", "outside" => "outside" },
      source_zone_pairs: pairs).perform
    assert plan.ready?, plan.issues.map(&:message).join("; ")
    assert_equal pairs, plan.changes.sole.fetch(:source_zone_pairs)
    assert_equal pairs, plan.change_set.targets.map { |target| target.context.values_at(:from_zone, :to_zone) }
    assert_equal 2, plan.change_set.apply.rules.size
  end

  test "explicit source scope partitions distinct ingress ACLs without requiring each rule in every context" do
    first = rule(:asa, name: "first", rule_number: 1, rule_set: "inside_acl")
    second = rule(:asa, name: "second", rule_number: 1, rule_set: "outside_acl", source: "10.1.0.0/24")
    source = snapshot(:asa, [ first, second ])
    outside = source.zone("outside")
    replacement = E::Zone.new(**context(:asa), name: "outside", acl_name: "outside_acl", vrf: outside.vrf,
      interfaces: outside.interfaces.values)
    source = source.with_catalog(E::Catalog.new(source.catalog.to_a - [ outside ] + [ replacement ], **context(:asa)))
    pairs = [ [ "inside", "outside" ], [ "outside", "inside" ] ]
    plan = P::Migration.new(source: source, target: destination, zones: { "inside" => "inside", "outside" => "outside" },
      source_zone_pairs: pairs).perform
    assert plan.ready?, plan.issues.map(&:message).join("; ")
    assert_equal pairs, plan.change_set.targets.map { |target| target.context.values_at(:from_zone, :to_zone) }
    assert_equal pairs.map { |pair| [ pair ] }, plan.changes.map { |change| change.fetch(:source_zone_pairs) }
  end

  test "explicit source scope never migrates an unrequested ordinary zone pair" do
    entry = rule(:palo_alto, rule_number: 1, from_zones: %w[inside outside], to_zones: %w[inside outside])
    plan = P::Migration.new(source: snapshot(:palo_alto, [ entry ]), target: destination,
      zones: { "inside" => "inside", "outside" => "outside" }, source_zone_pairs: [ [ "inside", "outside" ] ]).perform
    assert plan.ready?, plan.issues.map(&:message).join("; ")
    assert_equal [ [ "inside", "outside" ] ], plan.change_set.targets.map { |target| target.context.values_at(:from_zone, :to_zone) }
    assert_equal 1, plan.change_set.apply.rules.size
  end

  test "explicit source scope rejects an ingress without a native binding" do
    source = snapshot(:asa, [ rule(:asa, rule_number: 1) ])
    plan = P::Migration.new(source: source, target: destination,
      zones: { "inside" => "inside", "outside" => "outside", "missing" => "missing" },
      source_zone_pairs: [ [ "missing", "outside" ] ]).perform
    refute plan.ready?
    assert_equal :missing_migration_scope, plan.issues.first.evidence[:code]
    assert_raises(P::Error) { plan.script }
  end

  test "plan review encodes canonical scoped identity without retaining raw configuration" do
    entry = rule(:srx, name: "private-policy", rule_number: 1, config: "raw-private-source-command")
    reviewed = P::PlanDocument.review(entry)
    assert_equal "SecurityRule", reviewed.fetch("type")
    scope = reviewed.fetch("identity").find { |part| part.is_a?(Hash) }
    refute_nil scope
    assert_equal "srx", reviewed.fetch("identity").fetch(1)
    assert_equal %w[address_book device_id rulebase virtual_system zone], scope.keys.sort
    assert_equal 1, scope.fetch("device_id")
    refute_includes JSON.generate(reviewed), "raw-private-source-command"
  end
end
