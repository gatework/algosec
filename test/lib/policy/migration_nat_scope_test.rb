# frozen_string_literal: true

require "test_helper"
require "algosec/policy/plan_document"
require_relative "../framework/support/policy_factory"

class MigrationNatScopeTest < ActiveSupport::TestCase
  include PolicyFactory

  def baseline(vendor, objects = [], revision: nil)
    graph = snapshot(vendor, objects)
    P::Snapshot.new(**context(vendor), catalog: graph.catalog, revision: revision)
  end

  def migrate(target)
    source = baseline(:fortinet, [ rule(:fortinet, rule_number: 1) ], revision: "source")
    P::Migration.new(source: source, target: target, zones: { "inside" => "inside", "outside" => "outside" }).perform
  end

  def source_nat(source = "10.9.0.1", **attributes)
    E::DynamicNat.new(**context(:palo_alto), name: "nat", direction: :source, nat_order: [ 1 ],
      from_zone: "inside", to_zone: "outside", source_set: source, destination_set: "192.0.2.1",
      translated_source_set: "203.0.113.1", nat_type: "static-ip",
      extra_conf: { "panos" => { "translations" => [ %w[source-translation static-ip bi-directional no] ] } }, **attributes)
  end

  def embedded_nat_target(**attributes)
    existing = rule(:fortinet, name: "existing-nat-policy", rule_number: 1, nat: true,
      rule_set: "root", scope: E::Scope.new(device_id: 1, virtual_system: "root"), **attributes)
    baseline(:fortinet, [ existing ], revision: "target")
  end

  test "unexpanded embedded NAT cannot certify untranslated migration traffic" do
    plan = migrate(embedded_nat_target)
    assert_equal [ :nat ], plan.required_effects
    assert_empty plan.target_snapshot.nat_rules
    refute plan.ready?
    assert_includes plan.issues.map { |issue| issue.evidence[:code] }, :conditional_nat
    assert_raises(P::Error) { plan.script }
  end

  test "previous semantic revision rejects earlier approval before restoration" do
    source = baseline(:fortinet, [ rule(:fortinet, rule_number: 1) ], revision: "source")
    document = JSON.parse(File.read(TestPaths.root.join("test/fixtures/policy/unexpanded_nat_plan.json")))

    assert_raises(ArgumentError) { P::PlanDocument.load(document, source: source, target: embedded_nat_target) }
  end

  test "earlier approval shape with current semantics still rechecks unexpanded NAT" do
    source = baseline(:fortinet, [ rule(:fortinet, rule_number: 1) ], revision: "source")
    target = embedded_nat_target
    # Supply current context to test the old proof shape separately from version/context gates; this is not a document upgrade path.
    text = File.read(TestPaths.root.join("test/fixtures/policy/unexpanded_nat_plan.json"))
    document = JSON.parse(text.gsub('"firewall-domain-v1"', JSON.generate(Algosec::SEMANTIC_VERSION)))
    document["source_baseline"] = P::PlanDocument.review(source.baseline)
    document["target_baseline"] = P::PlanDocument.review(target.baseline)
    restored = P::PlanDocument.load(document, source: source, target: target)
    refute restored.ready?
    refute restored.effect_proofs.fetch(:nat).verified?
    assert_includes restored.effect_proofs.fetch(:nat).issues.map { |issue| issue.evidence[:code] }, :conditional_nat
    assert_raises(P::Error) { restored.script }
  end

  test "independent readback cannot hide new embedded NAT behind an unchanged disjoint VIP" do
    vip = E::StaticNat.new(**context(:fortinet), name: "unrelated-vip", interface: "inside", mapped_ip: "203.0.113.9",
      real_ip: "10.9.9.9", mapped_zone: "inside")
    plan = migrate(baseline(:fortinet, [ vip ]))
    assert plan.ready?, plan.issues.map(&:message).join("; ")
    candidate = plan.change_set.apply
    generated = candidate.rules.sole
    readback = candidate.with_catalog(E::Catalog.new(candidate.catalog.to_a - [ generated ] + [ generated.with(nat: true) ], **context(:fortinet)))
    checked = plan.verify_readback(readback)
    refute checked.verified?
    assert_includes checked.effects.fetch(:nat).issues.map { |issue| issue.evidence[:code] }, :nat_readback_mismatch
    assert_empty checked.effects.fetch(:nat).observations
  end

  test "permanently disabled embedded NAT is excluded but a future once window is not" do
    disabled = migrate(embedded_nat_target(disabled: true))
    assert disabled.ready?, disabled.issues.map(&:message).join("; ")
    now = Time.current
    later = E::Schedule.new(**context(:fortinet), name: "future-nat", start_at: now + 3600, end_at: now + 7200)
    future = migrate(embedded_nat_target(schedule: later))
    refute future.ready?
    assert_includes future.issues.map { |issue| issue.evidence[:code] }, :conditional_nat
  end

  test "a disabled linked NAT object cannot account for an active embedded conversion" do
    target = embedded_nat_target
    enabled = target.rules.sole
    linked = E::DynamicNat.new(**context(:fortinet), policy_id: enabled.native_rule_id, direction: :source,
      match_rule: enabled, extra_conf: { disabled: true })
    target = target.with_catalog(E::Catalog.new(target.catalog.to_a + [ linked ], **context(:fortinet)))
    plan = migrate(target)
    refute plan.ready?
    assert_includes plan.issues.map { |issue| issue.evidence[:code] }, :conditional_nat
  end

  test "unchanged overlapping translation cannot be called source-equivalent migration" do
    plan = migrate(baseline(:palo_alto, [ source_nat("10.0.0.1") ]))
    refute plan.ready?
    assert_includes plan.issues.map { |issue| issue.evidence[:code] }, :target_nat_interference
    assert_raises(P::Error) { plan.script }
  end

  test "disjoint target translation keeps typed requirement through approval and readback" do
    target = baseline(:palo_alto, [ source_nat ], revision: "target")
    plan = migrate(target)
    assert plan.ready?, plan.issues.map(&:message).join("; ")
    assert plan.effect_proofs.fetch(:nat).require_untranslated
    source = baseline(:fortinet, [ rule(:fortinet, rule_number: 1) ], revision: "source")
    document = P::PlanDocument.dump(plan)
    restored = P::PlanDocument.load(JSON.parse(JSON.generate(document)), source: source, target: target)
    assert restored.ready?, restored.issues.map(&:message).join("; ")
    assert restored.effect_proofs.fetch(:nat).require_untranslated
    assert_equal document, P::PlanDocument.dump(restored)
    candidate = restored.change_set.apply
    replacement = source_nat("10.0.0.1")
    readback = candidate.with_catalog(E::Catalog.new(candidate.catalog.reject { |item| item.is_a?(E::NatRule) } + [ replacement ], **context(:palo_alto)))
    refute restored.verify_readback(readback).verified?
  end

  test "Fortinet VIP public destination overlap blocks while disjoint VIP remains unchanged" do
    [ [ "192.0.2.1", false ], [ "203.0.113.9", true ] ].each do |mapped, expected|
      nat = E::StaticNat.new(**context(:fortinet), name: "vip", interface: "inside", mapped_ip: mapped, real_ip: "10.9.9.9",
        real_set: "10.9.9.9", mapped_set: mapped, mapped_zone: "inside")
      plan = migrate(baseline(:fortinet, [ nat ]))
      assert_equal expected, plan.ready?, plan.issues.map(&:message).join("; ")
      assert_includes plan.issues.map { |issue| issue.evidence[:code] }, :target_nat_interference unless expected
    end
  end

  test "untranslated requirement cannot be empty or use unresolved linked NAT scope" do
    target = baseline(:palo_alto, [ source_nat ])
    change = P::ChangeSet.new(snapshot: target, intents: [], targets: [])
    proof = P::Nat::Verification.unchanged(change_set: change, require_untranslated: true)
    refute proof.verified?
    assert_includes proof.issues.map { |issue| issue.evidence[:code] }, :missing_untranslated_scope
    match = rule(:palo_alto, rule_number: 1, source: "10.9.0.1")
    linked = source_nat(match_rule: match)
    plan = migrate(baseline(:palo_alto, [ match, linked ]))
    refute plan.ready?
  end
  test "unknown dynamic reverse direction stays blocked even with disjoint forward addresses" do
    plan = migrate(baseline(:palo_alto, [ source_nat(extra_conf: {}) ]))
    refute plan.ready?
    assert_includes plan.issues.map { |issue| issue.evidence[:code] }, :conditional_nat
  end

  test "independent native PAN readback reruns the untranslated scope alongside preserved NAT declarations" do
    content = <<~CONFIG
      set zone inside network layer3 ethernet1/1
      set zone outside network layer3 ethernet1/2
      set rulebase nat rules existing from inside
      set rulebase nat rules existing to outside
      set rulebase nat rules existing source 10.9.0.1
      set rulebase nat rules existing destination 192.0.2.1
      set rulebase nat rules existing service any
      set rulebase nat rules existing source-translation static-ip translated-address 203.0.113.1
      set rulebase nat rules existing source-translation static-ip bi-directional no
    CONFIG
    original = Algosec::Config::Parser.perform(content, vendor: :palo_alto, device_id: 1)
    assert original.complete?, original.diagnostics.map(&:message).join("; ")
    target = P::Snapshot.from_config(original, revision: "target")
    plan = migrate(target)
    assert plan.ready?, plan.issues.map(&:message).join("; ")
    source = baseline(:fortinet, [ rule(:fortinet, rule_number: 1) ], revision: "source")
    document = P::PlanDocument.dump(plan)
    restored = P::PlanDocument.load(JSON.parse(JSON.generate(document)), source: source, target: target)
    actual = Algosec::Config::Parser.perform(content + plan.script, vendor: :palo_alto, device_id: 1)
    assert actual.complete?, actual.diagnostics.map(&:message).join("; ")
    checked = restored.verify_readback(P::Snapshot.from_config(actual))
    assert checked.verified?, checked.to_h.inspect
    assert_equal :untranslated, checked.effects.fetch(:nat).observations.sole.fetch(:relation)

    invalid = JSON.parse(JSON.generate(document))
    invalid.fetch("effects").fetch("nat")["require_untranslated"] = "false"
    assert_raises(ArgumentError) { P::PlanDocument.load(invalid, source: source, target: target) }
  end
end
