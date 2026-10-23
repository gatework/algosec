# frozen_string_literal: true

require "test_helper"
require_relative "../framework/support/policy_factory"

class NatEffectBoundaryTest < ActiveSupport::TestCase
  include PolicyFactory

  def migration(objects = [])
    source = snapshot(:fortinet, [ rule(:fortinet, rule_number: 1) ])
    P::Migration.new(source: source, target: snapshot(:fortinet, objects),
      zones: { "inside" => "inside", "outside" => "outside" }).perform
  end

  def vip
    E::StaticNat.new(**context(:fortinet), name: "unrelated-vip", interface: "inside", mapped_ip: "203.0.113.9",
      real_ip: "10.9.9.9", mapped_zone: "inside")
  end

  def with_embedded_nat(candidate)
    original = candidate.rules.sole
    candidate.with_catalog(E::Catalog.new(candidate.catalog.to_a - [ original ] + [ original.with(nat: true) ], **context(:fortinet)))
  end

  def assert_unapproved_nat_readback
    plan = migration
    assert plan.ready?, plan.issues.map(&:message).join("; ")
    assert_empty plan.required_effects
    candidate = plan.change_set.apply
    assert plan.verify_readback(candidate).verified?
    checked = plan.verify_readback(yield(candidate))
    refute checked.verified?
    assert_includes checked.issues.map { |issue| issue.evidence[:code] }, :nat_readback_mismatch
  end

  test "readback cannot add embedded NAT to a plan without a NAT effect proof" do
    assert_unapproved_nat_readback { |candidate| with_embedded_nat(candidate) }
  end

  test "readback cannot add standalone NAT to a plan without a NAT effect proof" do
    assert_unapproved_nat_readback do |candidate|
      candidate.with_catalog(E::Catalog.new(candidate.catalog.to_a + [ vip ], **context(:fortinet)))
    end
  end

  test "unchanged NAT proof retains embedded declarations even without untranslated requirement" do
    original = migration([ vip ])
    change = original.change_set
    effect = P::Nat::Verification.unchanged(change_set: change)
    refute effect.require_untranslated
    plan = P::Plan.new(operation: :configure, snapshot: change.snapshot, changes: [], commands: original.script,
      change_set: change, effect_proofs: { nat: effect })
    assert plan.ready?, plan.issues.map(&:message).join("; ")
    candidate = change.apply
    assert plan.verify_readback(candidate).verified?
    checked = plan.verify_readback(with_embedded_nat(candidate))
    refute checked.verified?
    assert_includes checked.effects.fetch(:nat).issues.map { |issue| issue.evidence[:code] }, :nat_readback_mismatch
  end

  test "an unchanged NAT proof cannot introduce an unexpanded embedded conversion" do
    existing = rule(:fortinet, rule_number: 1)
    current = snapshot(:fortinet, [ existing, vip ])
    change = P::ChangeSet.new(snapshot: current,
      intents: [ P::ChangeSet::Intent.modify(rule_id: existing.rule_id, rule: existing.with(nat: true)) ], targets: [])
    effect = P::Nat::Verification.unchanged(change_set: change)
    refute effect.verified?
    assert_includes effect.issues.map { |issue| issue.evidence[:code] }, :conditional_nat
  end
end
