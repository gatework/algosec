# frozen_string_literal: true

require "test_helper"
require_relative "../framework/support/policy_factory"
require_relative "../framework/support/policy_config"

class MigrationScopeProofTest < ActiveSupport::TestCase
  include PolicyFactory
  include PolicyConfig

  def baseline
    original = snapshot(:asa)
    outside = original.zone("outside")
    replacement = E::Zone.new(**context(:asa), name: "outside", interfaces: outside.interfaces.values)
    original.with_catalog(E::Catalog.new(original.catalog.to_a - [ outside ] + [ replacement ], **context(:asa)))
  end

  def traffic
    P::Request::Traffic.from_maps(group(:asa, sources: [ "10.0.0.0/24" ]).slice(*P::Result::DIMENSIONS))
  end

  test "direct change set cannot normalize explicit egress into unrestricted ingress authorization" do
    target = P::ChangeSet::Target.new(traffic_set: traffic, action: "allow", from_zone: "inside", to_zone: "outside")
    change = P::ChangeSet.new(snapshot: baseline,
      intents: [ P::ChangeSet::Intent.create(rule: rule(:asa, rule_number: 1), placement: :append) ], targets: [ target ])
    proof = change.verify
    refute proof.verified?
    assert proof.differences.any? { |difference| difference.kind == :outside_target && difference.context.values_at(:from_zone, :to_zone) == %w[inside inside] }
    assert proof.differences.any? { |difference| difference.kind == :outside_target && difference.context[:to_zone].start_with?("__algosec_unknown_zone_") }
  end

  test "ordinary Planner cannot bypass explicit egress scope through an ingress ACL" do
    input = group(:asa)
    actions = P::Result::DIMENSIONS.to_h { |dimension| [ dimension, input.fetch(dimension).transform_values { nil } ] }
    result = P::Result.new(**input, type: :new, actions: { new: actions }, snapshot: baseline)
    plan = P::Planner.new(P::Report.new(results: [ result ])).plans.sole
    refute plan.ready?
    assert plan.proof.differences.any? { |difference| difference.kind == :outside_target }
    assert_raises(P::Error) { plan.script }
  end

  test "caller may explicitly approve native ingress-only scope using nil egress" do
    target = P::ChangeSet::Target.new(traffic_set: traffic, action: "allow", from_zone: "inside", to_zone: nil)
    change = P::ChangeSet.new(snapshot: baseline,
      intents: [ P::ChangeSet::Intent.create(rule: rule(:asa, rule_number: 1), placement: :append) ], targets: [ target ])
    assert change.verify.verified?, change.verify.to_h.inspect
  end

  test "nil egress never expands approval for a vendor with egress matching" do
    target = P::ChangeSet::Target.new(traffic_set: traffic, action: "allow", from_zone: "inside", to_zone: nil)
    change = P::ChangeSet.new(snapshot: snapshot(:palo_alto),
      intents: [ P::ChangeSet::Intent.create(rule: rule(:palo_alto, rule_number: 1), placement: :append) ], targets: [ target ])
    refute change.verify.verified?
    refute target.covers_context?(target.context.merge(to_zone: "outside"), behavior: change.snapshot.behavior)
  end

  test "explicit unrestricted ingress approval preserves native ASA future schedule and readback" do
    now = Time.utc(2026, 10, 23, 12)
    current = baseline
    request = P::Request.new(sources: [ "10.0.0.1" ], destinations: [ "192.0.2.1" ], services: [ "tcp/443" ],
      schedule: { start_at: now + 3600, end_at: now + 7200, time_zone: "UTC" })
    result = P::RuleMatcher.new(current, at: now).match(group(:asa), schedule: request.schedule)
    generated = current.definition.generator.new(snapshot: current).render([ result ])
    target = P::ChangeSet::Target.new(traffic_set: result.traffic_set, action: "allow", from_zone: "inside", to_zone: nil,
      effective_window: result.schedule)
    change = P::ChangeSet.new(snapshot: current, intents: generated.entries.flat_map(&:intents), targets: [ target ], at: now)
    plan = P::Plan.new(operation: :configure, snapshot: current, changes: [], change_set: change,
      commands: generated.text, effect_proofs: { time: P::TimeVerification.new(change_set: change) })
    assert plan.ready?, plan.issues.map(&:message).join("; ")
    parsed = Algosec::Config::Parser.perform(saved_config(:asa, plan.script), vendor: :asa, device_id: 1)
    assert parsed.complete?, parsed.diagnostics.map(&:message).join("; ")
    declarations = parsed.catalog.reject { |entry| entry.is_a?(E::Zone) || entry.is_a?(E::RuleBinding) }
    readback = current.with_catalog(E::Catalog.new(current.catalog.to_a + declarations, **context(:asa)))
    assert_equal result.schedule.window, readback.rules.sole.schedule.window
    assert plan.verify_readback(readback).verified?, plan.verify_readback(readback).to_h.inspect
  end
end
