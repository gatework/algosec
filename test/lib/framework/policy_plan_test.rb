# frozen_string_literal: true

require "test_helper"
require_relative "support/policy_factory"

class PolicyPlanTest < ActiveSupport::TestCase
  include PolicyFactory

  def revision_snapshot(revision, device_id: 1, settings: {})
    base = snapshot(:hillstone, device_id: device_id)
    P::Snapshot.new(device_id: device_id, vendor: :hillstone, catalog: base.catalog,
                    revision: revision, settings: settings)
  end

  test "designs share the migration and reclaim plan contract" do
    current = revision_snapshot("a")
    result = P::RuleMatcher.new(current).match(group(:hillstone))
    planner = P::Planner.new(P::Report.new(results: [ result ]))
    plan = planner.plans.sole
    assert_equal :configure, plan.operation
    assert_equal planner.perform.sole[:policy_contents].sole[:new][:content], plan.script
    assert_same plan, plan.validate!(target: revision_snapshot("a"))
    assert_equal :new, plan.changes.sole[:operation]
    assert_equal :stale_plan, assert_raises(P::Error) { plan.validate!(target: revision_snapshot("b")) }.code
    assert_equal :stale_plan, assert_raises(P::Error) { plan.validate!(target: revision_snapshot("a", settings: { vdom: "other" })) }.code
  end

  test "offline plans are reviewable but cannot pass baseline verification" do
    current = snapshot(:hillstone)
    result = P::RuleMatcher.new(current).match(group(:hillstone))
    plan = P::Planner.new(P::Report.new(results: [ result ])).plans.sole
    assert plan.ready?
    refute_empty plan.script
    assert_equal :missing_baseline, assert_raises(P::Error) { plan.validate!(target: revision_snapshot("a")) }.code
  end

  test "migration validates both source and target including when caller supplies the same snapshot twice" do
    source, target = revision_snapshot("source"), revision_snapshot("target", device_id: 2)
    change_set = P::ChangeSet.new(snapshot: target, intents: [], targets: [])
    plan = P::Plan.new(operation: :migrate, source: source, snapshot: target, changes: [], change_set: change_set)
    assert_same source, plan.source_snapshot
    assert_same target, plan.target_snapshot
    assert plan.source_snapshot.catalog.sealed?
    assert plan.target_snapshot.catalog.sealed?
    assert_same plan, plan.validate!(source: source, target: target)
    assert_equal :stale_plan, assert_raises(P::Error) { plan.validate!(source: target, target: target) }.code
    assert_equal :stale_plan, assert_raises(P::Error) { plan.validate!(source: revision_snapshot("changed"), target: target) }.code
  end

  test "one device design cannot combine results from different snapshots" do
    results = %w[a b].map { |revision| P::RuleMatcher.new(revision_snapshot(revision)).match(group(:hillstone)) }
    planner = P::Planner.new(P::Report.new(results: results))
    assert_equal :mixed_snapshots, assert_raises(P::Error) { planner.plans }.code
  end
end
