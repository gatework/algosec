# frozen_string_literal: true

require "test_helper"
require "algosec/policy/plan_document"
require_relative "../framework/support/policy_factory"

class TargetMetadataTest < ActiveSupport::TestCase
  include PolicyFactory

  def baseline
    graph = snapshot(:palo_alto)
    P::Snapshot.new(device_id: 1, vendor: :palo_alto, catalog: graph.catalog, revision: "b" * 64)
  end

  def change(current, value)
    entry = rule(:palo_alto, rule_number: 1, log_enabled: value)
    traffic = P::Request::Traffic.from_maps(group(:palo_alto, sources: [ "10.0.0.0/24" ]).slice(:sources, :destinations, :services))
    target = P::ChangeSet::Target.new(traffic_set: traffic, action: "allow", from_zone: "inside", to_zone: "outside", metadata: { log: nil, log_enabled: value })
    P::ChangeSet.new(snapshot: current, intents: [ P::ChangeSet::Intent.create(rule: entry, placement: :append) ], targets: [ target ])
  end

  test "explicit nil false true logging expectations reject each other on generation and readback" do
    [ nil, false, true ].each do |expected|
      current = baseline
      changes = change(current, expected)
      assert changes.verify.verified?
      [ nil, false, true ].reject { |actual| actual == expected }.each do |actual|
        candidate = changes.apply
        original = candidate.rules.sole
        changed = original.with(log_enabled: actual)
        readback = candidate.with_catalog(E::Catalog.new(candidate.catalog.to_a - [ original ] + [ changed ], **context(:palo_alto)))
        result = changes.verify(candidate: readback)
        refute result.verified?, "#{expected.inspect} accepted #{actual.inspect}"
        assert_equal :target, result.differences.sole.kind
      end
    end
  end

  test "approved target metadata round trips strictly and is rechecked" do
    current = baseline
    changes = change(current, false)
    plan = P::Plan.new(operation: :migrate, snapshot: current, changes: [], commands: "approved", change_set: changes)
    document = P::PlanDocument.dump(plan)
    assert_equal 2, document.fetch("schema_version")
    assert_raises(ArgumentError) { P::PlanDocument.load(document.merge("schema_version" => 1), target: current) }
    assert_equal({ "log" => nil, "log_enabled" => false }, document.fetch("targets").sole.fetch("metadata"))
    restored = P::PlanDocument.load(JSON.parse(JSON.generate(document)), target: current)
    assert restored.ready?
    assert_equal document, P::PlanDocument.dump(restored)
    malformed = JSON.parse(JSON.generate(document))
    malformed.fetch("targets").sole.fetch("metadata")["log_enabled"] = "false"
    assert_raises(ArgumentError) { P::PlanDocument.load(malformed, target: current) }
    malformed.fetch("targets").sole["metadata"] = { "verified" => true }
    assert_raises(ArgumentError) { P::PlanDocument.load(malformed, target: current) }
  end
  test "wrong generated logging cannot satisfy an explicit target" do
    current = baseline
    changes = change(current, false)
    wrong = changes.intents.sole.rule.with(log_enabled: true)
    altered = P::ChangeSet.new(snapshot: current, intents: [ P::ChangeSet::Intent.create(rule: wrong, placement: :append) ], targets: changes.targets)
    refute altered.verify.verified?
    assert_equal false, altered.verify.differences.sole.before.fetch(:metadata).fetch(:log_enabled)
    assert_equal true, altered.verify.differences.sole.after.rule.log_enabled
  end
end
