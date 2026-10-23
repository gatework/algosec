# frozen_string_literal: true

require "test_helper"
require_relative "../framework/support/policy_factory"

class ChangeSetTest < ActiveSupport::TestCase
  include PolicyFactory

  def traffic(source = "10.0.0.0/24")
    P::TrafficSet.new([ { family: :ipv4, source_addresses: Algosec::IPAddr.parse(source),
      destination_addresses: Algosec::IPAddr.parse("192.0.2.1"), protocols: Algosec::Set.new(6..6),
      source_ports: Algosec::Set.new(0..65535), destination_ports: Algosec::Set.new(443..443) } ])
  end

  test "change sets expose immutable intent and exact proof values" do
    assert defined?(P::ChangeSet), "ChangeSet must own candidate and semantic verification"
  end

  test "two slash25 rules jointly cover slash24 without creating a rule" do
    entries = [ rule(:palo_alto, name: "r1", source: "10.0.0.0/25", rule_number: 1),
      rule(:palo_alto, name: "r2", source: "10.0.0.128/25", rule_number: 2) ]
    result = P::RuleMatcher.new(snapshot(:palo_alto, entries)).match(group(:palo_alto, sources: [ "10.0.0.0/24" ]))
    assert_equal :ignore, result.type
    assert_empty result.actions || {}
  end
end

class ChangeSetTest
  def target(set = traffic, action: "allow")
    P::ChangeSet::Target.new(traffic_set: set, action: action, from_zone: "inside", to_zone: "outside")
  end

  test "candidate creation preserves baseline graph and proves target and outside" do
    current = snapshot(:palo_alto)
    current.catalog.seal!
    entry = rule(:palo_alto, rule_number: 1)
    change = P::ChangeSet.new(snapshot: current, intents: [ P::ChangeSet::Intent.create(rule: entry, placement: :append) ], targets: [ target ])
    candidate = change.apply(current)
    assert_same current.zone("inside"), candidate.zone("inside")
    assert_empty current.rules
    assert candidate.catalog.sealed?
    assert change.verify.verified?
  end

  test "outside widening and canonical action substitutions fail proof" do
    current = snapshot(:palo_alto)
    broad = rule(:palo_alto, source: "10.0.0.0/16", rule_number: 1)
    change = P::ChangeSet.new(snapshot: current, intents: [ P::ChangeSet::Intent.create(rule: broad, placement: :append) ], targets: [ target ])
    refute change.verify.verified?
    assert change.verify.differences.any? { |difference| difference.kind == :outside_target }
    reset = rule(:palo_alto, action: "reset-client", rule_number: 1)
    change = P::ChangeSet.new(snapshot: current, intents: [ P::ChangeSet::Intent.create(rule: reset, placement: :append) ], targets: [ target(action: "deny") ])
    refute change.verify.verified?
  end

  test "append behind deny fails while explicit move before deny proves exact target" do
    deny = rule(:palo_alto, name: "deny", action: "deny", rule_number: 1)
    current = snapshot(:palo_alto, [ deny ])
    allow = rule(:palo_alto, name: "allow", rule_number: 2)
    create = P::ChangeSet::Intent.create(rule: allow, placement: :append)
    change = P::ChangeSet.new(snapshot: current, intents: [ create ], targets: [ target ])
    refute change.verify.verified?
    move = P::ChangeSet::Intent.move(rule_id: allow.rule_id, before: deny.rule_id)
    change = P::ChangeSet.new(snapshot: current, intents: [ create, move ], targets: [ target ])
    assert change.verify.verified?
    assert_equal [ "allow", "deny" ], change.apply.rules.sort_by(&:rule_number).map(&:name)
    assert_equal 1, deny.rule_number
  end

  test "unknown affected behavior never proves equivalence" do
    unknown = rule(:palo_alto, rule_number: 1, applications: [ "web" ])
    current = snapshot(:palo_alto, [ unknown ])
    change = P::ChangeSet.new(snapshot: current, intents: [ P::ChangeSet::Intent.delete(rule_id: unknown.rule_id) ], targets: [])
    refute change.verify.verified?
  end

  test "modify and delete use owned constructors and keep untouched references" do
    original = rule(:palo_alto, rule_number: 1)
    current = snapshot(:palo_alto, [ original ])
    current.catalog.seal!
    replacement = original.with(action: "drop")
    assert_same original.sources, replacement.sources
    assert_equal "drop", replacement.action
    change = P::ChangeSet.new(snapshot: current, intents: [ P::ChangeSet::Intent.modify(rule_id: original.rule_id, rule: replacement) ], targets: [ target(action: "drop") ])
    assert change.verify.verified?
    removed = P::ChangeSet.new(snapshot: current, intents: [ P::ChangeSet::Intent.delete(rule_id: original.rule_id) ], targets: [ target(action: "deny") ])
    assert removed.verify.verified?
    assert_equal "allow", original.action
  end
end

class ChangeSetTest
  test "JSON evidence contains exact traffic and canonical actions without Ruby graph identities" do
    current = snapshot(:palo_alto)
    change = P::ChangeSet.new(snapshot: current, intents: [ P::ChangeSet::Intent.create(rule: rule(:palo_alto, action: "reset-both"), placement: :append) ], targets: [ target(action: "reset-both") ])
    proof = change.verify
    assert proof.verified?
    document = JSON.parse(JSON.generate(proof.to_h))
    assert_equal "reset-both", document.fetch("targets").sole.fetch("partitions").sole.fetch("action")
    assert_equal "ipv4", document.fetch("targets").sole.fetch("partitions").sole.fetch("traffic").sole.fetch("family")
    refute_includes JSON.generate(change.to_h), "#<"
  end

  test "with preserves unavailable raw evidence and honors public aliases" do
    original = rule(:palo_alto, conditions: { unparsed_commands: [ "unknown" ] })
    detached = E::SecurityRule.new(**context(:palo_alto), name: "detached", action: "allow", config_present: true,
      unparsed_commands_metadata: original.unparsed_commands_metadata)
    replacement = detached.with(action: "drop", source_zones: [ "other" ])
    assert_equal [ "other" ], replacement.from_zones
    assert replacement.unparsed_commands?
    refute replacement.unparsed_commands_available?
    refute replacement.config_available?
    assert_equal detached.unparsed_commands_metadata, replacement.unparsed_commands_metadata
  end

  test "readback detects unrelated extra rule and rejects mismatched software context" do
    current = snapshot(:palo_alto)
    change = P::ChangeSet.new(snapshot: current, intents: [ P::ChangeSet::Intent.create(rule: rule(:palo_alto, rule_number: 1), placement: :append) ], targets: [ target ])
    candidate = change.apply
    extra = rule(:palo_alto, name: "extra", source: "10.9.9.9", rule_number: 2)
    unexpected = candidate.with_catalog(E::Catalog.new(candidate.catalog.to_a + [ extra ]).seal!)
    refute change.verify(candidate: unexpected).verified?
    wrong = snapshot(:palo_alto, candidate.rules, version: "other")
    refute change.verify(candidate: wrong).verified?
  end
end

class ChangeSetTest
  test "append retains untouched rule numbers and sealed reference identity" do
    original = rule(:palo_alto, name: "old", rule_number: 100)
    current = snapshot(:palo_alto, [ original ])
    added = rule(:palo_alto, name: "new", source: "10.1.1.1")
    change = P::ChangeSet.new(snapshot: current, intents: [ P::ChangeSet::Intent.create(rule: added, placement: :append) ], targets: [])
    candidate = change.apply
    assert_same original, candidate.rules.find { |rule| rule.name == "old" }
    assert_equal 100, original.rule_number
    assert_equal 101, candidate.rules.find { |rule| rule.name == "new" }.rule_number
    assert current.catalog.sealed?
  end
end

class ChangeSetTest
  test "independent generic readback proves unchanged declarations without equating unknown defaults" do
    original = rule(:hillstone, name: "existing", source: "10.9.9.9", rule_number: 20)
    current = snapshot(:hillstone, [ original ])
    added = rule(:hillstone, name: "new", source: "10.0.0.0/24")
    change = P::ChangeSet.new(snapshot: current, intents: [ P::ChangeSet::Intent.create(rule: added, placement: :prepend) ], targets: [ target ])
    planned = change.apply
    readback = snapshot(:hillstone, planned.rules.map { |entry| entry.with.seal! })
    proof = change.verify(candidate: readback)
    assert proof.verified?, proof.issues.map(&:message).join("; ")
    widened = readback.rules.map { |entry| entry.name == "new" ? rule(:hillstone, name: "new", source: "10.0.0.0/16", rule_number: entry.rule_number) : entry }
    refute change.verify(candidate: snapshot(:hillstone, widened)).verified?
  end
end

class ChangeSetTest
  test "unknown native action changes are not structurally equivalent readback" do
    original = rule(:hillstone, action: "vendor-unknown-a", rule_number: 1)
    current = snapshot(:hillstone, [ original ])
    change = P::ChangeSet.new(snapshot: current, intents: [], targets: [])
    readback = snapshot(:hillstone, [ original.with(native_action: "vendor-unknown-b") ])
    assert_nil original.action
    assert_nil readback.rules.sole.action
    refute change.verify(candidate: readback).verified?
  end
end

class ChangeSetTest
  test "H3C binding endpoint changes cannot pass with no Zone declarations" do
    snapshots = [ [ [ "a", "b" ], [ "c", "d" ] ], [ [ "a", "d" ], [ "c", "b" ] ] ].map do |pairs|
      text = "object-policy ip p\n rule 1 pass\n#\n" + pairs.map do |from, to|
        "zone-pair security source #{from} destination #{to}\n object-policy apply ip p\n#\n"
      end.join
      parsed = Algosec::Config::Parser.perform(text, vendor: :h3c, device_id: 1)
      assert parsed.complete?, parsed.diagnostics.inspect
      P::Snapshot.from_config(parsed)
    end
    before, after = snapshots
    assert_empty before.elements(E::Zone)
    assert_empty P::ChangeSet::DeclarationComparison.new(before, after).changed_rules
    change = P::ChangeSet.new(snapshot: before, intents: [], targets: [])
    proof = change.verify(candidate: after)
    refute proof.verified?
    assert proof.differences.any? { |difference| difference.context.values_at(:from_zone, :to_zone) == [ "a", "b" ] }
  end

  test "independent readback publishes the same graph before retaining proof references" do
    current = snapshot(:palo_alto)
    entry = rule(:palo_alto, source: "10.0.0.0/24", rule_number: 1)
    readback = snapshot(:palo_alto, [ entry ])
    change = P::ChangeSet.new(snapshot: current, intents: [], targets: [ target ])
    proof = change.verify(candidate: readback)
    assert proof.verified?
    assert_same readback, proof.candidate
    assert readback.catalog.sealed?
    assert entry.sealed?
    assert_raises(FrozenError) { entry.action = "deny" }
  end

  test "unchanged large zone inventory does not spend Cartesian context budget" do
    zones = 200.times.map { |index| E::Zone.new(name: "zone#{index}", **context(:palo_alto)) }
    current = snapshot(:palo_alto, zones)
    change = P::ChangeSet.new(snapshot: current, intents: [], targets: [], proof_limit: 1)
    assert change.verify.verified?
    independent = snapshot(:palo_alto, zones.map { |zone| E::Zone.new(name: zone.name, **context(:palo_alto)) })
    assert change.verify(candidate: independent).verified?
  end

  test "proof context budget rejects wildcard expansion before visiting pairs" do
    zones = 70.times.map { |index| E::Zone.new(name: "zone#{index}", **context(:palo_alto)) }
    current = snapshot(:palo_alto, zones)
    wildcard = rule(:palo_alto, from_zones: [ "any" ], to_zones: [ "any" ])
    change = P::ChangeSet.new(snapshot: current, intents: [ P::ChangeSet::Intent.create(rule: wildcard, placement: :append) ], targets: [], proof_limit: 32)
    proof = change.verify
    refute proof.verified?
    assert_equal :proof_budget_exceeded, proof.issues.sole.evidence[:code]
  end

  test "explicit affected zone pair avoids unrelated zone Cartesian expansion" do
    zones = 70.times.map { |index| E::Zone.new(name: "zone#{index}", **context(:palo_alto)) }
    current = snapshot(:palo_alto, zones)
    added = rule(:palo_alto)
    change = P::ChangeSet.new(snapshot: current, intents: [ P::ChangeSet::Intent.create(rule: added, placement: :append) ], targets: [ target ], proof_limit: 32)
    assert change.verify.verified?
  end

  test "pure deletion preserves catalog order and needs no invented disabled rule numbers" do
    disabled = [ rule(:palo_alto, name: "disabled-a", disabled: true), rule(:palo_alto, name: "disabled-b", disabled: true) ]
    retained = rule(:palo_alto, name: "retained", source: "10.9.9.9", rule_number: 100)
    current = snapshot(:palo_alto, disabled + [ retained ])
    change = P::ChangeSet.new(snapshot: current, intents: disabled.map { |entry| P::ChangeSet::Intent.delete(rule_id: entry.rule_id) }, targets: [])
    candidate = change.apply
    assert_equal [ retained ], candidate.rules
    assert_same retained, candidate.rules.sole
    assert candidate.catalog.sealed?
    assert change.verify.verified?
    assert P::Plan.new(operation: :reclaim, snapshot: current, changes: [], change_set: change).ready?
  end

  test "pure deletion still rejects missing duplicated identities and unknown active ordering" do
    entries = [ rule(:palo_alto, name: "a"), rule(:palo_alto, name: "b") ]
    current = snapshot(:palo_alto, entries)
    intents = entries.map { |entry| P::ChangeSet::Intent.delete(rule_id: entry.rule_id) }
    change = P::ChangeSet.new(snapshot: current, intents: intents, targets: [])
    assert_empty change.apply.rules
    refute change.verify.verified?
    assert_raises(ArgumentError) { P::ChangeSet.new(snapshot: current, intents: [ intents.first, intents.first ], targets: []).apply }
    assert_raises(ArgumentError) { P::ChangeSet.new(snapshot: current, intents: [ P::ChangeSet::Intent.delete(rule_id: "missing") ], targets: []).apply }
  end

  test "delete readback requires actual absence even when the retained rule has no effect" do
    original = rule(:palo_alto, disabled: true)
    current = snapshot(:palo_alto, [ original ])
    change = P::ChangeSet.new(snapshot: current, intents: [ P::ChangeSet::Intent.delete(rule_id: original.rule_id) ], targets: [])
    assert change.verify.verified?
    proof = change.verify(candidate: current)
    refute proof.verified?
    assert_equal :unfulfilled_deletion, proof.issues.sole.evidence[:code]
  end
end

class ChangeSetTest
  test "control changes without an inferable domain remain unproven" do
    current = snapshot(:palo_alto)
    readback = snapshot(:palo_alto, [ E::Zone.new(name: "unexpected", **context(:palo_alto)) ])
    proof = P::ChangeSet.new(snapshot: current, intents: [], targets: []).verify(candidate: readback)
    refute proof.verified?
    assert_equal :unproven_control_context, proof.issues.sole.evidence[:code]
  end
end
