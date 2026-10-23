# frozen_string_literal: true

require "test_helper"
require_relative "../framework/support/policy_factory"

class EmbeddedNatOrderTest < ActiveSupport::TestCase
  include PolicyFactory

  def change_for(original, intents = [])
    traffic = P::Request::Traffic.from_maps(group(:fortinet).slice(*P::Result::DIMENSIONS))
    target = P::ChangeSet::Target.new(traffic_set: traffic, action: "allow", from_zone: "inside", to_zone: "outside")
    P::ChangeSet.new(snapshot: original, intents: intents, targets: [ target ])
  end

  def plan_for(change)
    P::Plan.new(operation: :configure, snapshot: change.snapshot, changes: [], commands: "offline order probe",
      change_set: change, effect_proofs: { nat: P::Nat::Verification.unchanged(change_set: change) })
  end

  def assert_order_change_blocked(original, change)
    assert change.verify.verified?, "The unchanged allow decisions alone cannot prove unchanged translation"
    effect = P::Nat::Verification.unchanged(change_set: change)
    refute effect.verified?
    assert_includes effect.issues.map { |issue| issue.evidence[:code] }, :nat_outside_target
    refute plan_for(change).ready?
    approved = plan_for(change_for(original))
    assert approved.ready?, approved.issues.map(&:to_h).inspect
    assert approved.verify_readback(original).verified?
    checked = approved.verify_readback(change.apply)
    refute checked.verified?
    assert_includes checked.effects.fetch(:nat).issues.map { |issue| issue.evidence[:code] }, :nat_readback_mismatch
  end

  test "two embedded NAT rules cannot trade first match order" do
    first = rule(:fortinet, name: "a", rule_number: 1, nat: true)
    second = rule(:fortinet, name: "b", rule_number: 2, nat: true)
    original = snapshot(:fortinet, [ first, second ])
    change = change_for(original, [ P::ChangeSet::Intent.move(rule_id: second.rule_id, before: first.rule_id) ])
    assert_order_change_blocked(original, change)
  end

  test "ordinary allow insertion and deletion can suppress an existing embedded NAT" do
    nat = rule(:fortinet, name: "nat", rule_number: 1, nat: true)
    plain = rule(:fortinet, name: "plain", rule_number: 2)
    original = snapshot(:fortinet, [ nat ])
    inserted = change_for(original, [ P::ChangeSet::Intent.create(rule: plain, placement: :prepend) ])
    assert_order_change_blocked(original, inserted)
    with_suppressor = inserted.apply
    deleted = change_for(with_suppressor, [ P::ChangeSet::Intent.delete(rule_id: plain.rule_id) ])
    assert_order_change_blocked(with_suppressor, deleted)
  end

  test "linked NAT depends on the actual security chain even when its nat flag is absent" do
    linked = rule(:fortinet, name: "linked", rule_number: 1)
    plain = rule(:fortinet, name: "plain", rule_number: 2)
    nat = E::DynamicNat.new(**context(:fortinet), name: "pool", match_rule: linked, nat_type: "dynamic-ip-and-port",
      source_set: "10.0.0.0/24", translated_source_set: "203.0.113.1")
    original = snapshot(:fortinet, [ linked, plain, nat ])
    refute linked.nat?
    moved = change_for(original, [ P::ChangeSet::Intent.move(rule_id: plain.rule_id, before: linked.rule_id) ])
    assert_order_change_blocked(original, moved)
  end

  test "absolute numbering and descriptions do not change embedded NAT dependencies" do
    plain = rule(:fortinet, name: "plain", rule_number: 1)
    nat = rule(:fortinet, name: "nat", rule_number: 2, nat: true)
    original = snapshot(:fortinet, [ plain, nat ])
    renumbered = snapshot(:fortinet, [ plain.with(rule_number: 100, description: "reviewed"), nat.with(rule_number: 200) ])
    effect = P::Nat::Verification.new(snapshot: original, candidate: renumbered, expectations: [])
    assert effect.verified?, effect.to_h.inspect
    assert effect.verify_readback(original).verified?
    assert plan_for(change_for(original)).verify_readback(renumbered).verified?
  end

  test "ordinary rules after the last NAT or in another chain remain independent" do
    nat = rule(:fortinet, name: "nat", rule_number: 1, nat: true, rule_set: "main")
    tail = rule(:fortinet, name: "tail", rule_number: 2, rule_set: "main")
    other = rule(:fortinet, name: "other", rule_number: 1, rule_set: "other")
    original = snapshot(:fortinet, [ nat ])
    changed = snapshot(:fortinet, [ nat, tail, other ])
    effect = P::Nat::Verification.new(snapshot: original, candidate: changed, expectations: [])
    assert effect.verified?, effect.to_h.inspect
    assert effect.verify_readback(original).verified?
    no_change = P::Nat::Verification.unchanged(change_set: change_for(original))
    assert no_change.verify_readback(changed).verified?
  end

  test "unknown embedded chain order is a typed blocker" do
    first = rule(:fortinet, name: "a", nat: true)
    second = rule(:fortinet, name: "b")
    original = snapshot(:fortinet, [ first, second ])
    effect = P::Nat::Verification.new(snapshot: original, candidate: original, expectations: [])
    refute effect.verified?
    assert_includes effect.issues.map { |issue| issue.evidence[:code] }, :unknown_order
  end

  test "complete native Fortinet order controls whether the winning allow translates" do
    original, reversed = [ [ 1, 2 ], [ 2, 1 ] ].map { |ids| native_snapshot(ids) }
    assert_equal [ 1, 1 ], [ original, reversed ].map { |graph| graph.nat_rules.size }
    packet = P::Packet.new(source: "10.0.0.1", destination: "192.0.2.1", protocol: 6, source_port: 12345, destination_port: 443)
    winners = [ original, reversed ].map do |graph|
      P::Evaluation.new(graph).perform(packet, from_zone: "inside", to_zone: "outside").partitions.sole.rule
    end
    assert_equal [ true, false ], winners.map(&:nat?)
    effect = P::Nat::Verification.new(snapshot: original, candidate: reversed, expectations: [])
    refute effect.verified?
    assert_includes effect.issues.map { |issue| issue.evidence[:code] }, :nat_outside_target
    approved = plan_for(change_for(original))
    assert approved.ready?, approved.issues.map(&:to_h).inspect
    assert approved.verify_readback(native_snapshot([ 1, 2 ])).verified?
    refute approved.verify_readback(reversed).verified?
  end

  test "native Fortinet source NAT cannot bypass an earlier ordinary allow" do
    options = { zone: "outside", direction: :source, peers: { "192.0.2.1" => {} }, services: { "tcp/443" => {} },
      flow: { from_zone: "inside", to_zone: "outside", vrf: "root" } }
    mapping = P::Nat::Resolver.new(native_snapshot([ 1, 2 ])).find("10.0.0.1", **options)
    assert_equal "1", mapping.fetch(:rule).policy_id
    assert_nil P::Nat::Resolver.new(native_snapshot([ 2, 1 ])).find("10.0.0.1", **options)
  end

  test "native ScreenOS destination NAT cannot bypass an earlier ordinary allow" do
    expected = destination_expectation
    mapping = P::Nat::Resolver.new(native_destination_snapshot([ 1, 2 ])).find(expected.address, **expected.options)
    assert_equal "1", mapping.fetch(:rule).policy_id
    assert_nil P::Nat::Resolver.new(native_destination_snapshot([ 2, 1 ])).find(expected.address, **expected.options)
  end

  test "destination relationship proof must establish the effective security winner" do
    expected = destination_expectation
    [ [ 1, 2 ], [ 2, 1 ] ].each do |ids|
      graph = native_destination_snapshot(ids)
      proof = P::Nat::Verification.new(snapshot: graph, candidate: graph, expectations: [ expected ])
      assert_equal ids.first == 1, proof.verified?, proof.to_h.inspect
      assert_equal ids.first == 1, proof.verify_readback(graph).verified?
    end
  end

  test "partial ordinary predecessor coverage cannot prove one complete NAT relationship" do
    graph = native_destination_snapshot([ 2, 1 ], plain_source: [ "10.0.0.0", "255.255.255.128" ])
    expected = destination_expectation(source: "10.0.0.0/24")
    error = assert_raises(P::Error) { P::Nat::Resolver.new(graph).find(expected.address, **expected.options) }
    assert_equal :conditional_nat, error.code
    outside = destination_expectation(source: "10.0.0.200")
    assert_equal "1", P::Nat::Resolver.new(graph).find(outside.address, **outside.options).fetch(:rule).policy_id
  end

  test "unknown predecessor conditions cannot establish embedded NAT first match" do
    original = native_destination_snapshot([ 2, 1 ])
    plain = original.rules.find { |rule| rule.native_rule_id == "2" }
    expected = destination_expectation
    [ { applications: [ "ssl" ] }, { source_users: [ "alice" ] }, { status: "unrecognized" } ].each do |attributes|
      graph = original.with_catalog(E::Catalog.new(original.catalog.to_a - [ plain ] + [ plain.with(**attributes) ], **context(:netscreen)))
      error = assert_raises(P::Error) { P::Nat::Resolver.new(graph).find(expected.address, **expected.options) }
      assert_equal :conditional_nat, error.code
    end
  end

  test "future predecessor activation cannot prove an unconditional embedded NAT relationship" do
    original = native_destination_snapshot([ 2, 1 ])
    plain = original.rules.find { |rule| rule.native_rule_id == "2" }
    future = plain.with(conditions: { starts_at: (Time.current + 3600).iso8601 })
    graph = original.with_catalog(E::Catalog.new(original.catalog.to_a - [ plain ] + [ future ], **context(:netscreen)))
    expected = destination_expectation
    error = assert_raises(P::Error) { P::Nat::Resolver.new(graph).find(expected.address, **expected.options) }
    assert_equal :conditional_nat, error.code
  end

  private

  def destination_expectation(source: "10.0.0.1")
    P::Nat::Verification::Expectation.new(address: "192.0.2.1", zone: "inside", direction: :destination,
      peers: { source => {} }, services: { "tcp/443" => {} },
      flow: { original_dst: "203.0.113.9", from_zone: "inside", to_zone: "outside" },
      allocation: { type: :static, address: "203.0.113.9" })
  end

  def native_destination_snapshot(ids, plain_source: [ "10.0.0.0", "255.255.255.0" ])
    config = <<~CONFIG
      set address inside clients 10.0.0.0 255.255.255.0
      set address inside plain-clients #{plain_source.join(" ")}
      set address outside public 203.0.113.9 255.255.255.255
      set service web protocol tcp src-port 0-65535 dst-port 443
    CONFIG
    ids.each do |id|
      config += if id == 1
        "set policy id 1 from inside to outside clients public web nat dst ip 192.0.2.1 permit\n"
      else
        "set policy id 2 from inside to outside plain-clients public web permit\n"
      end
    end
    parsed = Algosec::Config::Parser.perform(config, vendor: :netscreen, device_id: 1)
    assert parsed.complete?, parsed.diagnostics.map(&:message).join("; ")
    P::Snapshot.from_config(parsed)
  end

  def native_snapshot(ids)
    config = <<~CONFIG
      config system interface
      edit inside
      set ip 10.0.0.254 255.255.255.0
      next
      edit outside
      set ip 192.0.2.254 255.255.255.0
      next
      end
      config firewall address
      edit clients
      set subnet 10.0.0.0 255.255.255.0
      next
      edit server
      set subnet 192.0.2.1 255.255.255.255
      next
      end
      config firewall service custom
      edit web
      set protocol TCP/UDP/SCTP
      set tcp-portrange 443
      next
      end
      config firewall ippool
      edit public
      set startip 203.0.113.1
      set endip 203.0.113.1
      next
      end
    CONFIG
    policies = ids.map do |number|
      <<~CONFIG
        edit #{number}
        set srcintf inside
        set dstintf outside
        set srcaddr clients
        set dstaddr server
        set action accept
        set schedule always
        set service web
        #{number == 1 ? "set nat enable\nset poolname public" : "set nat disable"}
        next
      CONFIG
    end
    parsed = Algosec::Config::Parser.perform(config + "config firewall policy\n" + policies.join + "end\n", vendor: :fortinet, device_id: 1)
    assert parsed.complete?, parsed.diagnostics.map(&:message).join("; ")
    P::Snapshot.from_config(parsed)
  end
end
