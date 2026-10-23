# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "../framework/support/policy_factory"

class NatSourcePortRelationTest < Minitest::Test
  include PolicyFactory

  RAW = <<~CONFIG.freeze
    set network interface ethernet ethernet1/1 layer3 ip 10.0.0.254/24
    set network interface ethernet ethernet1/2 layer3 ip 192.0.2.254/24
    set network virtual-router default interface [ ethernet1/1 ethernet1/2 ]
    set zone inside network layer3 ethernet1/1
    set zone outside network layer3 ethernet1/2
    set rulebase nat rules source from inside
    set rulebase nat rules source to outside
    set rulebase nat rules source source 10.0.0.1
    set rulebase nat rules source destination 192.0.2.1
    set rulebase nat rules source service any
    set rulebase nat rules source source-translation static-ip translated-address 203.0.113.1
    set rulebase nat rules source source-translation static-ip bi-directional no
  CONFIG

  def test_native_static_address_translation_cannot_invent_a_source_port_rewrite
    plan, proof = prove(source_port: "1234", mapped_source_port: "6000")
    refute proof.verified?
    refute plan.ready?
    refute proof.verify_readback(parse(RAW, revision: "after")).verified?
    assert_includes proof.issues.map { |issue| issue.evidence[:code] }, :unsupported_nat_source_port
  end

  def test_native_identity_ports_singleton_and_range_pass_full_readback
    [ "1234", "1234-1240" ].each do |ports|
      plan, proof = prove(source_port: ports, mapped_source_port: ports)
      assert proof.verified?, proof.to_h.inspect
      assert plan.ready?, plan.issues.inspect
      assert plan.verify_readback(parse(RAW, revision: "after")).verified?
    end
  end

  def test_unknown_original_port_cannot_guarantee_a_requested_mapped_port
    _plan, proof = prove(mapped_source_port: "6000")
    refute proof.verified?
    assert_includes proof.issues.map { |issue| issue.evidence[:code] }, :unsupported_nat_source_port
  end

  def test_omitted_mapped_port_keeps_address_only_proof
    [ {}, { source_port: "1234-1240" } ].each do |options|
      plan, proof = prove(**options)
      assert proof.verified?, proof.to_h.inspect
      assert plan.ready?
      assert plan.verify_readback(parse(RAW, revision: "after")).verified?
    end
  end

  def test_dynamic_allocation_does_not_guarantee_even_same_requested_source_port
    text = RAW.lines.reject { |line| line.include?("bi-directional") }.join.gsub("static-ip", "dynamic-ip-and-port")
    plan, proof = prove(text: text, type: :dynamic, source_port: "1234", mapped_source_port: "1234")
    refute proof.verified?
    refute plan.ready?
    assert_includes proof.issues.map { |issue| issue.evidence[:code] }, :unsupported_nat_allocation
  end

  def test_explicit_canonical_singleton_rewrite_is_checked_after_rule_selection
    nat = E::DynamicNat.new(**context(:palo_alto), name: "explicit", direction: :source, nat_order: [ 1 ],
      from_zone: "inside", to_zone: "outside", source_set: "10.0.0.1", destination_set: "192.0.2.1",
      nat_type: "static-ip", translated_source_set: "203.0.113.1", translated_source_port: "6000")
    baseline = snapshot(:palo_alto, [ nat ])
    options = { address: "10.0.0.1", direction: :source, zone: "outside", peers: { "192.0.2.1" => {} },
      services: { "tcp/443" => {} }, flow: { from_zone: "inside", to_zone: "outside" },
      allocation: { type: :static, address: "203.0.113.1" }, source_port: "1234-1240" }
    expected = P::Nat::Verification::Expectation.new(**options, mapped_source_port: "6000")
    proof = P::Nat::Verification.new(snapshot: baseline, candidate: baseline, expectations: [ expected ])
    assert proof.verified?, proof.to_h.inspect
    wrong = P::Nat::Verification::Expectation.new(**options, mapped_source_port: "6000-6001")
    refute P::Nat::Verification.new(snapshot: baseline, candidate: baseline, expectations: [ wrong ]).verified?
  end

  def test_owner_requires_identity_or_an_explicit_singleton_fixed_rewrite
    original = ports("1234-1240")
    identity = E::Nat::SourceTranslation.new(mode: :static_ip)
    assert_equal :identity, identity.fixed_port_relation(original: original, translated: original)
    assert_nil identity.fixed_port_relation(original: original, translated: ports("6000"))
    assert_nil identity.fixed_port_relation(original: nil, translated: ports("6000"))
    fixed = E::Nat::SourceTranslation.new(mode: :static_ip, port: "6000")
    assert_equal :fixed, fixed.fixed_port_relation(original: original, translated: ports("6000"))
    assert_nil fixed.fixed_port_relation(original: original, translated: ports("6001"))
    assert_nil fixed.fixed_port_relation(original: original, translated: ports("6000-6001"))
    ranged = E::Nat::SourceTranslation.new(mode: :static_ip, port: "6000-6001")
    assert_nil ranged.fixed_port_relation(original: ports("1234-1235"), translated: ports("6000-6001"))
    [ nil, :unknown, :dynamic_ip, :dynamic_ip_and_port ].each do |mode|
      assert_nil E::Nat::SourceTranslation.new(mode: mode, port: "6000").fixed_port_relation(original: original, translated: ports("6000"))
    end
  end

  private

  def ports(value) = Algosec::IPAddr.ports(value)

  def parse(text, revision: "before")
    parsed = Algosec::Config::Parser.perform(text, vendor: :palo_alto, device_id: 1)
    assert parsed.complete?, parsed.diagnostics.inspect
    P::Snapshot.from_config(parsed, revision: revision)
  end

  def prove(text: RAW, type: :static, **options)
    baseline = parse(text)
    change = P::ChangeSet.new(snapshot: baseline, intents: [], targets: [])
    expected = P::Nat::Verification::Expectation.new(address: "10.0.0.1", direction: :source, zone: "outside",
      peers: { "192.0.2.1" => {} }, services: { "tcp/443" => {} }, flow: { from_zone: "inside", to_zone: "outside" },
      allocation: { type: type, address: "203.0.113.1" }, **options)
    proof = P::Nat::Verification.new(snapshot: baseline, candidate: change.apply, expectations: [ expected ], change_set: change)
    plan = P::Plan.new(operation: :configure, snapshot: baseline, changes: [], change_set: change,
      commands: "", required_effects: [ :nat ], effect_proofs: { nat: proof })
    [ plan, proof ]
  end
end
