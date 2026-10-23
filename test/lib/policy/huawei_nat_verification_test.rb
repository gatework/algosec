# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "../framework/support/policy_factory"
require_relative "../framework/support/policy_config"

class HuaweiNatVerificationTest < Minitest::Test
  include PolicyFactory
  include PolicyConfig

  ORIGINAL = <<~CONFIG.freeze
    interface GigabitEthernet0/0/1
     ip address 10.0.0.254 255.255.255.0
    #
    interface GigabitEthernet0/0/2
     ip address 192.0.2.254 255.255.255.0
    #
    firewall zone name inside
     add interface GigabitEthernet0/0/1
    #
    firewall zone name outside
     add interface GigabitEthernet0/0/2
    #
    ip route-static 0.0.0.0 0 GigabitEthernet0/0/2 192.0.2.253
  CONFIG

  def test_source_pool_native_policy_and_independent_readback
    plan = plan_for
    assert_verified_readback(plan)
    assert_equal :possible_targets, plan.effect_proofs.fetch(:nat).observations.map { |item| item[:relation] }.uniq.sole
  end

  def test_fixed_pool_with_explicit_route_proven_interface
    plan = plan_for(interface: "GigabitEthernet0/0/2")
    assert_verified_readback(plan)
    assert_includes plan.script, "egress-interface GigabitEthernet0/0/2"
  end

  def test_singleton_destination_pool_and_port_relation
    plan = plan_for(destination: true, port: true)
    assert_verified_readback(plan)
    wrong = parse(ORIGINAL + saved_config(:huawei, plan.script).sub(/address-group (\S+) 8443/, 'address-group \1 8444'), revision: "after")
    refute plan.verify_readback(wrong).verified?
  end

  def test_dual_native_policy_keeps_both_relations
    plan = plan_for(destination: true, combined: true)
    assert_verified_readback(plan)
    assert plan.effect_proofs.fetch(:nat).candidate.nat_rules.any?(&:dual_translation?)
  end

  def test_existing_pool_reference_and_mode_survive_independent_parse
    original = ORIGINAL + "nat address-group existing_pool\n mode pat\n section 0 198.51.100.1 198.51.100.1\n#\n"
    plan = plan_for(original: original)
    assert plan.ready?, plan.issues.map(&:to_h).inspect
    assert_includes plan.script, "action source-nat address-group existing_pool"
    proof = plan.effect_proofs.fetch(:nat)
    assert_same proof.snapshot.elements(E::NatPool).sole, proof.candidate.nat_rules.sole.source_pool
    readback = original + saved_config(:huawei, plan.script)
    assert plan.verify_readback(parse(readback, revision: "after")).verified?
    refute plan.verify_readback(parse(readback.sub("mode pat", "mode no-pat global"), revision: "after")).verified?
  end

  def test_native_line_offsets_shift_without_changing_prior_nat_order
    original = ORIGINAL + <<~CONFIG
      nat address-group old_pool
       mode pat
       section 0 198.51.100.2 198.51.100.2
      #
      nat-policy
       rule name old
        source-zone inside
        destination-zone outside
        source-address 10.0.0.2 32
        action source-nat address-group old_pool
      #
    CONFIG
    plan = plan_for(original: original)
    assert plan.ready?, plan.issues.map(&:to_h).inspect
    current = "\n\n" + original + saved_config(:huawei, plan.script)
    assert plan.verify_readback(parse(current, revision: "after")).verified?
    wrong = current.sub("source-address 10.0.0.2 32", "source-address 10.0.0.3 32")
    refute plan.verify_readback(parse(wrong, revision: "after")).verified?
  end

  def test_known_no_pat_pool_proves_configuration_targets_without_runtime_claim
    text = ORIGINAL + <<~CONFIG
      nat address-group pool
       mode no-pat global
       section 0 198.51.100.1 198.51.100.9
      #
      nat-policy
       rule name source
        source-zone inside
        destination-zone outside
        source-address 10.0.0.1 32
        action source-nat address-group pool
      #
    CONFIG
    baseline = parse(text)
    expected = P::Nat::Verification::Expectation.new(address: "10.0.0.1", zone: "outside", direction: :source,
      peers: { "192.0.2.1" => {} }, services: { "tcp/443" => {} }, flow: { from_zone: "inside", to_zone: "outside" },
      allocation: { type: :dynamic, address: "198.51.100.1-198.51.100.9" })
    proof = P::Nat::Verification.new(snapshot: baseline, candidate: baseline, expectations: [ expected ])
    assert proof.verified?, proof.to_h.inspect
    assert_equal :dynamic_ip, proof.observations.sole[:source_mode]
    assert_equal :possible_targets, proof.observations.sole[:relation]
    assert proof.verify_readback(parse(text, revision: "after")).verified?
  end

  def test_combined_port_keeps_exact_service_holes_and_independent_readback
    plan = plan_for(destination: true, combined: true, port: true)
    assert_verified_readback(plan)
    text = ORIGINAL + saved_config(:huawei, plan.script)
    wrong = text.sub(/address-group (\S+) 8443/, 'address-group \1 8444')
    refute plan.verify_readback(parse(wrong, revision: "after")).verified?
    wrong = text.sub("service protocol tcp destination-port 443", "service protocol tcp destination-port 444")
    refute plan.verify_readback(parse(wrong, revision: "after")).verified?
  end

  private

  def parse(text, revision: "before")
    parsed = Algosec::Config::Parser.perform(text, vendor: :huawei, device_id: 1)
    assert parsed.complete?, parsed.diagnostics.inspect
    P::Snapshot.from_config(parsed, software_version: "V500R005", revision: revision)
  end

  def plan_for(destination: false, combined: false, port: false, original: ORIGINAL, interface: nil)
    data = if destination
      group(:huawei, sources: [ "192.0.2.1" ], destinations: [ "203.0.113.9" ], services: port ? [ { services: [ "tcp/443" ], translated_port: "8443" } ] : [ "tcp/443" ], from_zone: "outside", to_zone: "inside", hit: :destination)
    else
      group(:huawei)
    end
    actions = P::Result::DIMENSIONS.to_h { |dimension| [ dimension, data.fetch(dimension).transform_values { nil } ] }
    if destination
      actions[:nat_destinations] = { "10.0.0.9/32" => { real_ip: "10.0.0.9/32", nat: { type: :dynamic, address: "203.0.113.9" } } }
    end
    if !destination || combined
      real = combined ? "192.0.2.1/32" : "10.0.0.1/32"
      allocation = { type: :dynamic, address: "198.51.100.1" }
      allocation.merge!(interface: interface, option: "d") if interface
      actions[:nat_sources] = { real => { real_ip: real, nat: allocation } }
    end
    result = P::Result.new(**data, snapshot: parse(original), type: :new, actions: { new: actions })
    P::Planner.new(P::Report.new(results: [ result ])).plans.sole
  end

  def assert_verified_readback(plan)
    assert plan.ready?, plan.issues.map(&:to_h).inspect
    proof = plan.verify_readback(parse(ORIGINAL + saved_config(:huawei, plan.script), revision: "after"))
    assert proof.verified?, proof.to_h.inspect
  end
end
