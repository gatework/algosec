# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "../framework/support/policy_factory"
require_relative "../framework/support/policy_config"
require "algosec/policy/nat/verification"
require "algosec/policy/nat/generation"

class NatVerificationTest < Minitest::Test
  include PolicyFactory
  include PolicyConfig

  def test_real_source_relation_and_independent_readback
    nat = source_nat
    baseline = snapshot(:palo_alto, [ nat ])
    proof = verify(baseline, baseline, [ source_expectation ])
    assert proof.verified?, proof.to_h.inspect
    assert_equal :nat, proof.effect
    assert_equal Algosec::SEMANTIC_VERSION, proof.baseline[:semantic_version]
    assert proof.verify_readback(snapshot(:palo_alto, [ source_nat ])).verified?
    refute proof.verify_readback(snapshot(:palo_alto, [ source_nat(translated_source_set: "203.0.113.99") ])).verified?
    assert JSON.generate(proof.to_h)
    assert_predicate proof, :frozen?
  end

  def test_destination_relation_and_translated_port
    nat = destination_nat
    baseline = snapshot(:palo_alto, [ nat ])
    proof = verify(baseline, baseline, [ destination_expectation ])
    assert proof.verified?, proof.to_h.inspect
    wrong = snapshot(:palo_alto, [ destination_nat(translated_destination_port: "8444") ])
    refute proof.verify_readback(wrong).verified?
  end

  def test_first_original_match_cannot_be_skipped
    first = destination_nat(name: "first", translated_destination_set: "10.0.0.8")
    baseline = snapshot(:palo_alto, [ first, destination_nat(name: "later", nat_order: [ 2 ]) ])
    refute verify(baseline, baseline, [ destination_expectation ]).verified?
  end

  def test_unknown_source_allocation_is_not_static_proof
    baseline = snapshot(:palo_alto, [ source_nat(nat_type: nil) ])
    refute verify(baseline, baseline, [ source_expectation ]).verified?
  end

  def test_dynamic_and_interface_allocation_do_not_claim_deterministic_effect
    baseline = snapshot(:palo_alto, [ source_nat(nat_type: "dynamic-ip-and-port") ])
    proof = verify(baseline, baseline, [ source_expectation(allocation: { type: :dynamic, address: "203.0.113.1", interface: "outside" }) ])
    refute proof.verified?
    assert_includes proof.issues.map { |issue| issue.evidence[:code] }, :unsupported_nat_allocation
  end

  def test_known_dynamic_configuration_proves_only_possible_targets
    baseline = snapshot(:palo_alto, [ source_nat(nat_type: "dynamic-ip-and-port") ])
    expected = source_expectation(allocation: { type: :dynamic, address: "203.0.113.1" })
    proof = verify(baseline, baseline, [ expected ])
    assert proof.verified?, proof.to_h.inspect
    assert_equal :possible_targets, proof.observations.sole[:relation]
    assigned = source_expectation(allocation: { type: :dynamic, address: "203.0.113.1" }, mapped_source_port: "6000")
    refute verify(baseline, baseline, [ assigned ]).verified?
  end

  def test_generated_scope_outside_target_is_rejected
    baseline = snapshot(:palo_alto)
    candidate = snapshot(:palo_alto, [ source_nat(source_set: "10.0.0.0/24") ])
    proof = verify(baseline, candidate, [ source_expectation ])
    refute proof.verified?
    assert_includes proof.issues.map { |issue| issue.evidence[:code] }, :nat_outside_target
  end

  def test_new_exact_source_relation_has_outside_target_proof
    proof = verify(snapshot(:palo_alto), snapshot(:palo_alto, [ source_nat ]), [ source_expectation ])
    assert proof.verified?, proof.to_h.inspect
  end

  def test_existing_relation_cannot_be_changed_even_outside_requested_flow
    baseline = snapshot(:palo_alto, [ source_nat(name: "existing", source_set: "10.0.0.2") ])
    candidate = snapshot(:palo_alto, [ source_nat(name: "existing", source_set: "10.0.0.2", translated_source_set: "203.0.113.2"), source_nat ])
    refute verify(baseline, candidate, [ source_expectation ]).verified?
  end

  def test_readback_context_drift_and_incomplete_config_fail
    baseline = snapshot(:palo_alto, [ source_nat ])
    proof = verify(baseline, baseline, [ source_expectation ])
    refute proof.verify_readback(snapshot(:palo_alto, [ source_nat ], settings: { changed: true })).verified?
    incomplete = P::Snapshot.new(**context(:palo_alto), catalog: baseline.catalog, complete: false)
    refute proof.verify_readback(incomplete).verified?
  end

  def test_expectation_rejects_unknown_flow_keys_and_persisted_receipts
    assert_raises(ArgumentError) { source_expectation(flow: { original_src: "10.0.0.1" }) }
    assert_raises(ArgumentError) { verify(snapshot(:palo_alto), snapshot(:palo_alto), [ { verified: true } ]) }
  end

  def test_actual_huawei_server_declaration_roundtrips_independent_parser
    parsed = Algosec::Config::Parser.perform("", vendor: :huawei, device_id: 1)
    baseline = P::Snapshot.from_config(parsed, software_version: "V500R005", revision: "before")
    evidence = Algosec::Vendors::Huawei::Nat::Generation.server(snapshot: baseline, command: "nat server publish zone outside global 203.0.113.9 inside 10.0.0.9", zone: "outside", real: "10.0.0.9", mapped: "203.0.113.9")
    candidate = baseline.with_catalog(E::Catalog.new(evidence.declarations, **context(:huawei)))
    proof = verify(baseline, candidate, evidence.expectations)
    assert proof.verified?, proof.to_h.inspect
    saved = Algosec::Config::Parser.perform("nat server publish zone outside global 203.0.113.9 inside 10.0.0.9\n", vendor: :huawei, device_id: 1)
    readback = P::Snapshot.from_config(saved, software_version: "V500R005", revision: "after")
    assert proof.verify_readback(readback).verified?, proof.verify_readback(readback).to_h.inspect
    wrong = Algosec::Config::Parser.perform("nat server publish zone outside global 203.0.113.9 inside 10.0.0.8\n", vendor: :huawei, device_id: 1)
    refute proof.verify_readback(P::Snapshot.from_config(wrong, software_version: "V500R005", revision: "after")).verified?
    refute verify(baseline, candidate, evidence.expectations.take(1)).verified?, "Reverse relation also needs an approved target"
  end

  def test_dual_translation_requires_both_actual_relations
    nat = source_nat(direction: :bidirectional, destination_set: "203.0.113.9", translated_destination_set: "10.0.0.9")
    baseline = snapshot(:palo_alto, [ nat ])
    source = source_expectation(peers: { "203.0.113.9" => {} })
    destination = destination_expectation(peers: { "10.0.0.1" => {} }, services: nil,
      flow: { from_zone: "inside", to_zone: "outside", original_dst: "203.0.113.9" })
    refute verify(baseline, baseline, [ source ]).verified?
    proof = verify(baseline, baseline, [ source, destination ])
    assert proof.verified?, proof.to_h.inspect
  end

  def test_equal_address_unions_do_not_prove_static_pairing
    nat = E::StaticNat.new(**context(:asa), real_ip: "10.0.0.0/31", mapped_ip: "203.0.113.0/31",
      real_zone: "inside", mapped_zone: "outside", nat_order: [ 1, 1 ],
      mappings: [ [ "10.0.0.0", "203.0.113.1" ], [ "10.0.0.1", "203.0.113.0" ] ])
    baseline = snapshot(:asa, [ nat ])
    expectation = P::Nat::Verification::Expectation.new(address: "10.0.0.0/31", zone: "outside", direction: :source,
      peers: { "192.0.2.1" => {} }, allocation: { type: :static, address: "203.0.113.0/31" })
    refute verify(baseline, baseline, [ expectation ]).verified?
  end

  def test_huawei_planner_proves_actual_emitted_static_mapping_and_full_readback
    original = <<~CONFIG
      interface eth0
       ip address 10.0.0.254 255.255.255.0
      #
      interface eth1
       ip address 192.0.2.254 255.255.255.0
      #
      firewall zone inside
       add interface eth0
      #
      firewall zone outside
       add interface eth1
      #
    CONFIG
    baseline = P::Snapshot.from_config(Algosec::Config::Parser.perform(original, vendor: :huawei, device_id: 1),
      software_version: "V500R005", revision: "before")
    data = group(:huawei)
    members = P::Result::DIMENSIONS.to_h { |dimension| [ dimension, data.fetch(dimension).transform_values { nil } ] }
    members[:nat_sources] = { "10.0.0.1/32" => { real_ip: "10.0.0.1/32", nat: { type: :static, address: "203.0.113.1" } } }
    result = P::Result.new(**data, snapshot: baseline, type: :new, actions: { new: members })
    planner = P::Planner.new(P::Report.new(results: [ result ]))
    plan = planner.plans.sole
    assert plan.ready?, plan.issues.map(&:to_h).inspect
    assert plan.effect_proofs.fetch(:nat).verified?
    assert_includes plan.script, "global 203.0.113.1 inside 10.0.0.1"
    readback_text = original + saved_config(:huawei, plan.script)
    parsed = Algosec::Config::Parser.perform(readback_text, vendor: :huawei, device_id: 1)
    assert parsed.complete?, parsed.diagnostics.inspect
    readback = P::Snapshot.from_config(parsed, software_version: "V500R005", revision: "after")
    assert plan.verify_readback(readback).verified?, plan.verify_readback(readback).to_h.inspect
    wrong = Algosec::Config::Parser.perform(readback_text.sub("global 203.0.113.1 inside 10.0.0.1", "global 203.0.113.1 inside 10.0.0.8"), vendor: :huawei, device_id: 1)
    refute plan.verify_readback(P::Snapshot.from_config(wrong, software_version: "V500R005", revision: "after")).verified?
  end

  def test_huawei_searcher_static_request_remains_executable
    baseline = snapshot(:huawei, [], version: "V500R005")
    report = P::Searcher.new(networks: networks(:huawei, nat_mode: 1, address_type: :private), snapshots: { 1 => baseline }).perform(
      sources: [ { addresses: [ "10.0.0.1" ], nat: { type: :static, address: "203.0.113.1" } } ],
      destinations: [ "192.0.2.1" ], services: [ "tcp/443" ])
    assert report.success?, report.comment
    plan = P::Planner.new(report).plans.sole
    assert plan.ready?, plan.issues.map(&:to_h).inspect
    assert_equal :fixed_relation, plan.effect_proofs.fetch(:nat).observations.first.fetch(:relation)
  end

  def test_unrecorded_nat_generation_stays_nonready
    baseline = snapshot(:hillstone)
    data = group(:hillstone)
    record = { real_ip: "10.0.0.1", nat: { type: :dynamic, address: "203.0.113.1" } }
    result = P::Result.new(**data, snapshot: baseline, type: :ignore, actions: { new: { nat_sources: { "10.0.0.1" => record } } })
    plan = P::Planner.new(P::Report.new(results: [ result ])).plans.sole
    refute plan.ready?
    assert_includes plan.issues.map { |item| item.evidence[:code] }, :missing_nat_generation_evidence
  end

  def test_readback_routing_dependency_change_is_not_unchanged_nat
    baseline = snapshot(:palo_alto, [ source_nat ])
    proof = verify(baseline, baseline, [ source_expectation ])
    route = E::Route.new(**context(:palo_alto), name: "extra", subnet: "192.0.2.0/24", zone: "inside")
    readback = snapshot(:palo_alto, [ source_nat, route ])
    refute proof.verify_readback(readback).verified?
  end

  def test_changed_security_rule_cannot_leave_an_embedded_nat_predicate_stale
    matching = rule(:palo_alto)
    nat = source_nat(match_rule: matching)
    baseline = snapshot(:palo_alto, [ matching, nat ])
    changed = matching.with(action: "deny")
    candidate = snapshot(:palo_alto, [ changed, nat ])
    proof = verify(baseline, candidate, [])
    refute proof.verified?
    assert_includes proof.issues.map { |item| item.evidence[:code] }, :nat_dependency_changed
  end

  def test_unknown_native_policy_order_is_not_a_first_match_proof
    baseline = snapshot(:palo_alto, [ source_nat(name: "first", nat_order: nil), source_nat(name: "later", nat_order: nil) ])
    refute verify(baseline, baseline, [ source_expectation ]).verified?
  end

  def test_unemitted_allocation_metadata_cannot_disappear_from_the_plan
    baseline = snapshot(:huawei, [], version: "V500R005")
    data = group(:huawei, sources: [ { addresses: [ "10.0.0.1" ], nat: { type: :static, address: "203.0.113.1" } } ])
    actions = P::Result::DIMENSIONS.to_h { |dimension| [ dimension, data.fetch(dimension).transform_values { nil } ] }
    result = P::Result.new(**data, snapshot: baseline, type: :new, actions: { new: actions })
    plan = P::Planner.new(P::Report.new(results: [ result ])).plans.sole
    refute plan.ready?
    assert_includes plan.issues.map { |item| item.evidence[:code] }, :missing_nat_generation_evidence
  end

  def test_expectation_rejects_invalid_restored_values_before_any_proof
    original = source_expectation.to_h
    invalid = [
      { services: { "tcp/99999" => {} } },
      { services: { "tcp/443" => { origin: "udp/99999" } } },
      { services: { "tcp/443" => { translated_port: "99999" } } },
      { services: { "tcp/443/extra" => {} } },
      { services: { "tcp/443" => { origin: "udp/443" } } },
      { services: { "0/99999" => {} } },
      { flow: { original_dst: "not-an-address" } },
      { direction: :destination, allocation: { type: :dynamic, interface: "outside" } },
      { allocation: original[:allocation].merge(direction: "sideways") }
    ]
    invalid.each do |overrides|
      input = original.merge(overrides)
      assert_raises(ArgumentError, input.inspect) { P::Nat::Verification::Expectation.new(**input) }
      assert_raises(ArgumentError, input.inspect) { P::Nat::Verification::Expectation.from_h(JSON.parse(JSON.generate(input))) }
    end
    %w[any 0].each do |name|
      value = original.merge(services: { name => {} }, flow: { original_dst: "192.0.2.1" })
      restored = P::Nat::Verification::Expectation.from_h(JSON.parse(JSON.generate(value)))
      assert_equal P::Nat::Verification::Expectation.new(**value).to_h, restored.to_h
    end
  end

  def test_expectation_json_roundtrip_revalidates_inputs
    original = source_expectation
    restored = P::Nat::Verification::Expectation.from_h(JSON.parse(JSON.generate(original.to_h)))
    assert_equal original.to_h, restored.to_h
    assert_raises(ArgumentError) { P::Nat::Verification::Expectation.from_h(original.to_h.merge(verified: true)) }
    assert_raises(ArgumentError) { P::Nat::Verification::Expectation.from_h(original.to_h.merge(address: "not-an-address")) }
  end

  def test_unchanged_effect_is_bound_to_actual_change_set_and_sealed
    baseline = snapshot(:palo_alto, [ source_nat ])
    created = rule(:palo_alto, source: "10.0.0.8", rule_number: 1)
    change = P::ChangeSet.new(snapshot: baseline, intents: [ P::ChangeSet::Intent.create(rule: created, placement: :append) ], targets: [])
    proof = P::Nat::Verification.unchanged(change_set: change)
    assert proof.verified?, proof.to_h.inspect
    assert_same change, proof.change_set
    assert proof.generation?
    assert proof.candidate.catalog.sealed?
    assert proof.candidate.nat_rules.all?(&:sealed?)
    refute verify(baseline, baseline, []).generation?
    assert_raises(ArgumentError) { P::Nat::Verification.new(snapshot: baseline, candidate: baseline, expectations: [], change_set: change) }
  end

  def test_nat_order_offsets_may_shift_but_stage_and_sequence_must_remain
    first = source_nat(name: "first", nat_order: [ 1 ])
    second = source_nat(name: "second", source_set: "10.0.0.2", nat_order: [ 2 ])
    baseline = snapshot(:palo_alto, [ first, second ])
    proof = verify(baseline, baseline, [])
    shifted = snapshot(:palo_alto, [ source_nat(name: "first", nat_order: [ 10 ]), source_nat(name: "second", source_set: "10.0.0.2", nat_order: [ 20 ]) ])
    assert proof.verify_readback(shifted).verified?
    reversed = snapshot(:palo_alto, [ source_nat(name: "first", nat_order: [ 20 ]), source_nat(name: "second", source_set: "10.0.0.2", nat_order: [ 10 ]) ])
    refute proof.verify_readback(reversed).verified?
    single = snapshot(:palo_alto, [ source_nat(nat_order: [ 0, 1 ]) ])
    stage = snapshot(:palo_alto, [ source_nat(nat_order: [ 1, 1 ]) ])
    refute verify(single, single, []).verify_readback(stage).verified?
  end

  private

  def verify(base, candidate, expectations)
    P::Nat::Verification.new(snapshot: base, candidate: candidate, expectations: expectations)
  end

  def source_nat(**overrides)
    E::DynamicNat.new(**context(:palo_alto), name: "source", direction: :source, nat_order: [ 1 ],
      from_zone: "inside", to_zone: "outside", source_set: "10.0.0.1", destination_set: "192.0.2.1",
      translated_source_set: "203.0.113.1", nat_type: "static-ip", **overrides)
  end

  def destination_nat(**overrides)
    E::DynamicNat.new(**context(:palo_alto), name: "destination", direction: :destination, nat_order: [ 1 ],
      from_zone: "outside", to_zone: "inside", source_set: "192.0.2.1", destination_set: "203.0.113.9",
      translated_destination_set: "10.0.0.9", protocol: "tcp", destination_port: "443", translated_destination_port: "8443", **overrides)
  end

  def source_expectation(**overrides)
    P::Nat::Verification::Expectation.new(address: "10.0.0.1", zone: "outside", direction: :source,
      peers: { "192.0.2.1" => {} }, services: nil, flow: { from_zone: "inside", to_zone: "outside" },
      allocation: { type: :static, address: "203.0.113.1" }, **overrides)
  end

  def destination_expectation(**overrides)
    P::Nat::Verification::Expectation.new(address: "10.0.0.9", zone: "outside", direction: :destination,
      peers: { "192.0.2.1" => {} }, services: { "tcp/8443" => { origin: "tcp/443", translated_port: "8443" } },
      flow: { from_zone: "outside", to_zone: "inside", original_dst: "203.0.113.9" },
      allocation: { type: :static, address: "203.0.113.9" }, **overrides)
  end
end
