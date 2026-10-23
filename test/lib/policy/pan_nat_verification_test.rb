# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "../framework/support/policy_factory"

class PanNatVerificationTest < Minitest::Test
  include PolicyFactory

  ORIGINAL = <<~CONFIG.freeze
    set network interface ethernet ethernet1/1 layer3 ip 10.0.0.254/24
    set network interface ethernet ethernet1/2 layer3 ip 192.0.2.254/24
    set network virtual-router default interface [ ethernet1/1 ethernet1/2 ]
    set network virtual-router default routing-table ip static-route default destination 0.0.0.0/0
    set network virtual-router default routing-table ip static-route default interface ethernet1/2
    set network virtual-router default routing-table ip static-route default nexthop ip-address 192.0.2.253
    set zone inside network layer3 ethernet1/1
    set zone outside network layer3 ethernet1/2
  CONFIG

  def test_static_source_native_declaration_and_independent_readback
    plan = source_plan(:static)
    assert_verified_readback(plan)
    assert_equal :fixed_relation, plan.effect_proofs.fetch(:nat).observations.map { |item| item[:relation] }.uniq.sole
  end

  def test_dynamic_address_configuration_is_possible_targets_only
    plan = source_plan(:dynamic)
    assert_verified_readback(plan)
    assert_equal :possible_targets, plan.effect_proofs.fetch(:nat).observations.map { |item| item[:relation] }.uniq.sole
  end

  def test_destination_port_translation_native_declaration_and_readback
    plan = destination_plan
    assert_verified_readback(plan)
    wrong = parse(ORIGINAL + plan.script.sub("translated-port 8443", "translated-port 8444"), revision: "after")
    refute plan.verify_readback(wrong).verified?
  end

  def test_combined_translation_is_one_real_native_rule
    plan = destination_plan(combined: true)
    assert_verified_readback(plan)
    proof = plan.effect_proofs.fetch(:nat)
    assert_equal [ :destination, :source ], proof.observations.map { |item| item[:expectation][:direction] }.uniq
    assert_equal 1, proof.candidate.nat_rules.size
    assert proof.candidate.nat_rules.sole.dual_translation?
  end

  def test_generated_name_collision_uses_the_actual_native_reference
    original = ORIGINAL + "set address addr_10.0.0.1/32 ip-netmask 10.9.9.9/32\n"
    plan = source_plan(:static, original: original)
    assert plan.ready?, plan.issues.map(&:to_h).inspect
    assert_includes plan.script, 'source "addr_10.0.0.1/32_2"'
    proof = plan.verify_readback(parse(original + plan.script, revision: "after"))
    assert proof.verified?, proof.to_h.inspect
    wrong = (original + plan.script).sub('"addr_10.0.0.1/32_2" ip-netmask 10.0.0.1/32', '"addr_10.0.0.1/32_2" ip-netmask 10.0.0.2/32')
    refute plan.verify_readback(parse(wrong, revision: "after")).verified?
  end

  def test_existing_native_nat_keeps_identity_order_and_relation
    original = ORIGINAL + <<~CONFIG
      set rulebase nat rules existing from inside
      set rulebase nat rules existing to outside
      set rulebase nat rules existing source 10.0.0.2
      set rulebase nat rules existing destination 192.0.2.2
      set rulebase nat rules existing service any
      set rulebase nat rules existing source-translation static-ip translated-address 203.0.113.2
      set rulebase nat rules existing source-translation static-ip bi-directional no
    CONFIG
    plan = source_plan(:static, original: original)
    assert plan.ready?, plan.issues.map(&:to_h).inspect
    assert_equal [ [ 1 ], [ 2 ] ], plan.effect_proofs.fetch(:nat).candidate.nat_rules.map(&:position)
    proof = plan.verify_readback(parse(original + plan.script, revision: "after"))
    assert proof.verified?, proof.to_h.inspect
  end

  def test_multiple_native_service_rules_prove_the_whole_request
    plan = source_plan(:static, services: [ "tcp/443", "tcp/8443" ])
    assert_verified_readback(plan)
    assert_equal 2, plan.effect_proofs.fetch(:nat).candidate.nat_rules.size
  end

  def test_interface_allocation_is_explicitly_nonready
    plan = source_plan(:dynamic, address: nil)
    refute plan.ready?
    assert plan.generated?
    assert_includes plan.issues.map { |item| item.evidence[:code] }, :unsupported_nat_allocation
  end

  def test_generation_proof_cannot_be_reused_for_another_change_set
    plan = source_plan(:static)
    change = plan.change_set
    other = P::ChangeSet.new(snapshot: change.snapshot, intents: change.intents, targets: change.targets, at: change.at)
    assert_raises(ArgumentError) do
      P::Plan.new(operation: :configure, snapshot: change.snapshot, changes: [], change_set: other,
        commands: plan.script, effect_proofs: plan.effect_proofs, required_effects: [ :nat ])
    end
  end

  private

  def parse(text, revision: "before")
    result = Algosec::Config::Parser.perform(text, vendor: :palo_alto, device_id: 1)
    assert result.complete?, result.diagnostics.inspect
    P::Snapshot.from_config(result, revision: revision)
  end

  def source_plan(type, original: ORIGINAL, services: [ "tcp/443" ], address: "203.0.113.1")
    data = group(:palo_alto, services: services)
    actions = P::Result::DIMENSIONS.to_h { |dimension| [ dimension, data.fetch(dimension).transform_values { nil } ] }
    actions[:nat_sources] = { "10.0.0.1/32" => { real_ip: "10.0.0.1/32", nat: { type: type, address: address } } }
    result = P::Result.new(**data, snapshot: parse(original), type: :new, actions: { new: actions })
    P::Planner.new(P::Report.new(results: [ result ])).plans.sole
  end

  def destination_plan(combined: false)
    data = group(:palo_alto, sources: [ "192.0.2.1" ], destinations: [ "203.0.113.9" ],
      services: [ { services: [ "tcp/443" ], translated_port: "8443" } ], from_zone: "outside", to_zone: "inside", hit: :destination)
    actions = P::Result::DIMENSIONS.to_h { |dimension| [ dimension, data.fetch(dimension).transform_values { nil } ] }
    actions[:nat_destinations] = { "10.0.0.9/32" => { real_ip: "10.0.0.9/32", nat: { type: :static, address: "203.0.113.9" } } }
    if combined
      actions[:nat_sources] = { "192.0.2.1/32" => { real_ip: "192.0.2.1/32", nat: { type: :static, address: "198.51.100.1" } } }
    end
    result = P::Result.new(**data, snapshot: parse(ORIGINAL), type: :new, actions: { new: actions })
    P::Planner.new(P::Report.new(results: [ result ])).plans.sole
  end

  def assert_verified_readback(plan)
    assert plan.ready?, plan.issues.map(&:to_h).inspect
    readback = parse(ORIGINAL + plan.script, revision: "after")
    proof = plan.verify_readback(readback)
    assert proof.verified?, proof.to_h.inspect
  end
end
