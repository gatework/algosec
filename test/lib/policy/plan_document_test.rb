# frozen_string_literal: true

require "test_helper"
require "algosec/policy/plan_document"
require_relative "../framework/support/policy_factory"

class PlanDocumentTest < ActiveSupport::TestCase
  include PolicyFactory

  test "native NAT candidate and typed expectations round trip and reprove" do
    originals = {
      huawei: "interface GigabitEthernet0/0/1\n ip address 10.0.0.254 255.255.255.0\n#\ninterface GigabitEthernet0/0/2\n ip address 192.0.2.254 255.255.255.0\n#\nfirewall zone name inside\n add interface GigabitEthernet0/0/1\n#\nfirewall zone name outside\n add interface GigabitEthernet0/0/2\n#\nip route-static 0.0.0.0 0 GigabitEthernet0/0/2 192.0.2.253\n",
      palo_alto: "set network interface ethernet ethernet1/1 layer3 ip 10.0.0.254/24\nset network interface ethernet ethernet1/2 layer3 ip 192.0.2.254/24\nset network virtual-router default interface [ ethernet1/1 ethernet1/2 ]\nset zone inside network layer3 ethernet1/1\nset zone outside network layer3 ethernet1/2\n"
    }
    originals.each do |vendor, text|
      parsed = Algosec::Config::Parser.perform(text, vendor: vendor, device_id: 1)
      baseline = P::Snapshot.from_config(parsed, revision: "a" * 64, software_version: vendor == :huawei ? "V500R005" : nil)
      data = group(vendor)
      actions = P::Result::DIMENSIONS.to_h { |dimension| [ dimension, data.fetch(dimension).transform_values { nil } ] }
      actions[:nat_sources] = { "10.0.0.1/32" => { real_ip: "10.0.0.1/32", nat: { type: :dynamic, address: "198.51.100.1" } } }
      result = P::Result.new(**data, snapshot: baseline, type: :new, actions: { new: actions })
      plan = P::Planner.new(P::Report.new(results: [ result ])).plans.sole
      assert plan.executable?, plan.to_h.inspect
      document = P::PlanDocument.dump(plan)
      restored = P::PlanDocument.load(JSON.parse(JSON.generate(document)), target: baseline)
      assert restored.executable?, restored.to_h.inspect
      assert_equal document, P::PlanDocument.dump(restored)
      assert_same restored.change_set, restored.effect_proofs.fetch(:nat).change_set
      assert_equal "proposed_graph", document.fetch("effects").fetch("nat").fetch("candidate").fetch("kind")
    end
  end

  test "Fortinet default parser context is encoded without changing policy settings" do
    baseline = P::Snapshot.from_config(Algosec::Config::Parser.perform("config system zone\n edit inside\n next\n edit outside\n next\nend\n", vendor: :fortinet, device_id: 1), revision: "b" * 64)
    change = P::ChangeSet.new(snapshot: baseline, intents: [], targets: [])
    plan = P::Plan.new(operation: :converge, snapshot: baseline, changes: [], change_set: change, commands: "approved")
    restored = P::PlanDocument.load(P::PlanDocument.dump(plan), target: baseline)
    assert restored.executable?
    assert_equal({}, restored.target_baseline.fetch(:settings))
  end

  test "approvals using previous behavior semantics require replanning" do
    graph = snapshot(:palo_alto)
    baseline = P::Snapshot.new(device_id: 1, vendor: :palo_alto, catalog: graph.catalog, revision: "a" * 64)
    change = P::ChangeSet.new(snapshot: baseline, intents: [], targets: [])
    plan = P::Plan.new(operation: :configure, snapshot: baseline, changes: [], change_set: change)
    %w[firewall-domain-v2 firewall-domain-v3 firewall-domain-v4 firewall-domain-v5].each do |version|
      document = P::PlanDocument.dump(plan).merge("semantic_version" => version)
      assert_raises(ArgumentError) { P::PlanDocument.load(document, target: baseline) }
    end
  end

  test "approved inputs reconstruct typed declarations and rerun proof without trusting receipts" do
    graph = snapshot(:palo_alto)
    baseline = P::Snapshot.new(device_id: 1, vendor: :palo_alto, catalog: graph.catalog, revision: "a" * 64)
    change = P::ChangeSet.new(snapshot: baseline, intents: [], targets: [], at: Time.at(Rational(1_900_000_000_000_001, 1_000_000)))
    plan = P::Plan.new(operation: :converge, snapshot: baseline, changes: [], change_set: change, commands: "approved script")
    assert defined?(P::PlanDocument), "missing typed approved plan codec"
    document = P::PlanDocument.dump(plan)
    restored = P::PlanDocument.load(JSON.parse(JSON.generate(document)), target: baseline, source: baseline)
    assert restored.executable?
    assert_equal plan.script, restored.script
    assert_equal change.at.to_r, restored.change_set.at.to_r
    assert_equal document, P::PlanDocument.dump(restored)
    assert_raises(ArgumentError) { P::PlanDocument.load(document.merge("verified" => true), target: baseline, source: baseline) }
  end
end
