# frozen_string_literal: true

require "test_helper"
require_relative "../framework/support/policy_factory"
require_relative "../framework/support/policy_config"

class ExactPlannerTest < ActiveSupport::TestCase
  include PolicyFactory
  include PolicyConfig

  test "generated text alone does not make a plan executable" do
    plan = P::Plan.new(operation: :configure, snapshot: snapshot(:palo_alto), changes: [], commands: "commands\n")
    refute plan.ready?
    assert plan.generated?
    refute plan.verified?
    assert_raises(P::Error) { plan.script }
  end

  test "partial coverage generates exact gap and parses to the same request subset" do
    original = rule(:palo_alto, source: "10.0.0.0/25", rule_number: 1)
    current = snapshot(:palo_alto, [ original ])
    result = P::RuleMatcher.new(current).match(group(:palo_alto, sources: [ "10.0.0.0/24" ]))
    planner = P::Planner.new(P::Report.new(results: [ result ]))
    generated = planner.perform.sole[:policy_contents].sole[:new][:content]
    assert_includes generated, "10.0.0.128/25"
    refute_includes generated, "10.0.0.0/24"
    parsed = Algosec::Config::Parser.perform(saved_config(:palo_alto, generated), vendor: :palo_alto, device_id: 1)
    assert parsed.complete?, parsed.diagnostics.inspect
    assert_equal Algosec::IPAddr.parse("10.0.0.128/25"), parsed.catalog.select { |entry| entry.is_a?(E::SecurityRule) }.sole.sources.resolved_set
  end

  test "new native PAN plan has both generation and semantic proof" do
    current = snapshot(:palo_alto)
    result = P::RuleMatcher.new(current).match(group(:palo_alto))
    plan = P::Planner.new(P::Report.new(results: [ result ])).plans.sole
    assert plan.generated?
    assert plan.verified?, plan.issues.map(&:message).join("; ")
    assert plan.ready?
    assert_equal Algosec::SEMANTIC_VERSION, plan.target_baseline[:semantic_version]
    assert plan.change_set
  end

  test "ICMP coverage planning and readback share unrestricted type semantics" do
    entry = rule(:palo_alto, services: [ "icmp/1 65535" ])
    current = snapshot(:palo_alto, [ entry ])
    report = P::Searcher.new(networks: networks(:palo_alto), snapshots: { 1 => current })
      .perform(sources: [ "10.0.0.1" ], destinations: [ "192.0.2.1" ], services: [ "icmp" ])

    assert report.success?, report.comment
    assert_equal :ignore, report.results.sole.type
    plan = P::Planner.new(report).plans.sole
    assert plan.verified?, plan.issues.map(&:message).join("; ")
    assert_empty plan.script
    equivalent = snapshot(:palo_alto, [ rule(:palo_alto, services: [ "icmp/65535-1" ]) ])
    assert plan.verify_readback(equivalent).verified?
    restricted = snapshot(:palo_alto, [ rule(:palo_alto, services: [ "icmp/8" ]) ])
    refute plan.verify_readback(restricted).verified?
  end

  test "old semantic baselines cannot validate" do
    context = { device_id: 1, vendor: :palo_alto, revision: "r1", software_version: nil, settings: {} }
    error = assert_raises(P::Error) { P::Plan.validate_context!(context, context) }
    assert_equal :semantic_version_mismatch, error.code
  end
end

class ExactPlannerTest
  test "crossed source destination pairs keep the two uncovered rectangles separate" do
    originals = [ rule(:palo_alto, name: "a", source: "10.0.0.1", destination: "192.0.2.1", rule_number: 1),
      rule(:palo_alto, name: "b", source: "10.0.0.2", destination: "192.0.2.2", rule_number: 2) ]
    current = snapshot(:palo_alto, originals)
    result = P::RuleMatcher.new(current).match(group(:palo_alto, sources: [ "10.0.0.1", "10.0.0.2" ], destinations: [ "192.0.2.1", "192.0.2.2" ]))
    slices = result.generation_results
    generated = slices.reduce(P::TrafficSet.new) { |all, item| all | item.traffic_set }
    requested = result.traffic_set
    covered = P::Evaluation.new(current).perform(requested, from_zone: "inside", to_zone: "outside").partitions.select { |part| part.action == "allow" }.reduce(P::TrafficSet.new) { |set, part| set | part.traffic_set }
    assert (generated & covered).empty?
    assert requested.cover?(generated)
    assert (requested - covered).cover?(generated)
    assert generated.cover?(requested - covered)
  end

  test "PAN explicit before command is represented in native intents and proof" do
    parsed = Algosec::Config::Parser.perform(<<~CONFIG, vendor: :palo_alto, device_id: 1)
      set rulebase security rules deny from inside
      set rulebase security rules deny to outside
      set rulebase security rules deny source any
      set rulebase security rules deny destination any
      set rulebase security rules deny service any
      set rulebase security rules deny application any
      set rulebase security rules deny action deny
    CONFIG
    current = P::Snapshot.from_config(parsed)
    result = P::RuleMatcher.new(current).match(group(:palo_alto))
    plan = P::Planner.new(P::Report.new(results: [ result ])).plans.sole
    assert plan.ready?, plan.issues.map(&:message).join("; ")
    assert_equal [ :create, :move ], plan.change_set.intents.map(&:operation)
    assert_includes plan.script, ' before "deny"'
  end
end

class ExactPlannerTest
  test "native network creation preserves explicit egress or blocks an ingress-only target" do
    VENDORS.each do |vendor|
      settings = vendor == :h3c ? { policy_bindings: [ { name: "objects", from_zone: "inside", to_zone: "outside" } ] } : {}
      current = snapshot(vendor, settings: settings)
      if vendor == :asa
        zones = %w[inside outside].map do |name|
          interface = E::Interface.new(name: name, zone: name, **context(vendor))
          E::Zone.new(name: name, acl_name: "#{name}_acl", interfaces: [ interface ], **context(vendor))
        end
        current = current.with_catalog(E::Catalog.new(zones).seal!)
      end
      result = P::RuleMatcher.new(current).match(group(vendor))
      plan = P::Planner.new(P::Report.new(results: [ result ])).plans.sole
      if vendor == :asa
        refute plan.ready?
        assert plan.proof.differences.any? { |difference| difference.kind == :outside_target && difference.context[:to_zone] != "outside" }
        next
      end
      assert plan.ready?, "#{vendor}: #{plan.issues.map(&:message).join('; ')}"
      assert plan.proof.verified?, vendor.to_s
      assert JSON.parse(JSON.generate(plan.to_h)).fetch("executable"), vendor.to_s
    end
  end

  test "ASA shared inbound ACL is blocked even when target traffic would be permitted" do
    current = snapshot(:asa)
    result = P::RuleMatcher.new(current).match(group(:asa))
    plan = P::Planner.new(P::Report.new(results: [ result ])).plans.sole
    assert plan.generated?
    refute plan.ready?
    assert plan.proof.differences.any? { |difference| difference.kind == :outside_target }
  end

  test "NAT effect is an explicit typed proof requirement" do
    current = snapshot(:palo_alto)
    change = P::ChangeSet.new(snapshot: current, intents: [], targets: [])
    plan = P::Plan.new(operation: :configure, snapshot: current, changes: [], change_set: change, required_effects: [ :nat ])
    assert plan.proof.verified?
    refute plan.verified?
    assert_equal :nat, plan.issues.sole.evidence[:effect]
    assert_raises(ArgumentError) do
      P::Plan.new(operation: :configure, snapshot: current, changes: [], change_set: change, required_effects: [ :nat ], effect_proofs: { nat: { verified: true } })
    end
  end
end

class ExactPlannerTest
  test "all native candidates can be independently read back without assuming a default action" do
    (VENDORS - [ :asa ]).each do |vendor|
      settings = vendor == :h3c ? { policy_bindings: [ { name: "objects", from_zone: "inside", to_zone: "outside" } ] } : {}
      current = snapshot(vendor, settings: settings)
      result = P::RuleMatcher.new(current).match(group(vendor))
      plan = P::Planner.new(P::Report.new(results: [ result ])).plans.sole
      candidate = plan.proof.candidate
      objects = candidate.catalog.map { |object| object.is_a?(E::SecurityRule) ? object.with.seal! : object }
      readback = candidate.with_catalog(E::Catalog.new(objects).seal!)
      assert plan.verify_readback(readback).verified?, vendor.to_s
    end
  end
end

class ExactPlannerTest
  test "all ten generated policies parse and evaluate the exact requested traffic" do
    VENDORS.each do |vendor|
      settings = vendor == :h3c ? { policy_bindings: [ { name: "objects", from_zone: "inside", to_zone: "outside" } ] } : {}
      current = snapshot(vendor, settings: settings)
      result = P::RuleMatcher.new(current).match(group(vendor, sources: [ "10.0.0.1", "10.0.0.2" ], services: [ "tcp/443", "udp/53" ]))
      script = current.definition.build_generator(result).render
      parsed = Algosec::Config::Parser.perform(saved_config(vendor, script.text), vendor: vendor, device_id: 1)
      assert parsed.complete?, "#{vendor}: #{parsed.diagnostics.inspect}"
      # 命令往返只解析新增声明，保留设备原有的区域/绑定上下文。
      candidate = current.with_catalog(E::Catalog.new(current.catalog.to_a + parsed.catalog.to_a).seal!)
      evaluation = P::Evaluation.new(candidate).perform(result.traffic_set, from_zone: "inside", to_zone: "outside")
      assert evaluation.complete?, "#{vendor}: #{evaluation.partitions.map(&:reason).inspect}"
      assert evaluation.partitions.all? { |partition| partition.action == "allow" }, vendor.to_s
    end
  end
end

class ExactPlannerTest
  test "PAN IPv4 any generation does not silently permit the IPv6 universe" do
    current = snapshot(:palo_alto)
    result = P::RuleMatcher.new(current).match(group(:palo_alto, sources: [ "any" ], destinations: [ "any" ], services: [ "any" ]))
    script = current.definition.build_generator(result).render
    parsed = Algosec::Config::Parser.perform(saved_config(:palo_alto, script.text), vendor: :palo_alto, device_id: 1)
    readback = P::Snapshot.from_config(parsed)
    packet = P::Packet.new(source: "::1", destination: "::2", protocol: 6, source_port: 1, destination_port: 443)
    evaluation = P::Evaluation.new(readback).perform(packet, from_zone: "inside", to_zone: "outside")
    assert_equal "deny", evaluation.partitions.sole.action
  end
end

class ExactPlannerTest
  test "PAN ordinary creation precedes terminal defaults without a CLI move to them" do
    baseline = "set rulebase default-security-rules rules interzone-default action deny\n"
    parsed = Algosec::Config::Parser.perform(baseline, vendor: :palo_alto, device_id: 1)
    assert parsed.complete?, parsed.diagnostics.inspect
    current = P::Snapshot.from_config(parsed)
    result = P::RuleMatcher.new(current).match(group(:palo_alto))
    planner = P::Planner.new(P::Report.new(results: [ result ]))
    plan = planner.plans.sole
    assert plan.ready?, plan.issues.map(&:message).join("; ")
    refute_match(/move .*interzone-default/, plan.script)
    assert_equal [ "allow", "deny" ], plan.proof.candidate.rules.sort_by(&:rule_number).map(&:action)
    reparsed = Algosec::Config::Parser.perform(baseline + saved_config(:palo_alto, plan.script), vendor: :palo_alto, device_id: 1)
    assert reparsed.complete?, reparsed.diagnostics.inspect
    assert plan.verify_readback(P::Snapshot.from_config(reparsed)).verified?
  end
end
