# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "../framework/support/policy_factory"

class ReclaimerProofTest < Minitest::Test
  include PolicyFactory

  def test_joint_first_match_coverage_and_whole_batch_proof
    rows = [ rule(:fortinet, name: "1", rule_number: 1, source: "10.0.0.0/25"),
             rule(:fortinet, name: "2", rule_number: 2, source: "10.0.0.128/25"),
             rule(:fortinet, name: "3", rule_number: 3) ]
    snap = snapshot(:fortinet, rows)
    service = P::Reclaimer.new(snap)
    covered = service.perform.violations.find { |finding| finding.check == :covered && finding.rule_id == snap.signature(rows.last) }
    refute_nil covered
    assert_equal :redundant, covered.evidence[:kind]
    assert_equal rows.first(2).map { |row| snap.signature(row) }, covered.evidence[:covering_rule_ids]
    plan = service.plan(rule_ids: [ snap.signature(rows.last) ])
    assert plan.ready?, plan.issues.map(&:message).join("; ")
    assert plan.verify_readback(plan.change_set.apply).verified?
    assert_equal rows.first(2), plan.change_set.apply.rules
  end

  def test_source_ports_are_not_erased_by_coverage
    first = rule(:fortinet, name: "1", rule_number: 1)
    services = E::ServiceGroup.new(**context(:fortinet), name: "services")
    services.add("restricted", E::ServiceObject.new(**context(:fortinet), name: "restricted", protocol: "tcp", source_port: "1024-2048", destination_port: "443"))
    first = first.with(services: services)
    later = rule(:fortinet, name: "2", rule_number: 2)
    snap = snapshot(:fortinet, [ first, later ])
    refute P::Reclaimer.new(snap).perform.violations.any? { |finding| finding.check == :covered }
    refute P::Reclaimer.new(snap).plan(rule_ids: [ snap.signature(later) ]).ready?
  end

  def test_exact_source_port_joint_coverage_can_be_reclaimed
    rows = [ "0-32767", "32768-65535", "0-65535" ].each_with_index.map do |ports, index|
      row = rule(:fortinet, name: (index + 1).to_s, rule_number: index + 1)
      group = E::ServiceGroup.new(**context(:fortinet), name: "services")
      group.add("tcp", E::ServiceObject.new(**context(:fortinet), name: "tcp", protocol: "tcp", source_port: ports, destination_port: "443"))
      row.with(services: group)
    end
    snap = snapshot(:fortinet, rows)
    plan = P::Reclaimer.new(snap).plan(rule_ids: [ snap.signature(rows.last) ])
    assert plan.ready?, plan.issues.map(&:message).join("; ")
  end

  def test_current_temporal_coverage_does_not_authorize_future_behavior_loss
    at = Time.utc(2030, 1, 1, 12)
    window = E::Schedule.new(**context(:fortinet), name: "brief", start_at: at - 60, end_at: at + 60)
    first = rule(:fortinet, name: "1", rule_number: 1, schedule: window)
    later = rule(:fortinet, name: "2", rule_number: 2)
    snap = snapshot(:fortinet, [ first, later ])
    plan = P::Reclaimer.new(snap, at: at).plan(rule_ids: [ snap.signature(later) ])
    refute plan.ready?
    assert_includes plan.required_effects, :time
    refute plan.effect_proofs.fetch(:time).verified?
  end

  def test_zero_usage_requires_complete_identity_and_window_but_is_not_deletion_authority
    at = Time.utc(2030, 1, 1, 12)
    row = rule(:fortinet, name: "1", rule_number: 1)
    snap = snapshot(:fortinet, [ row ])
    window = { window_start: at - 3600, window_end: at }
    evidence = P::UsageObservation.new(rule_identity: row.identity, **window, hits: 0, counter_reset: false, complete: true)
    service = P::Reclaimer.new(snap, at: at, usage_observations: [ evidence ], usage_window: window)
    finding = service.perform.violations.find { |item| item.check == :unused }
    refute_nil finding
    assert_nil finding.remediation
    refute service.plan(rule_ids: [ snap.signature(row) ]).ready?
    [ { complete: false }, { counter_reset: true }, { window_start: at - 60 },
      { rule_identity: row.with(name: "another", native_rule_id: "another").identity } ].each do |override|
      bad = P::UsageObservation.new(rule_identity: row.identity, **window, hits: 0, counter_reset: false, complete: true, **override)
      findings = P::Reclaimer.new(snap, at: at, usage_observations: [ bad ], usage_window: window).perform.violations
      refute findings.any? { |item| item.check == :unused }, override.inspect
    end
  end

  def test_canonical_action_distinguishes_reset_from_drop
    first = rule(:palo_alto, name: "first", rule_number: 1, action: "drop")
    later = rule(:palo_alto, name: "later", rule_number: 2, action: "reset-both")
    snap = snapshot(:palo_alto, [ first, later ])
    finding = P::Reclaimer.new(snap).perform.violations.find { |item| item.check == :covered }
    refute_nil finding
    assert_equal :shadowed, finding.evidence[:kind]
    assert P::Reclaimer.new(snap).plan(rule_ids: [ snap.signature(later) ]).ready?
  end

  def test_all_selected_deletions_use_one_proof_and_preserve_original_graph
    rows = (1..3).map { |index| rule(:fortinet, name: index.to_s, rule_number: index) }
    snap = snapshot(:fortinet, rows)
    plan = P::Reclaimer.new(snap).plan(rule_ids: rows.drop(1).map { |row| snap.signature(row) })
    assert plan.ready?, plan.issues.map(&:message).join("; ")
    assert_equal 2, plan.change_set.intents.size
    assert_equal [ rows.first ], plan.change_set.apply.rules
    assert_equal rows, snap.rules
    assert rows.all?(&:sealed?)
  end

  def test_native_palo_alto_reclaim_requires_actual_rule_absence_in_readback
    declaration = lambda do |name|
      fields = { from: "inside", to: "outside", source: "any", destination: "any", service: "any", application: "any", action: "allow" }
      fields.map { |field, value| "set rulebase security rules #{name} #{field} #{value}" }.join("\n") + "\n"
    end
    before_text = declaration.call("first") + declaration.call("redundant")
    before = Algosec::Config::Parser.perform(before_text, vendor: :palo_alto, device_id: 1)
    after = Algosec::Config::Parser.perform(declaration.call("first"), vendor: :palo_alto, device_id: 1)
    assert before.complete?, before.diagnostics.inspect
    assert after.complete?, after.diagnostics.inspect
    snap = P::Snapshot.from_config(before)
    selected = snap.rules.find { |row| row.name == "redundant" }
    plan = P::Reclaimer.new(snap).plan(rule_ids: [ snap.signature(selected) ])
    assert plan.ready?, plan.issues.map(&:message).join("; ")
    assert_includes plan.script, 'delete rulebase security rules "redundant"'
    assert plan.verify_readback(P::Snapshot.from_config(after)).verified?
    refute plan.verify_readback(P::Snapshot.from_config(Algosec::Config::Parser.perform(before_text, vendor: :palo_alto, device_id: 1))).verified?
  end

  def test_conflicting_observations_cannot_claim_unused
    at = Time.utc(2030, 1, 1, 12)
    row = rule(:fortinet, name: "1", rule_number: 1)
    snap = snapshot(:fortinet, [ row ])
    window = { window_start: at - 3600, window_end: at }
    observations = [ 0, 3 ].map do |hits|
      P::UsageObservation.new(rule_identity: row.identity, **window, hits: hits, counter_reset: false, complete: true)
    end
    assert_raises(ArgumentError) do
      P::Reclaimer.new(snap, at: at, usage_observations: observations, usage_window: window)
    end
  end

  def test_unknown_application_condition_cannot_establish_coverage
    first = rule(:fortinet, name: "1", rule_number: 1, applications: [ "ssl" ])
    later = rule(:fortinet, name: "2", rule_number: 2)
    snap = snapshot(:fortinet, [ first, later ])
    service = P::Reclaimer.new(snap)
    refute service.perform.violations.any? { |item| item.check == :covered }
    assert service.perform.unknowns.any? { |item| item.check == :covered }
    refute service.plan(rule_ids: [ snap.signature(later) ]).ready?
  end

  def test_usage_evidence_cannot_include_future_window
    at = Time.utc(2030, 1, 1, 12)
    assert_raises(ArgumentError) do
      P::Reclaimer.new(snapshot(:fortinet), at: at, usage_window: { window_start: at - 60, window_end: at + 60 })
    end
  end

  def test_hillstone_unrestricted_zones_share_the_control_context_contract
    rows = (1..2).map do |number|
      rule(:hillstone, name: number.to_s, rule_number: number, from_zones: nil, to_zones: nil)
    end
    snap = snapshot(:hillstone, rows)
    service = P::Reclaimer.new(snap)
    assert service.perform.violations.any? { |finding| finding.check == :covered && finding.rule_id == rows.last.rule_id }
    plan = service.plan(rule_ids: [ rows.last.rule_id ])
    assert plan.ready?, plan.issues.map(&:message).join("; ")
  end

  def test_native_hillstone_global_rules_need_no_zone_catalog_for_coverage
    declaration = lambda do |number|
      "rule id #{number}\n action permit\n src-ip 10.0.0.0/24\n dst-ip 192.0.2.1/32\n service-rule tcp dst-port 443\nexit\n"
    end
    before = Algosec::Config::Parser.perform(declaration.call(1) + declaration.call(2), vendor: :hillstone, device_id: 1)
    after = Algosec::Config::Parser.perform(declaration.call(1), vendor: :hillstone, device_id: 1)
    assert before.complete?, before.diagnostics.inspect
    assert after.complete?, after.diagnostics.inspect
    snap = P::Snapshot.from_config(before)
    assert_empty snap.elements(E::Zone)
    service = P::Reclaimer.new(snap)
    assert service.perform.violations.any? { |finding| finding.check == :covered && finding.rule_id == snap.rules.last.rule_id }
    plan = service.plan(rule_ids: [ snap.rules.last.rule_id ])
    assert plan.ready?, plan.issues.map(&:message).join("; ")
    assert plan.verify_readback(P::Snapshot.from_config(after)).verified?
    refute plan.verify_readback(snap).verified?
  end

  def test_real_zone_names_cannot_capture_the_unknown_zone_contexts
    declarations = <<~CONFIG
      rule id 1
       action permit
       src-zone __other_zone__
       src-zone __another_zone__
       dst-zone __other_zone__
       dst-zone __another_zone__
       src-ip 10.0.0.0/24
       dst-ip 192.0.2.1/32
       service-rule tcp dst-port 443
      exit
      rule id 2
       action permit
       src-ip 10.0.0.0/24
       dst-ip 192.0.2.1/32
       service-rule tcp dst-port 443
      exit
    CONFIG
    parsed = Algosec::Config::Parser.perform(declarations, vendor: :hillstone, device_id: 1)
    assert parsed.complete?, parsed.diagnostics.inspect
    snap = P::Snapshot.from_config(parsed)
    later = snap.rules.last
    service = P::Reclaimer.new(snap)
    refute service.perform.violations.any? { |finding| finding.check == :covered && finding.rule_id == later.rule_id }
    refute service.plan(rule_ids: [ later.rule_id ]).ready?
    change = P::ChangeSet.new(snapshot: snap, intents: [ P::ChangeSet::Intent.delete(rule_id: later.rule_id) ], targets: [])
    refute change.verify.verified?
  end

  def test_representative_contexts_are_distinct_from_real_names_ignoring_case
    names = %w[__OTHER_ZONE__ __ANOTHER_ZONE__ __ALGOSEC_UNKNOWN_ZONE_0__ __ALGOSEC_UNKNOWN_ZONE_1__]
    first = rule(:hillstone, name: "first", rule_number: 1, from_zones: names, to_zones: names)
    later = rule(:hillstone, name: "later", rule_number: 2, from_zones: [ "any" ], to_zones: [ "any" ])
    snap = snapshot(:hillstone, [ first, later ])
    contexts = P::ChangeSet::ProofContexts.new(snap, snap, targets: [], rules: [ later ], same_controls: true,
      budget: P::ChangeSet::ProofContexts::Budget.new(4096)).resolve
    real_names = (names + snap.elements(E::Zone).map(&:name)).map(&:downcase)
    representatives = contexts.flat_map { |entry| entry.values_at(:from_zone, :to_zone) }.uniq.reject { |name| real_names.include?(name.downcase) }
    assert_equal 2, representatives.size
    refute_equal representatives.first.downcase, representatives.last.downcase
  end
end
