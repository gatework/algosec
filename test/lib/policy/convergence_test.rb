# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "../framework/support/policy_factory"

class ConvergenceTest < Minitest::Test
  include PolicyFactory

  def converge(snap, selected = snap.rules, **options)
    P::Convergence.new(snap, **options).perform(rule_ids: selected.map(&:rule_id))
  end

  def test_adjacent_halves_merge_and_delete_in_one_native_batch
    rows = [ rule(:palo_alto, name: "first", rule_number: 1, source: "10.0.0.0/25", log_enabled: true),
             rule(:palo_alto, name: "second", rule_number: 2, source: "10.0.0.128/25", log_enabled: true) ]
    snap = snapshot(:palo_alto, rows)
    plan = converge(snap, rows.reverse)
    assert plan.ready?, plan.issues.map(&:message).join("; ")
    assert_equal :converge, plan.operation
    assert_empty plan.change_set.targets
    assert_equal %i[modify delete], plan.change_set.intents.map(&:operation)
    assert_equal [ "first" ], plan.change_set.apply.rules.map(&:name)
    assert_equal Algosec::IPAddr.parse("10.0.0.0/24"), plan.change_set.apply.rules.first.sources.resolved_set
    assert_equal true, plan.change_set.apply.rules.first.log_enabled
    assert_equal 1, plan.script.lines.count { |line| line == "configure\n" }
    assert_equal 1, plan.script.lines.count { |line| line == "commit\n" }
    assert_operator plan.script.index('set rulebase security rules "first" source'), :<,
                    plan.script.index('delete rulebase security rules "second"')
    assert_equal rows, snap.rules
    assert_equal Algosec::IPAddr.parse("10.0.0.0/25"), rows.first.sources.resolved_set
    assert rows.all?(&:sealed?)
    assert plan.verify_readback(plan.change_set.apply).verified?
  end

  def test_diagonal_addresses_and_service_pairs_never_become_cartesian_allow
    cases = [ { destination: "192.0.2.2" }, { services: [ "tcp/80" ] } ]
    cases.each do |attributes|
      first = rule(:palo_alto, name: "first", source: "10.0.0.1", rule_number: 1)
      second = rule(:palo_alto, name: "second", source: "10.0.0.2", rule_number: 2, **attributes)
      plan = converge(snapshot(:palo_alto, [ first, second ]))
      refute plan.ready?
      assert_includes plan.issues.map { |issue| issue.evidence[:code] }, :non_rectangular_union
      assert_raises(P::Error) { plan.script }
    end
  end

  def test_intervening_deny_blocks_earlier_merge_and_the_whole_batch
    first = rule(:palo_alto, name: "first", rule_number: 1, source: "10.0.0.0/25")
    deny = rule(:palo_alto, name: "deny", rule_number: 2, source: "10.0.0.128/25", action: "deny")
    last = rule(:palo_alto, name: "last", rule_number: 3, source: "10.0.0.128/25")
    snap = snapshot(:palo_alto, [ first, deny, last ])
    plan = converge(snap, [ first, last ])
    refute plan.ready?
    assert plan.proof.differences.any?
    assert_raises(P::Error) { plan.script }
  end

  def test_complete_four_corner_union_is_evaluated_as_one_batch
    rows = [ [ "10.0.0.1", "192.0.2.1" ], [ "10.0.0.2", "192.0.2.2" ],
             [ "10.0.0.1", "192.0.2.2" ], [ "10.0.0.2", "192.0.2.1" ] ].each_with_index.map do |(source, destination), index|
      rule(:palo_alto, name: index.to_s, rule_number: index + 1, source: source, destination: destination)
    end
    snap = snapshot(:palo_alto, rows)
    refute converge(snap, rows.first(2)).ready?
    plan = converge(snap)
    assert plan.ready?, plan.issues.map(&:message).join("; ")
    assert_equal %i[modify delete delete delete], plan.change_set.intents.map(&:operation)
    assert_equal 1, plan.change_set.apply.rules.size
  end

  def test_service_union_retains_protocol_and_port_holes
    rows = [ rule(:palo_alto, name: "first", rule_number: 1, services: [ "tcp/443" ]),
             rule(:palo_alto, name: "last", rule_number: 2, services: [ "udp/53", "tcp/8443" ]) ]
    plan = converge(snapshot(:palo_alto, rows))
    assert plan.ready?, plan.issues.map(&:message).join("; ")
    candidate = plan.change_set.apply
    [ [ 6, 443, true ], [ 17, 53, true ], [ 6, 8443, true ], [ 6, 53, false ], [ 17, 443, false ], [ 6, 444, false ] ].each do |protocol, port, expected|
      packet = P::Packet.new(source: "10.0.0.1", destination: "192.0.2.1", protocol: protocol, source_port: 12000, destination_port: port)
      evaluated = P::Evaluation.new(candidate).perform(packet, from_zone: "inside", to_zone: "outside")
      assert_equal expected, evaluated.partitions.any? { |part| part.action == "allow" }, "#{protocol}/#{port}"
    end
  end

  def test_metadata_mismatches_are_not_silently_erased
    options = [ { action: "drop" }, { action: "reset-both" }, { log_enabled: true }, { log_enabled: false },
                { log: "session-close" }, { applications: [ "ssl" ] }, { source_users: [ "alice" ] },
                { conditions: { security_profiles: { antivirus: "strict" } } },
                { conditions: { expires_at: "2030-01-01T01:00:00Z" } } ]
    options.each do |attributes|
      first = rule(:palo_alto, name: "first", rule_number: 1)
      second = rule(:palo_alto, name: "second", rule_number: 2, **attributes)
      plan = converge(snapshot(:palo_alto, [ first, second ]))
      refute plan.ready?, attributes.inspect
      assert_includes plan.issues.map { |issue| issue.evidence[:code] }, :incompatible_metadata
    end
  end

  def test_rule_chain_and_scope_must_match_before_selection_can_merge
    first = rule(:palo_alto, name: "first", rule_number: 1, rule_set: "vsys1/rulebase")
    second = rule(:palo_alto, name: "second", rule_number: 2, rule_set: "vsys2/rulebase")
    plan = converge(snapshot(:palo_alto, [ first, second ]))
    refute plan.ready?
    assert_includes plan.issues.map { |issue| issue.evidence[:code] }, :incompatible_scope
    same_chain = second.with(rule_set: "vsys1/rulebase", scope: E::Scope.new(device_id: 1, virtual_system: "vsys2"))
    refute converge(snapshot(:palo_alto, [ first, same_chain ])).ready?
  end

  def test_explicit_selection_requires_two_distinct_existing_rules
    row = rule(:palo_alto, name: "first", rule_number: 1)
    service = P::Convergence.new(snapshot(:palo_alto, [ row ]))
    [ [], [ row.rule_id ], [ row.rule_id, row.rule_id ], [ row.rule_id, "missing" ] ].each do |ids|
      assert_raises(ArgumentError) { service.perform(rule_ids: ids) }
    end
  end

  def test_redundancy_reduction_uses_each_declared_native_removal
    expected = { fortinet: "delete 2", srx: "delete security policies from-zone inside to-zone outside policy 2",
                 netscreen: "unset policy id 2", hillstone: "no rule id 2", h3c: "undo rule 2",
                 palo_alto: 'delete rulebase security rules "2"' }
    expected.each do |vendor, removal|
      rows = (1..3).map { |index| rule(vendor, name: index.to_s, rule_number: index) }
      shared = rows.first.sources.unique_leaves.first
      snap = snapshot(vendor, [ shared, *rows ])
      plan = converge(snap)
      assert plan.ready?, "#{vendor}: #{plan.issues.map(&:message).join('; ')}"
      assert_equal %i[delete delete], plan.change_set.intents.map(&:operation)
      assert_includes plan.script, removal
      assert_equal [ rows.first ], plan.change_set.apply.rules
      assert_includes plan.change_set.apply.addresses, shared
    end
  end

  def test_each_removal_capable_vendor_can_generate_a_useful_member_merge
    %i[fortinet srx netscreen hillstone h3c palo_alto].each do |vendor|
      rows = [ rule(vendor, name: "1", rule_number: 1, source: "10.0.0.0/25", config: 'set srcaddr "sources"'),
               rule(vendor, name: "2", rule_number: 2, source: "10.0.0.128/25") ]
      plan = converge(snapshot(vendor, rows))
      assert plan.ready?, "#{vendor}: #{plan.issues.map(&:message).join('; ')}"
      assert_equal %i[modify delete], plan.change_set.intents.map(&:operation)
      assert_equal Algosec::IPAddr.parse("10.0.0.0/24"), plan.change_set.apply.rules.first.sources.resolved_set
    end
  end

  def test_canonical_reset_action_and_false_logging_survive_a_merge
    rows = [ rule(:palo_alto, name: "first", rule_number: 1, source: "10.0.0.0/25", action: "reset-both", log_enabled: false),
             rule(:palo_alto, name: "last", rule_number: 2, source: "10.0.0.128/25", action: "reset-both", log_enabled: false) ]
    plan = converge(snapshot(:palo_alto, rows))
    assert plan.ready?, plan.issues.map(&:message).join("; ")
    merged = plan.change_set.apply.rules.first
    assert_equal "reset-both", merged.action
    assert_equal false, merged.log_enabled
    refute_includes plan.script, " action "
  end

  def test_small_proof_budget_fails_closed
    rows = (1..2).map { |index| rule(:palo_alto, name: index.to_s, rule_number: index) }
    plan = converge(snapshot(:palo_alto, rows), rows, proof_limit: 1)
    refute plan.ready?
    assert_includes plan.issues.map { |issue| issue.evidence[:code] }, :proof_budget_exceeded
  end

  def test_identical_unknown_profiles_and_applications_do_not_establish_safe_union
    [ { applications: [ "ssl" ] }, { conditions: { security_profiles: { antivirus: "strict" } } } ].each do |attributes|
      rows = (1..2).map { |index| rule(:palo_alto, name: index.to_s, rule_number: index, **attributes) }
      plan = converge(snapshot(:palo_alto, rows))
      refute plan.ready?
      assert_includes plan.issues.map { |issue| issue.evidence[:code] }, :unsupported_conditions
    end
  end

  def test_nat_relationship_is_proved_unchanged_and_independent_readback_rejects_drift
    rows = (1..2).map { |index| rule(:palo_alto, name: index.to_s, rule_number: index) }
    nat = E::DynamicNat.new(**context(:palo_alto), name: "snat", direction: :source, nat_type: "static-ip",
      from_zone: "inside", to_zone: "outside", source_set: "10.0.0.1", destination_set: "192.0.2.1",
      translated_source_set: "203.0.113.1", nat_order: [ 1 ])
    snap = snapshot(:palo_alto, [ *rows, nat ])
    plan = converge(snap)
    assert plan.ready?, plan.issues.map(&:message).join("; ")
    assert plan.effect_proofs.fetch(:nat).verified?
    assert_same nat, plan.change_set.apply.nat_rules.first
    assert plan.verify_readback(plan.change_set.apply).verified?
    without_nat = snapshot(:palo_alto, [ rows.first ])
    refute plan.verify_readback(without_nat).verified?
  end

  def test_nat_bound_to_a_removed_rule_blocks_even_equivalent_security_deletion
    rows = (1..2).map { |index| rule(:fortinet, name: index.to_s, rule_number: index) }
    nat = E::DynamicNat.new(**context(:fortinet), name: "snat", direction: :source, policy_id: "2",
      match_rule: rows.last, nat_type: "overload", source_set: "10.0.0.0/24", translated_source_set: "203.0.113.1")
    plan = converge(snapshot(:fortinet, [ *rows, nat ]))
    refute plan.ready?
    assert plan.proof.verified?
    refute plan.effect_proofs.fetch(:nat).verified?
    assert_includes plan.issues.map { |issue| issue.evidence[:code] }, :nat_dependency_changed
  end

  def test_unsupported_removal_blocks_entire_batch_without_publishing_commands
    rows = (1..2).map { |index| rule(:neteye, name: index.to_s, rule_number: index) }
    plan = converge(snapshot(:neteye, rows))
    refute plan.ready?
    refute plan.generated?
    assert_includes plan.issues.map { |issue| issue.evidence[:code] }, :unsupported_operation
    assert_raises(P::Error) { plan.script }
  end

  def test_source_ports_are_preserved_or_explicitly_blocked
    rows = [ "1024-2047", "2048-4095" ].each_with_index.map do |ports, index|
      row = rule(:palo_alto, name: index.to_s, rule_number: index + 1)
      services = E::ServiceGroup.new(**context(:palo_alto), name: "ports")
      services.add("tcp", E::ServiceObject.new(**context(:palo_alto), name: "tcp", protocol: "tcp", source_port: ports, destination_port: "443"))
      row.with(services: services)
    end
    plan = converge(snapshot(:palo_alto, rows))
    refute plan.ready?
    assert_includes plan.issues.map { |issue| issue.evidence[:code] }, :unsupported_gap
    assert_equal [ "1024-2047", "2048-4095" ], rows.map { |row| row.services.unique_leaves.first.terms.first[:source_port] }
  end

  def test_numeric_protocol_zero_never_becomes_any
    rows = (1..2).map { |index| rule(:palo_alto, name: index.to_s, rule_number: index, services: [ "0" ]) }
    plan = converge(snapshot(:palo_alto, rows))
    refute plan.ready?
    assert_includes plan.issues.map { |issue| issue.evidence[:code] }, :unsupported_conditions
  end

  def test_matching_once_windows_are_preserved_and_proved_across_the_future
    at = Time.utc(2030, 1, 1)
    schedule = E::Schedule.new(**context(:palo_alto), name: "window", start_at: at + 60, end_at: at + 120, time_zone: "UTC")
    rows = [ rule(:palo_alto, name: "first", rule_number: 1, source: "10.0.0.0/25", schedule: schedule),
             rule(:palo_alto, name: "last", rule_number: 2, source: "10.0.0.128/25", schedule: schedule) ]
    plan = converge(snapshot(:palo_alto, rows), rows, at: at)
    assert plan.ready?, plan.issues.map(&:message).join("; ")
    assert_equal [ :time ], plan.required_effects
    assert plan.effect_proofs.fetch(:time).verified?
    assert_same schedule, plan.change_set.apply.rules.first.schedule
    assert_operator plan.effect_proofs.fetch(:time).checks.size, :>, 1
  end

  def test_future_intervening_deny_is_not_hidden_by_current_inactivity
    at = Time.utc(2030, 1, 1)
    schedule = E::Schedule.new(**context(:palo_alto), name: "deny-window", start_at: at + 60, end_at: at + 120, time_zone: "UTC")
    first = rule(:palo_alto, name: "first", rule_number: 1, source: "10.0.0.0/25")
    deny = rule(:palo_alto, name: "deny", rule_number: 2, source: "10.0.0.128/25", action: "deny", schedule: schedule)
    last = rule(:palo_alto, name: "last", rule_number: 3, source: "10.0.0.128/25")
    plan = converge(snapshot(:palo_alto, [ first, deny, last ]), [ first, last ], at: at)
    assert plan.proof.verified?
    refute plan.ready?
    refute plan.effect_proofs.fetch(:time).verified?
  end

  def test_embedded_nat_dependency_cannot_be_removed_with_the_security_rule
    first = rule(:fortinet, name: "1", rule_number: 1, nat: true)
    last = rule(:fortinet, name: "2", rule_number: 2, nat: true)
    plan = converge(snapshot(:fortinet, [ first, last ]))
    refute plan.ready?
    assert_includes plan.issues.map { |issue| issue.evidence[:code] }, :nat_dependency
  end

  def test_native_pan_readback_confirms_both_merge_and_removal
    objects = "set address lower ip-netmask 10.0.0.0/25\nset address upper ip-netmask 10.0.0.128/25\nset service https protocol tcp port 443\n"
    before_text = objects + pan_rule("first", "lower") + pan_rule("second", "upper")
    snap = parsed_pan(before_text)
    plan = converge(snap)
    assert plan.ready?, plan.issues.map(&:message).join("; ")
    assert_includes plan.script, 'set address "addr_10.0.0.128/25" ip-netmask 10.0.0.128/25'
    assert_includes plan.script, 'set rulebase security rules "first" source [ "addr_10.0.0.128/25" ]'
    after_text = objects + "set address addr_10.0.0.128/25 ip-netmask 10.0.0.128/25\n" + pan_rule("first", "[ lower addr_10.0.0.128/25 ]")
    assert plan.verify_readback(parsed_pan(after_text)).verified?
    refute plan.verify_readback(parsed_pan(before_text)).verified?
    retained = plan.verify_readback(parsed_pan(after_text + pan_rule("second", "upper")))
    refute retained.verified?
    assert_includes retained.issues.map { |issue| issue.evidence[:code] }, :unfulfilled_deletion
  end

  def test_combined_generator_validates_delete_targets_and_does_not_commit_partial_state
    first = rule(:palo_alto, name: "first", rule_number: 1)
    second = rule(:palo_alto, name: "second", rule_number: 2)
    snap = snapshot(:palo_alto, [ first, second ])
    state = {}
    generator = snap.definition.generator.new(snapshot: snap, state: state)
    assert_raises(ArgumentError) { generator.render([], remove_rules: [ second.with ]) }
    assert_empty state
    assert_empty generator.commands
    script = generator.render([], remove_rules: [ second ])
    entry = script.entries.fetch(0)
    assert_equal :remove_rule, entry.operation
    assert_same second, entry.rule
    assert_equal :delete, entry.intents.fetch(0).operation
    assert_equal second.rule_id, entry.intents.fetch(0).rule_id
  end

  def test_late_native_removal_failure_rolls_back_prior_modification_commands
    first = rule(:palo_alto, name: "first", rule_number: 1)
    second = rule(:palo_alto, name: "default", rule_number: 2, vendor_data: { "panos" => '{"family":"default-security-rules"}' })
    snap = snapshot(:palo_alto, [ first, second ])
    data = group(:palo_alto, sources: [ "10.0.1.1" ])
    result = P::Result.new(**data, snapshot: snap, type: :modify, rule: first,
      actions: { add: { sources: { "10.0.1.1/32" => nil } } })
    state = {}
    generator = snap.definition.generator.new(snapshot: snap, state: state)
    assert_raises(P::Error) { generator.render([ result ], remove_rules: [ second ]) }
    assert_empty generator.commands
    assert_empty state
  end

  private

  def pan_rule(name, source)
    { from: "inside", to: "outside", source: source, destination: "192.0.2.1", service: "https", application: "any", action: "allow" }
      .map { |field, value| "set rulebase security rules #{name} #{field} #{value}\n" }.join
  end

  def parsed_pan(text)
    result = Algosec::Config::Parser.perform(text, vendor: :palo_alto, device_id: 1)
    assert result.complete?, result.diagnostics.inspect
    P::Snapshot.from_config(result)
  end
end
