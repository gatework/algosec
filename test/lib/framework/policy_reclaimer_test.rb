# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "support/policy_factory"

class PolicyReclaimerTest < Minitest::Test
  include PolicyFactory

  def covered_findings(snapshot)
    P::Reclaimer.new(snapshot).perform.violations.select { |finding| finding.check == :covered }
  end

  def test_coverage_uses_device_order_and_distinguishes_actions
    first = rule(:fortinet, name: "20", rule_number: 1, source: "10.0.0.0/8")
    duplicate = rule(:fortinet, name: "10", rule_number: 2, source: "10.0.0.0/8")
    narrower = rule(:fortinet, name: "2", rule_number: 3)
    denied = rule(:fortinet, name: "1", rule_number: 4, action: "deny")
    snap = snapshot(:fortinet, [ denied, narrower, duplicate, first ])
    findings = covered_findings(snap).to_h { |finding| [ finding.rule_id, finding ] }
    assert_equal :duplicate, findings.fetch(snap.signature(duplicate)).evidence[:kind]
    assert_equal :redundant, findings.fetch(snap.signature(narrower)).evidence[:kind]
    assert_equal :shadowed, findings.fetch(snap.signature(denied)).evidence[:kind]
    assert findings.values.all? { |finding| finding.evidence[:covering_rule_id] == snap.signature(first) }
    refute findings.key?(snap.signature(first))
  end

  def test_different_chains_and_cross_dimension_unions_are_not_covering
    left = rule(:fortinet, name: "1", rule_number: 1, source: "10.0.0.1/32", destination: "192.0.2.1/32")
    right = rule(:fortinet, name: "2", rule_number: 2, source: "10.0.0.2/32", destination: "192.0.2.2/32")
    other_chain = rule(:fortinet, name: "3", rule_number: 3, source: "0.0.0.0/0", destination: "0.0.0.0/0", from_zones: "dmz")
    combined = rule(:fortinet, name: "4", rule_number: 4, source: "10.0.0.0/24", destination: "192.0.2.0/24")
    assert_empty covered_findings(snapshot(:fortinet, [ left, right, other_chain, combined ]))
  end

  def test_duplicate_classification_preserves_all_three_logging_states
    [ true, false, nil ].repeated_permutation(2) do |earlier_logging, later_logging|
      earlier = rule(:fortinet, name: "1", rule_number: 1, log_enabled: earlier_logging)
      later = rule(:fortinet, name: "2", rule_number: 2, log_enabled: later_logging)
      snap = snapshot(:fortinet, [ earlier, later ])
      finding = covered_findings(snap).find { |item| item.rule_id == snap.signature(later) }

      expected = earlier_logging == later_logging ? :duplicate : :redundant
      assert_equal expected, finding.evidence[:kind], "logging: #{earlier_logging.inspect} -> #{later_logging.inspect}"
      assert_equal snap.signature(earlier), finding.evidence[:covering_rule_id]
      # 首条匹配已经证明后序规则不可达；日志差异影响重复分类，不推翻覆盖证据。
      assert P::Reclaimer.new(snap).plan(rule_ids: [ snap.signature(later) ]).ready?
    end
  end

  def test_matching_logging_switches_do_not_hide_different_logging_modes
    earlier = rule(:fortinet, name: "1", rule_number: 1, log_enabled: true, log: "session-init")
    later = rule(:fortinet, name: "2", rule_number: 2, log_enabled: true, log: "session-close")
    finding = covered_findings(snapshot(:fortinet, [ earlier, later ])).sole

    assert_equal :redundant, finding.evidence[:kind]
  end

  def test_disabled_and_expired_rules_do_not_cover_later_rules
    now = Time.utc(2026, 9, 16, 12)
    expired = E::Schedule.new(**context(:fortinet), name: "past", start_at: now - 7200, end_at: now - 3600)
    future = E::Schedule.new(**context(:fortinet), name: "future", start_at: now + 3600, end_at: now + 7200)
    weekly = E::Schedule.new(**context(:fortinet), name: "weekly", kind: :weekly, days: "mon", periods: [ [ "09:00", "18:00" ] ])
    rows = [ rule(:fortinet, name: "1", rule_number: 1, status: "disable"),
            rule(:fortinet, name: "2", rule_number: 2, schedule: expired),
            rule(:fortinet, name: "3", rule_number: 3, schedule: future),
            rule(:fortinet, name: "4", rule_number: 4, schedule: weekly),
            rule(:fortinet, name: "5", rule_number: 5) ]
    report = P::Reclaimer.new(snapshot(:fortinet, rows), at: now).perform
    assert_equal [ :disabled, :expired ], report.violations.map(&:check)
  end

  def test_missing_or_duplicate_order_is_unknown_and_does_not_authorize_removal
    [ [ nil, nil ], [ 1, 1 ] ].each do |positions|
      rows = positions.each_with_index.map { |rule_number, index| rule(:fortinet, name: (index + 1).to_s, rule_number: rule_number) }
      snap = snapshot(:fortinet, rows)
      service = P::Reclaimer.new(snap)
      assert service.perform.unknowns.any? { |finding| finding.evidence[:code] == :unknown_order }
      plan = service.plan(rule_ids: [ snap.signature(rows.last) ])
      refute plan.ready?
      assert_raises(P::Error) { plan.script }
    end
  end

  def test_registered_vendors_generate_scoped_removal_without_deleting_objects
    expected = {
      hillstone: "configure\nno rule id 12\nsave\n",
      fortinet: "config firewall policy\ndelete 12\nend\n",
      srx: "configure\ndelete security policies from-zone inside to-zone outside policy 12\ncommit check\ncommit\nexit\n",
      netscreen: "unset policy id 12\nsave\n",
      h3c: "sys\nobject-policy ip objects\nundo rule 12\nquit\nsave\n"
    }
    expected.each do |vendor, script|
      inactive = rule(vendor, name: "12", status: "disable")
      snap = snapshot(vendor, [ inactive ])
      plan = P::Reclaimer.new(snap).plan(rule_ids: [ snap.signature(inactive), snap.signature(inactive) ])
      assert plan.ready?, plan.issues.map(&:message).join("; ")
      assert_equal script, plan.script
      assert_equal 1, plan.changes.size
      assert_equal [ inactive ], snap.rules
    end
  end

  def test_fortinet_bulk_removal_wraps_vdom_once_and_empty_selection_is_empty
    rows = %w[2 12].map { |name| rule(:fortinet, name: name, status: "disable") }
    snap = snapshot(:fortinet, rows, settings: { vdom: "tenant" })
    service = P::Reclaimer.new(snap)
    script = service.plan(rule_ids: rows.map { |rule| snap.signature(rule) }).script
    assert script.start_with?("config vdom\nedit \"tenant\"\n")
    assert_equal 1, script.scan("config vdom").size
    assert script.end_with?("end\nend\n")
    assert_empty service.plan(rule_ids: []).script
  end

  def test_selection_is_revalidated_and_unsupported_vendor_is_explicit
    inactive = rule(:fortinet, name: "1", status: "disable", rule_number: 1)
    snap = snapshot(:fortinet, [ inactive ])
    service = P::Reclaimer.new(snap)
    assert service.perform.violations.any?
    inactive.status = "enable"
    refute service.plan(rule_ids: [ snap.signature(inactive) ]).ready?
    assert_raises(ArgumentError) { service.plan(rule_ids: [ "missing" ]) }
    other = rule(:neteye, status: "disable")
    unsupported = snapshot(:neteye, [ other ])
    plan = P::Reclaimer.new(unsupported).plan(rule_ids: [ unsupported.signature(other) ])
    assert_equal :unsupported_operation, plan.issues.first.evidence[:code]
    assert_raises(P::Error) { plan.script }
  end

  def test_nat_dependencies_block_the_entire_selected_batch
    first = rule(:fortinet, name: "1", status: "disable")
    second = rule(:fortinet, name: "2", status: "disable")
    nat = E::DynamicNat.new(**context(:fortinet), policy_id: "2", direction: :source, match_rule: second)
    snap = snapshot(:fortinet, [ first, second, nat ])
    plan = P::Reclaimer.new(snap).plan(rule_ids: [ snap.signature(first), snap.signature(second) ])
    assert_equal :nat_dependency, plan.issues.first.evidence[:code]
    assert_raises(P::Error) { plan.script }
  end

  def test_generator_failure_discards_prior_commands_and_rejects_wildcard_names
    good = rule(:srx, name: "good", status: "disable")
    wildcard = rule(:srx, name: "*", status: "disable")
    snap = snapshot(:srx, [ good, wildcard ])
    generator = snap.definition.generator.new(snapshot: snap)
    assert_raises(P::Error) { generator.generate_operation(:remove_rule, [ good, wildcard ]) }
    assert_empty generator.commands
    assert_match(/policy good/, generator.generate_operation(:remove_rule, [ good ]))
    assert_raises(ArgumentError) { generator.generate_operation(:remove_rule, [ rule(:srx, name: "good") ]) }
    assert_empty generator.commands
  end

  def test_vendor_operations_extend_through_declarations_without_dispatch_changes
    implementation = Class.new(Algosec::Vendors::Fortinet::Generator) do
      command_operation :disable_rule, using: :disable_rule

      def disable_rule(rule)
        emit("config firewall policy", "edit #{numeric_identifier(rule.native_rule_id)}", "set status disable", "next", "end")
      end
    end
    implementation.validate_declarations!
    current = rule(:fortinet, name: "12")
    generator = implementation.new(snapshot: snapshot(:fortinet, [ current ]))
    assert_includes generator.generate_operation(:disable_rule, [ current ]), "edit 12\nset status disable"
    refute Algosec::Vendors::Fortinet::Generator.declarations.key?([ :command_operation, :disable_rule ])
    assert_raises(P::Error) { generator.generate_operation(:unknown, [ current ]) }
    assert_empty generator.commands
    invalid = Class.new(implementation) { command_operation :missing, using: :not_implemented }
    assert_raises(ArgumentError) { invalid.validate_declarations! }
  end
end
