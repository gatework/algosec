# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "support/policy_factory"

class PolicyOrderTest < Minitest::Test
  include PolicyFactory

  def test_shared_order_rejects_independent_chains_and_unproven_numbers
    behavior = snapshot(:hillstone).behavior
    resolver = P::RuleOrder.new(behavior)
    [ [ rule(:hillstone, rule_set: "first", rule_number: 1), rule(:hillstone, rule_set: "second", rule_number: 2) ],
      [ rule(:hillstone, rule_number: nil), rule(:hillstone, name: "r2", rule_number: 2) ],
      [ rule(:hillstone, rule_number: 2), rule(:hillstone, name: "r2", rule_number: 2) ] ].each do |rules|
      error = assert_raises(P::RuleOrder::Unproven) { resolver.resolve(rules) }
      assert_equal :unknown_order, error.code
    end
    first, second = [ 1, 2 ].map { |number| rule(:hillstone, name: "r#{number}", rule_number: number) }
    assert_equal [ first, second ], resolver.resolve([ second, first ])
    assert_equal [], resolver.resolve([])
    unnumbered = rule(:hillstone)
    assert_equal [ unnumbered ], resolver.resolve([ unnumbered ])
    assert_raises(P::RuleOrder::Unproven) { P::RuleOrder.new(behavior, require_number: true).resolve([ unnumbered ]) }
  end

  def test_traffic_matching_keeps_uncertain_order_unknown
    [ [ nil, 2 ], [ 1, 1 ] ].each do |numbers|
      entries = [ rule(:hillstone, name: "allow", rule_number: numbers.first),
                 rule(:hillstone, name: "deny", action: "deny", rule_number: numbers.last) ]
      [ entries, entries.reverse ].each do |rules|
        matched = P::TrafficMatcher.new(snapshot(:hillstone, rules)).perform(source: "10.0.0.1", destination: "192.0.2.1",
          protocol: "tcp", source_port: "12345", destination_port: "443", from_zone: "inside", to_zone: "outside")
        assert_equal :unknown, matched.status
        assert_nil matched.rule
        assert_nil matched.decision
      end
    end
  end

  def test_design_refuses_missing_or_duplicate_execution_order
    [ [ nil, nil ], [ 1, 1 ] ].each do |numbers|
      entries = [ rule(:hillstone, name: "allow", rule_number: numbers.first),
                 rule(:hillstone, name: "deny", action: "deny", rule_number: numbers.last) ]
      [ entries, entries.reverse ].each do |ordered|
        error = assert_raises(P::Error) { P::RuleMatcher.new(snapshot(:hillstone, ordered)).match(group(:hillstone)) }
        assert_equal :unknown_order, error.code
      end
    end
  end

  def test_design_preserves_explicit_deny_before_permit
    allow = rule(:hillstone, name: "allow", rule_number: 20)
    deny = rule(:hillstone, name: "deny", action: "deny", rule_number: 10)
    result = P::RuleMatcher.new(snapshot(:hillstone, [ allow, deny ])).match(group(:hillstone))
    assert_equal [ deny ], result.conflicting_rules
    refute_equal :ignore, result.type
  end
end
