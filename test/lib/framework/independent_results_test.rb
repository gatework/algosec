# frozen_string_literal: true

require "test_helper"
require_relative "support/policy_factory"
require_relative "support/policy_config"

class IndependentResultsTest < ActiveSupport::TestCase
  include PolicyFactory
  include PolicyConfig

  test "shared modifications become independently generatable rules without mutating originals" do
    config = snapshot(:hillstone, [ rule(:hillstone, source: "10.0.0.1/32") ])
    first = group(:hillstone, sources: [ "10.0.0.1", "10.0.0.2" ])
    second = group(:hillstone, destinations: [ "192.0.2.1", "192.0.2.2" ])
    originals = [ first, second ].map { |entry| P::RuleMatcher.new(config).match(entry) }
    assert_equal [ :modify, :modify ], originals.map(&:type)
    converted = P::IndependentResults.perform(originals)
    script = P::Planner.new(P::Report.new(results: converted)).plans.sole.script
    parsed = Algosec::Config::Parser.perform(saved_config(:hillstone, script), vendor: :hillstone, device_id: 1)
    assert parsed.complete?, parsed.diagnostics.inspect
    assert parsed.rules.none? { |entry| entry.sources.resolved_set.include?(Algosec::IPAddr.to_i("10.0.0.2")) && entry.destinations.resolved_set.include?(Algosec::IPAddr.to_i("192.0.2.2")) }
    assert_equal [ :modify, :modify ], originals.map(&:type)
    assert_equal [ :new, :new ], converted.map(&:type)
  end

  test "converted rows preserve conflict evidence" do
    allowed = rule(:hillstone, name: "r1", rule_number: 1, source: "10.0.0.1/32")
    denied = rule(:hillstone, name: "r2", rule_number: 2, action: "deny", source: "10.0.0.2/32")
    config = snapshot(:hillstone, [ allowed, denied ])
    originals = 2.times.map { P::RuleMatcher.new(config).match(group(:hillstone, sources: [ "10.0.0.1", "10.0.0.2" ])) }
    assert originals.all? { |entry| entry.conflicting_rules == [ denied ] }
    converted = P::IndependentResults.perform(originals)
    assert converted.all? { |entry| entry.conflicting_rules == [ denied ] }
  end
end
