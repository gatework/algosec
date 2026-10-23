# frozen_string_literal: true

require "test_helper"
require "open3"
require_relative "support/policy_factory"

class TrafficMatcherTest < ActiveSupport::TestCase
  include PolicyFactory

  def traffic
    { source: "10.0.0.1", destination: "192.0.2.1", protocol: "tcp", source_port: "12345",
      destination_port: "443", from_zone: "inside", to_zone: "outside" }
  end

  test "exact packet queries reject wildcard protocols and accept concrete numeric aliases" do
    entries = [ rule(:hillstone, name: "block", rule_number: 1, action: "deny"),
                rule(:hillstone, name: "fallback", rule_number: 2, services: [ "any" ]) ]
    matcher = P::TrafficMatcher.new(snapshot(:hillstone, entries))
    [ "any", "ANY" ].each do |protocol|
      assert_raises(ArgumentError) { matcher.perform(**traffic.merge(protocol: protocol)) }
    end
    assert_equal :permit, matcher.perform(**traffic.merge(protocol: 0)).decision
    assert_equal :permit, matcher.perform(**traffic.merge(protocol: "0")).decision
    assert_equal :deny, matcher.perform(**traffic.merge(protocol: 6)).decision
    assert_equal :permit, matcher.perform(**traffic.merge(protocol: "17")).decision
  end

  test "policy entrypoint initializes default time in a fresh Ruby process" do
    program = <<~RUBY
      require "algosec/policy"
      catalog = Algosec::Elements::Catalog.new([], vendor: :hillstone, device_id: 1)
      snapshot = Algosec::Policy::Snapshot.new(vendor: :hillstone, device_id: 1, catalog: catalog)
      Algosec::Policy::RuleMatcher.new(snapshot)
      matcher = Algosec::Policy::TrafficMatcher.new(snapshot)
      result = matcher.perform(source: "10.0.0.1", destination: "192.0.2.1", protocol: "tcp",
        source_port: "1024", destination_port: "443", from_zone: "inside", to_zone: "outside")
      puts result.at.is_a?(Time)
    RUBY
    output, error, status = Open3.capture3(RbConfig.ruby, "-Ilib", "-e", program)
    assert status.success?, error
    assert_equal "true\n", output
  end

  test "vendor zone scopes support permit and deny matches" do
    VENDORS.each do |vendor|
      entry = rule(vendor)
      hit = P::TrafficMatcher.new(snapshot(vendor, [ entry ])).perform(**traffic)
      assert_equal :matched, hit.status, vendor.to_s
      assert_equal :permit, hit.decision, vendor.to_s
      denied = rule(vendor, action: "deny")
      hit = P::TrafficMatcher.new(snapshot(vendor, [ denied ])).perform(**traffic)
      assert_equal :deny, hit.decision, vendor.to_s
    end
  end

  test "multiple chains require an explicit chain and missing references stay unknown" do
    entries = [ rule(:srx, name: "r1", rule_set: "first"), rule(:srx, name: "r2", rule_set: "second") ]
    matcher = P::TrafficMatcher.new(snapshot(:srx, entries))
    assert_equal :unknown, matcher.perform(**traffic).status
    assert_equal "r2", matcher.perform(**traffic, rule_set: "second").name
    entry = rule(:hillstone)
    current = snapshot(:hillstone, [ entry ])
    entry.sources.add("missing", nil)
    hit = P::TrafficMatcher.new(current).perform(**traffic)
    assert_equal :unknown, hit.status
  end

  test "canonical scope selects the matching chain and returns the database locator" do
    first = rule(:fortinet, native_rule_id: "1", rule_set: "first", rule_number: 1)
    second = rule(:fortinet, native_rule_id: "1", rule_set: "second", rule_number: 1)
    hit = P::TrafficMatcher.new(snapshot(:fortinet, [ first, second ])).perform(**traffic, rule_set: "second")
    assert_equal :matched, hit.status
    assert_equal second.locator, { rule_id: hit.rule_id }
    assert_equal "second/1", hit.rule_id
    refute_equal first.locator, second.locator
  end

  test "missing or duplicate execution order cannot prove a traffic decision" do
    [ [ nil, nil ], [ 10, nil ], [ 10, 10 ] ].each do |numbers|
      entries = [ rule(:hillstone, name: "allow", rule_number: numbers.first),
                  rule(:hillstone, name: "block", rule_number: numbers.last, action: "deny") ]
      [ entries, entries.reverse ].each do |ordered|
        hit = P::TrafficMatcher.new(snapshot(:hillstone, ordered)).perform(**traffic)
        assert_equal :unknown, hit.status, numbers.inspect
        assert_nil hit.decision
        assert_match(/顺序/, hit.reason)
      end
    end
  end

  test "explicit execution order takes precedence over catalog order" do
    entries = [ rule(:hillstone, name: "allow", rule_number: 20),
                rule(:hillstone, name: "block", rule_number: 10, action: "deny") ]
    hit = P::TrafficMatcher.new(snapshot(:hillstone, entries)).perform(**traffic)
    assert_equal :matched, hit.status
    assert_equal :deny, hit.decision
    assert_equal "block", hit.name
  end

  test "irrelevant and disabled rules do not make execution order ambiguous" do
    entries = [ rule(:hillstone, name: "allow", rule_number: 10),
                rule(:hillstone, name: "disabled", action: "deny", status: "disable"),
                rule(:hillstone, name: "other_zone", action: "deny", from_zones: "dmz") ]
    hit = P::TrafficMatcher.new(snapshot(:hillstone, entries)).perform(**traffic)
    assert_equal :matched, hit.status
    assert_equal :permit, hit.decision
    assert_equal "allow", hit.name
  end

  test "unrelated restricted service does not block a later matching rule" do
    first = rule(:hillstone, name: "r1", rule_number: 1, services: [])
    first.services.add("restricted", E::ServiceObject.new(**context(:hillstone), name: "restricted", protocol: "tcp",
                                                    destination_port: "22", timeout: "60"))
    matcher = P::TrafficMatcher.new(snapshot(:hillstone, [ first, rule(:hillstone, name: "r2", rule_number: 2) ]))
    assert_equal "r2", matcher.perform(**traffic).name
    assert_equal :unknown, matcher.perform(**traffic.merge(destination_port: "22")).status
  end
  test "canonical reset and reject actions remain visible without a lossy legacy decision" do
    %w[reset-client reset-server reset-both reject].each do |action|
      hit = P::TrafficMatcher.new(snapshot(:palo_alto, [ rule(:palo_alto, action: action) ])).perform(**traffic)
      assert_equal :matched, hit.status
      assert_nil hit.decision
      assert_equal action, hit.action
    end
  end
end
