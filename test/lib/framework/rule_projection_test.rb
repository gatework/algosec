# frozen_string_literal: true

require "minitest/autorun"
require "algosec"

class RuleProjectionTest < Minitest::Test
  E = Algosec::Elements

  def test_shared_projection_applies_each_groups_negation_once
    host = E::AddressObject.new(name: "host", member: [ { type: "host", value: "192.0.2.1" } ])
    positive = E::AddressGroup.new(name: "positive", members: { "host" => host })
    negative = E::AddressGroup::Negated.new(name: "negative", members: { "positive" => positive })
    rules = [ E::SecurityRule.new(name: "first", sources: positive, destinations: negative),
              E::SecurityRule.new(name: "second", sources: negative, destinations: positive) ]

    report = Algosec::Config::Result::RuleProjection.new(rules, at: Time.utc(2026))

    assert_equal positive.set, report.sources.fetch(rules.first.identity)
    assert_equal negative.set, report.destinations.fetch(rules.first.identity)
    assert_equal negative.set, report.sources.fetch(rules.last.identity)
    assert_equal positive.set, report.destinations.fetch(rules.last.identity)
  end

  def test_projection_uses_its_time_for_dns_expiry_in_both_address_directions
    at = Time.utc(2000, 1, 1)
    address = E::AddressObject.new(name: "host", member: [ { type: "domain", value: "example.test" } ])
    resolve(address, "192.0.2.1", expires_at: at + 60)
    addresses = E::AddressGroup.new(name: "addresses", members: { address.name => address })
    rule = E::SecurityRule.new(native_rule_id: "1", sources: addresses, destinations: addresses)
    reads = 0
    original = address.method(:direct_member)
    address.define_singleton_method(:direct_member) { reads += 1; original.call }

    report = Algosec::Config::Result::RuleProjection.new([ rule ], at: at)
    assert_equal 1, reads
    assert_equal Algosec::IPAddr.parse("192.0.2.1"), report.sources.fetch(rule.identity)
    assert_equal report.sources.fetch(rule.identity), report.destinations.fetch(rule.identity)
    expired = Algosec::Config::Result::RuleProjection.new([ rule ], at: at + 60)
    assert_equal 2, reads, "Expired DNS evidence still shares its projection within one report"
    assert_empty expired.sources.fetch(rule.identity)
    assert_empty expired.destinations.fetch(rule.identity)

    resolve(address, "192.0.2.2", expires_at: at + 120)
    refreshed = Algosec::Config::Result::RuleProjection.new([ rule ], at: at + 60)
    assert_equal 3, reads
    assert_equal Algosec::IPAddr.parse("192.0.2.2"), refreshed.sources.fetch(rule.identity)
    assert_equal Algosec::IPAddr.parse("192.0.2.1"), report.sources.fetch(rule.identity)
  end

  def test_projection_expands_shared_descendants_once_and_does_not_reuse_them_between_reports
    leaf = E::AddressObject.new(name: "host", member: [ { type: "host", value: "192.0.2.1" } ])
    reads = 0
    original = leaf.method(:direct_member)
    leaf.define_singleton_method(:direct_member) { reads += 1; original.call }
    rules = 100.times.map do |index|
      sources = E::AddressGroup.new(name: "sources#{index}", members: { leaf.name => leaf })
      destinations = E::AddressGroup.new(name: "destinations#{index}", members: { sources.name => sources })
      E::SecurityRule.new(native_rule_id: index.to_s, sources: sources, destinations: destinations)
    end

    first = Algosec::Config::Result::RuleProjection.new(rules, at: Time.utc(2026))
    assert_equal 1, reads, "Shared descendants must be expanded once across all report roots"
    assert_equal 100, first.sources.size
    assert_equal [ Algosec::IPAddr.parse("192.0.2.1") ], first.sources.values.uniq
    assert_equal first.sources, first.destinations

    leaf.add(type: "host", value: "192.0.2.2")
    second = Algosec::Config::Result::RuleProjection.new(rules, at: Time.utc(2026))
    assert_equal 2, reads
    assert_equal [ Algosec::IPAddr.parse("192.0.2.1-192.0.2.2") ], second.sources.values.uniq
    assert_equal [ Algosec::IPAddr.parse("192.0.2.1") ], first.sources.values.uniq
  end

  def test_shared_descendants_preserve_parent_exclusions_and_ignored_rules
    leaf = E::AddressObject.new(name: "subnet", member: [ { type: "subnet", value: "192.0.2.0/24" } ])
    rules = %w[192.0.2.0/25 192.0.2.128/25].each_with_index.map do |excluded, index|
      parent = E::AddressObject.new(name: "parent#{index}", references: [ leaf.name, "missing" ],
                             excluded_member: [ { type: "subnet", value: excluded } ]).resolve!(strict: false) { |name| leaf if name == leaf.name }
      E::SecurityRule.new(native_rule_id: index.to_s, sources: E::AddressGroup.new(name: "sources", members: { parent.name => parent }))
    end
    ignored = E::SecurityRule.new(native_rule_id: "ignored", status: "disable", sources: rules.first.sources)

    report = Algosec::Config::Result::RuleProjection.new([ *rules, ignored ], at: Time.utc(2026))
    assert_equal Algosec::IPAddr.parse("192.0.2.128/25"), report.sources.fetch(rules.first.identity)
    assert_equal Algosec::IPAddr.parse("192.0.2.0/25"), report.sources.fetch(rules.last.identity)
    refute report.sources.key?(ignored.identity)
  end

  def test_circular_reference_diagnostics_do_not_cache_incomplete_paths_for_other_roots
    first = E::AddressObject.new(name: "first", member: [ { type: "host", value: "192.0.2.1" } ])
    second = E::AddressObject.new(name: "second", member: [ { type: "host", value: "192.0.2.2" } ])
    # 模拟绕过构造校验的旧对象图，保留投影原有的环诊断及已知叶子证据。
    first.instance_variable_get(:@references)[second.name] = second
    second.instance_variable_get(:@references)[first.name] = first
    rules = [ first, second ].map do |address|
      E::SecurityRule.new(native_rule_id: address.name, sources: E::AddressGroup.new(name: "sources", members: { address.name => address }))
    end

    [ rules, rules.reverse ].each do |ordered|
      report = Algosec::Config::Result::RuleProjection.new(ordered, at: Time.utc(2026))
      rules.each { |rule| assert_equal Algosec::IPAddr.parse("192.0.2.1-192.0.2.2"), report.sources.fetch(rule.identity) }
    end
    [ first, second ].each do |address|
      projection = address.address_projection
      refute projection[:resolution]["complete"]
      assert_equal Algosec::IPAddr.parse("192.0.2.1-192.0.2.2"), projection[:set]
      assert projection[:resolution]["errors"].any? { |error| error.start_with?("circular_reference:") }
    end
  end

  private

  def resolve(address, ip, expires_at:)
    answer = { "status" => "resolved", "addresses" => [ ip ], "expires_at" => expires_at.iso8601 }
    resolver = Object.new
    resolver.define_singleton_method(:resolve) { |_domain| answer }
    address.resolve_domains!(resolver)
  end
end
