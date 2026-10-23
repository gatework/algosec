# frozen_string_literal: true

require "test_helper"
require "algosec/policy/domain_query"
require "algosec/dns_resolver"
require_relative "support/policy_factory"

class DomainQueryTest < ActiveSupport::TestCase
  include PolicyFactory

  def traffic
    { source: "10.0.0.1", destination: "registry.npmjs.org", protocol: "tcp", source_port: "12345",
      destination_port: "443", from_zone: "inside", to_zone: "outside" }
  end

  def wildcard_rule(**options)
    entry = rule(:hillstone, **options)
    entry.destinations.delete("destinations")
    entry.destinations.add("npm", E::AddressObject.new(**context(:hillstone), name: "npm",
      member: [ { type: "domain", value: "*.npmjs.org" } ]))
    entry
  end

  def query(entries, addresses: [ "192.0.2.1" ], ttl: 30)
    resolver = Algosec::DnsResolver.new(device_id: 1, transport: ->(*) { [ addresses, ttl ] })
    P::DomainQuery.new(snapshot(:hillstone, entries), resolver: resolver)
  end

  test "domain matching respects label boundaries and retains unknown IP only decisions" do
    entry = wildcard_rule
    matcher = query([ entry ])
    assert_equal [ entry ], matcher.rules(domain: "REGISTRY.npmjs.org.")
    assert_equal [ entry ], matcher.rules(domain: "a.b.npmjs.org")
    assert_equal [ entry ], matcher.rules(domain: "*.npmjs.org")
    assert_empty matcher.rules(domain: "npmjs.org")
    assert_empty matcher.rules(domain: "evilnpmjs.org")
    assert_empty matcher.rules(domain: "npmjs.org.evil.test")
    assert_raises(ArgumentError) { matcher.perform(**traffic.merge(destination: "*.npmjs.org")) }
    assert_equal :unknown, P::TrafficMatcher.new(snapshot(:hillstone, [ entry ])).perform(**traffic.merge(destination: "192.0.2.1")).status
    report = matcher.perform(**traffic)
    assert_equal :conditional, report.status
    assert_equal :permit, report.matches.sole[:match].decision
    assert_equal "registry.npmjs.org", report.evidence[:destination][:domain]
    refute entry.destinations.resolved?
    assert_empty entry.destinations.set
  end

  test "every current address is checked and an earlier deny wins" do
    deny = rule(:hillstone, name: "deny", rule_number: 1, action: "deny")
    allow = wildcard_rule(name: "allow", rule_number: 2)
    report = query([ allow, deny ], addresses: [ "192.0.2.1", "192.0.2.2" ]).perform(**traffic)
    assert_equal :mixed, report.status
    assert_equal [ :deny, :permit ], report.matches.map { |entry| entry[:match].decision }
    assert_equal [ :matched, :conditional ], report.matches.map { |entry| entry[:match].status }
    assert_equal :unmatched, query([ allow ]).perform(**traffic.merge(destination_port: "80")).status
  end

  test "multiple DNS answers are aggregated by canonical actions rather than legacy decisions" do
    [ [ "deny", "drop", :mixed ], [ "reset-client", "reset-server", :mixed ],
      [ "reset-both", "reject", :mixed ], [ "reset-client", "reset-client", :matched ] ].each do |first, second, expected|
      entries = [ rule(:palo_alto, name: "first", rule_number: 1, destination: "192.0.2.1", action: first),
        rule(:palo_alto, name: "second", rule_number: 2, destination: "192.0.2.2", action: second) ]
      resolver = Algosec::DnsResolver.new(device_id: 1, transport: ->(*) { [ [ "192.0.2.1", "192.0.2.2" ], 30 ] })
      report = P::DomainQuery.new(snapshot(:palo_alto, entries), resolver: resolver).perform(**traffic)

      assert_equal [ first, second ], report.matches.map { |entry| entry[:match].action }
      assert_equal expected, report.status, "#{first} / #{second}"
    end
  end

  test "DNS failure and zero TTL remain unknown and uncertain preceding domains cannot be skipped" do
    entry = wildcard_rule(rule_number: 2)
    assert_equal :unknown, query([ entry ], addresses: []).perform(**traffic).status
    assert_equal :unknown, query([ entry ], ttl: 0).perform(**traffic).status
    before = wildcard_rule(name: "other", rule_number: 1, action: "deny")
    before.destinations.delete("npm")
    before.destinations.add("other", E::AddressObject.new(**context(:hillstone), name: "other",
      member: [ { type: "domain", value: "*.other.test" } ]))
    assert_equal :unknown, query([ entry, before ]).perform(**traffic).status
  end

  test "query caches DNS answers until expiry without promoting them to static coverage" do
    travel_to Time.utc(2026, 9, 20, 12) do
      calls = 0
      resolver = Algosec::DnsResolver.new(device_id: 1, store: ActiveSupport::Cache::MemoryStore.new,
        transport: ->(*) { calls += 1; [ [ "192.0.2.1" ], 30 ] })
      entry = wildcard_rule
      2.times { P::DomainQuery.new(snapshot(:hillstone, [ entry ]), resolver: resolver).perform(**traffic) }
      assert_equal 1, calls
      travel 31.seconds
      P::DomainQuery.new(snapshot(:hillstone, [ entry ]), resolver: resolver).perform(**traffic)
      assert_equal 2, calls
      refute entry.destinations.resolved?
      assert entry.destinations.conditional?
    end
  end
end
