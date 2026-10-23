# frozen_string_literal: true

require "test_helper"
require "algosec/policy/traffic_ranges"
require_relative "support/policy_factory"

class TrafficRangesTest < ActiveSupport::TestCase
  include PolicyFactory

  def query(**overrides)
    { source: Algosec::IPAddr.parse("10.0.0.0/24"), destination: Algosec::IPAddr.parse("192.0.2.1"),
      source_port: Algosec::IPAddr.ports("0-65535"), destination_port: Algosec::IPAddr.ports("443"),
      protocol: "tcp", from_zone: "inside", to_zone: "outside" }.merge(overrides)
  end

  test "any protocol ranges retain tcp deny and other protocol permits" do
    entries = [ rule(:hillstone, name: "block", action: "deny", rule_number: 1),
                rule(:hillstone, name: "fallback", services: [ "any" ], rule_number: 2) ]
    rows = P::TrafficRanges.new(snapshot(:hillstone, entries)).perform(**query(protocol: "any"))
    assert_equal [ "0-5", "6", "7-255" ], rows.map { |row| row[:protocol] }
    assert_equal [ :permit, :deny, :permit ], rows.map { |row| row[:decision] }
    assert_equal :matched, rows.first[:status]
  end

  test "wildcard protocol partitions only use relevant port boundaries and share one budget" do
    entries = [ rule(:hillstone, name: "tcp", services: [ "tcp/443" ], rule_number: 1),
                rule(:hillstone, name: "udp", services: [ "udp/53" ], rule_number: 2),
                rule(:hillstone, name: "fallback", services: [ "any" ], rule_number: 3) ]
    ranges = P::TrafficRanges.new(snapshot(:hillstone, entries))
    rows = ranges.perform(**query(protocol: "any", destination_port: Algosec::IPAddr.ports("0-65535")), limit: 9)
    assert_equal 9, rows.size
    assert_equal [ "0-442", "443", "444-65535" ], rows.select { |row| row[:protocol] == "6" }.map { |row| row[:destination_port] }
    assert_equal [ "0-52", "53", "54-65535" ], rows.select { |row| row[:protocol] == "17" }.map { |row| row[:destination_port] }
    error = assert_raises(ArgumentError) do
      ranges.perform(**query(protocol: "any", destination_port: Algosec::IPAddr.ports("0-65535")), limit: 8)
    end
    assert_equal "query_too_complex", error.message
  end

  test "CIDR crossing a deny and permit boundary preserves first match and gaps" do
    entries = [ rule(:hillstone, source: "10.0.0.64/26", action: "deny", rule_number: 1, native_rule_id: "deny"),
               rule(:hillstone, source: "10.0.0.0/25", rule_number: 2, native_rule_id: "permit") ]
    rows = P::TrafficRanges.new(snapshot(:hillstone, entries)).perform(**query)
    assert_equal [ "10.0.0.0/26", "10.0.0.64/26", "10.0.0.128/25" ], rows.map { |row| row[:source] }
    assert_equal [ :permit, :deny, nil ], rows.map { |row| row[:decision] }
    assert_equal [ :matched, :matched, :unmatched ], rows.map { |row| row[:status] }
  end

  test "source and destination port combinations preserve correlated service terms" do
    entry = rule(:hillstone, services: [])
    entry.services.add("paired", E::ServiceObject.new(**context(:hillstone), name: "paired", terms: [
      { protocol: "tcp", source_port: "100-101", destination_port: "443" },
      { protocol: "tcp", source_port: "102-103", destination_port: "444" }
    ]))
    rows = P::TrafficRanges.new(snapshot(:hillstone, [ entry ])).perform(**query(source_port: Algosec::IPAddr.ports("100-103"), destination_port: Algosec::IPAddr.ports("443-444")))
    assert_equal 4, rows.size
    assert_equal 2, rows.count { |row| row[:status] == :matched }
    assert_equal 2, rows.count { |row| row[:status] == :unmatched }
  end

  test "large networks are partitioned without enumerating hosts" do
    rows = P::TrafficRanges.new(snapshot(:hillstone, [])).perform(**query(source: Algosec::IPAddr.parse("0.0.0.0/0")))
    assert_equal 1, rows.size
    assert_equal "0.0.0.0/0", rows.first[:source]
    assert_equal :unmatched, rows.first[:status]
  end

  test "unknown references and ambiguous chain cannot become absence of policy" do
    entry = rule(:hillstone)
    current = snapshot(:hillstone, [ entry ])
    entry.sources.add("missing", nil)
    assert_equal [ :unknown ], P::TrafficRanges.new(current).perform(**query).map { |row| row[:status] }.uniq
    entries = [ rule(:srx, name: "r1", rule_set: "a"), rule(:srx, name: "r2", rule_set: "b") ]
    assert_equal [ :unknown ], P::TrafficRanges.new(snapshot(:srx, entries)).perform(**query).map { |row| row[:status] }.uniq
  end

  test "complexity limit rejects the full result instead of truncating" do
    entry = rule(:hillstone, source: "10.0.0.0/25")
    assert_raises(ArgumentError, "query_too_complex") { P::TrafficRanges.new(snapshot(:hillstone, [ entry ])).perform(**query, limit: 1) }
  end

  test "caller cannot raise the hard segment budget above 4096" do
    addresses = Algosec::Set.new(*(0..4096).map { |index| (index * 2)..(index * 2) })
    error = assert_raises(ArgumentError) do
      P::TrafficRanges.new(snapshot(:hillstone, [])).perform(**query(source: addresses), limit: 5000)
    end
    assert_equal "query_too_complex", error.message
  end
  test "canonical action survives range result adaptation" do
    entries = [ rule(:palo_alto, action: "reset-client", rule_number: 1) ]
    rows = P::TrafficRanges.new(snapshot(:palo_alto, entries)).perform(**query)
    assert_equal [ "reset-client" ], rows.map { |row| row[:action] }
    assert_equal [ nil ], rows.map { |row| row[:decision] }
  end
end
