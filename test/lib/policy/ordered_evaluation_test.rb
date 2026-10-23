# frozen_string_literal: true

require "test_helper"
require "algosec/policy/evaluation"
require_relative "../framework/support/policy_factory"

class OrderedEvaluationTest < ActiveSupport::TestCase
  include PolicyFactory

  def numeric_set(source: 0..2, destination: 0..2, protocol: 6..6, sport: 0..2, dport: 0..2, family: :ipv4, limit: 4096)
    P::TrafficSet.new([ { family: family, source_addresses: Algosec::Set.new(source),
      destination_addresses: Algosec::Set.new(destination), protocols: Algosec::Set.new(protocol),
      source_ports: Algosec::Set.new(sport), destination_ports: Algosec::Set.new(dport) } ], limit: limit)
  end

  def packet(source: 0, destination: 0, protocol: 6, sport: 0, dport: 0, family: :ipv4, **context)
    af = family == :ipv4 ? Socket::AF_INET : Socket::AF_INET6
    P::Packet.new(source: ::IPAddr.new(source, af).to_s, destination: ::IPAddr.new(destination, af).to_s,
      protocol: protocol, source_port: sport, destination_port: dport, **context)
  end

  def numeric_rule(index, source: 0..2, destination: 0..2, protocol: "tcp", sport: "0-2", dport: "0-2", action: "allow", **attributes)
    entry = E::SecurityRule.new(**context(:palo_alto), name: "r#{index}", native_rule_id: "r#{index}", rule_number: index,
      from_zones: [ "inside" ], to_zones: [ "outside" ], action: action, **attributes)
    { sources: source, destinations: destination }.each do |dimension, range|
      address = E::AddressObject.new(**context(:palo_alto), name: dimension.to_s,
        member: [ { type: "iprange", value: "#{Algosec::IPAddr.from_i(range.begin)}-#{Algosec::IPAddr.from_i(range.end)}" } ])
      entry.public_send(dimension).add(address.name, address)
    end
    service = E::ServiceObject.new(**context(:palo_alto), name: "svc", protocol: protocol, source_port: sport, destination_port: dport)
    entry.services.add(service.name, service)
    entry
  end

  def evaluate(entries, traffic = numeric_set, **options)
    P::Evaluation.new(snapshot(:palo_alto, entries)).perform(traffic, from_zone: "inside", to_zone: "outside", **options)
  end

  test "ordered partitions preserve canonical actions and joint coverage" do
    entries = [ numeric_rule(1, source: 0..0, action: "reset-client"), numeric_rule(2, source: 1..2) ]
    result = evaluate(entries)
    assert result.complete?
    assert result.remaining.empty?
    assert result.unknown.empty?
    assert_equal [ "reset-client", "allow" ], result.partitions.map(&:action)
    assert result.partitions.first.traffic_set.include?(packet)
    assert_equal entries.first, result.partitions.first.rule
    assert result.frozen?
    assert result.partitions.frozen?
    assert result.partitions.all?(&:frozen?)
  end

  test "seeded independent enumeration preserves first match and crossed pairings" do
    random = Random.new(20261022)
    20.times do
      declarations = Array.new(4) do |index|
        intervals = Array.new(4) { [ random.rand(3), random.rand(3) ].sort }.map { |a, b| a..b }
        { source: intervals[0], destination: intervals[1], sport: intervals[2], dport: intervals[3], action: %w[allow deny drop reject][index] }
      end
      entries = declarations.each_with_index.map { |d, i| numeric_rule(i + 1, **d.merge(sport: "#{d[:sport].begin}-#{d[:sport].end}", dport: "#{d[:dport].begin}-#{d[:dport].end}")) }
      result = evaluate(entries)
      (0..2).to_a.repeated_permutation(4) do |src, dst, sport, dport|
        expected = declarations.find { |d| d[:source].include?(src) && d[:destination].include?(dst) && d[:sport].include?(sport) && d[:dport].include?(dport) }
        hits = result.partitions.select { |part| part.traffic_set.include?(packet(source: src, destination: dst, sport: sport, dport: dport)) }
        assert_equal 1, hits.size
        assert_equal expected ? expected[:action] : "deny", hits.first.action
      end
    end
  end

  test "missing application context only consumes possible intersection before later allow" do
    entries = [ numeric_rule(1, source: 0..0, applications: [ "web" ]), numeric_rule(2) ]
    result = evaluate(entries)
    assert_equal [ :unknown, :matched ], result.partitions.map(&:status)
    assert result.unknown.include?(packet)
    refute result.unknown.include?(packet(source: 1))
    refute result.complete?
    assert evaluate(entries, application: "web").complete?
    assert_equal "r2", evaluate(entries, application: "ssh").partitions.first.rule.name
  end

  test "packet application and source user context match exact declared names" do
    entry = numeric_rule(1, applications: [ "web" ], source_users: [ "alice" ])
    result = evaluate([ entry ], packet(application: "web", source_user: "alice"))
    assert_equal "allow", result.partitions.first.action
    assert_equal :matched, result.partitions.first.status
    assert_equal "deny", evaluate([ entry ], packet(application: "web", source_user: "bob")).partitions.first.action
    assert_raises(ArgumentError) { evaluate([ entry ], packet(application: "web"), application: "ssh") }
  end

  test "unknown references retain safe service and destination bounds" do
    entry = numeric_rule(1, destination: 0..0, dport: "1")
    current = snapshot(:palo_alto, [ entry, numeric_rule(2) ])
    entry.sources.add("missing", nil)
    result = P::Evaluation.new(current).perform(numeric_set, from_zone: "inside", to_zone: "outside")
    assert result.unknown.include?(packet(destination: 0, dport: 1))
    refute result.unknown.include?(packet(destination: 1, dport: 1))
    refute result.unknown.include?(packet(destination: 0, dport: 2))
  end

  test "unknown syntax prevents narrowing even by known address declarations" do
    entry = numeric_rule(1, source: 0..0, conditions: { unparsed_commands: [ "unknown restriction" ] })
    result = evaluate([ entry, numeric_rule(2) ])
    assert_equal [ :unknown ], result.partitions.map(&:status)
    assert result.unknown.cover?(numeric_set)
  end

  test "application default uses injected full service definitions and missing definition stays unknown" do
    entry = numeric_rule(1, applications: [ "web" ], service_selection: :application_default)
    current = snapshot(:palo_alto, [ entry ])
    app = E::ServiceObject.new(**context(:palo_alto), name: "web-default", protocol: "tcp", source_port: "1", destination_port: "2")
    result = P::Evaluation.new(current, application_definitions: { "web" => app }).perform(numeric_set, from_zone: "inside", to_zone: "outside", application: "web")
    assert_equal "allow", result.partitions.find { |part| part.traffic_set.include?(packet(sport: 1, dport: 2)) }.action
    assert_equal "deny", result.partitions.find { |part| part.traffic_set.include?(packet(sport: 2, dport: 1)) }.action
    refute evaluate([ entry ], application: "web").complete?
  end

  test "protocol zero is concrete and wildcard service covers every protocol" do
    result = evaluate([ numeric_rule(1, protocol: "any", sport: "0-65535", dport: "0-65535") ], numeric_set(protocol: 0..255))
    assert result.complete?
    assert_equal [ "allow" ], result.partitions.map(&:action)
    assert result.partitions.first.traffic_set.include?(packet(protocol: 0))
  end

  test "explicit address families never share their low integer values" do
    entry = numeric_rule(1, source: 0..0, destination: 0..0)
    address = E::AddressObject.new(**context(:palo_alto), name: "v6", member: [ { type: "ipv6", value: "::1" } ])
    entry.sources.add(address.name, address)
    entry.destinations.add(address.name, address)
    result = evaluate([ entry ], numeric_set(family: :ipv6))
    assert_equal "allow", result.partitions.find { |part| part.traffic_set.include?(packet(source: 1, destination: 1, family: :ipv6)) }.action
    assert_equal "deny", result.partitions.find { |part| part.traffic_set.include?(packet(source: 0, destination: 0, family: :ipv6)) }.action
  end

  test "same zone explicit denial precedes PAN default and unknown generic default remains unproven" do
    entry = numeric_rule(1, to_zones: [ "inside" ], action: "deny")
    result = P::Evaluation.new(snapshot(:palo_alto, [ entry ])).perform(numeric_set, from_zone: "inside", to_zone: "inside")
    assert_equal "deny", result.partitions.first.action
    refute result.partitions.first.default?
    default = P::Evaluation.new(snapshot(:palo_alto)).perform(numeric_set, from_zone: "inside", to_zone: "inside")
    assert_equal "allow", default.partitions.first.action
    assert default.partitions.first.default?
    generic = P::Evaluation.new(snapshot(:hillstone)).perform(numeric_set, from_zone: "inside", to_zone: "inside")
    refute generic.complete?
    assert generic.remaining.cover?(numeric_set)
  end
  test "one budget bounds the entire result before adding another partition" do
    entries = 3.times.map { |i| numeric_rule(i + 1, source: i..i) }
    assert_raises(P::TrafficSet::LimitExceeded) { evaluate(entries, numeric_set(limit: 2)) }
  end

  test "parsed application default and user restrictions use injected context" do
    parsed = Algosec::Config::Parser.perform(<<~CONFIG, vendor: :palo_alto, device_id: 1)
      set rulebase security rules web from inside
      set rulebase security rules web to outside
      set rulebase security rules web application web
      set rulebase security rules web source-user alice
      set rulebase security rules web service application-default
      set rulebase security rules web action allow
    CONFIG
    assert parsed.complete?, parsed.diagnostics.inspect
    restored = Algosec::Config::Document.load(JSON.parse(JSON.generate(Algosec::Config::Document.dump(parsed))))
    app = E::ServiceObject.new(**context(:palo_alto), name: "web-default", protocol: "tcp", destination_port: "2")
    [ parsed, restored ].each do |config|
      evaluator = P::Evaluation.new(P::Snapshot.from_config(config), application_definitions: { "web" => app })
      result = evaluator.perform(packet(dport: 2, application: "web", source_user: "alice"), from_zone: "inside", to_zone: "outside")
      assert_equal :matched, result.partitions.first.status
      assert_equal "allow", result.partitions.first.action
      assert_equal :unknown, evaluator.perform(packet(dport: 2), from_zone: "inside", to_zone: "outside").partitions.first.status
    end
  end

  test "unsupported HIP remains unknown even with application and user evidence" do
    parsed = Algosec::Config::Parser.perform(<<~CONFIG, vendor: :palo_alto, device_id: 1)
      set rulebase security rules web from inside
      set rulebase security rules web to outside
      set rulebase security rules web application web
      set rulebase security rules web source-user alice
      set rulebase security rules web source-hip protected
      set rulebase security rules web service any
      set rulebase security rules web action allow
    CONFIG
    current = P::Snapshot.from_config(parsed, allow_incomplete: true)
    result = P::Evaluation.new(current).perform(packet(application: "web", source_user: "alice"), from_zone: "inside", to_zone: "outside")
    refute result.complete?
    assert_equal :unknown, result.partitions.first.status
  end

  test "ICMP type restrictions are unknown while unrelated protocols remain decidable" do
    entry = numeric_rule(1, protocol: "icmp", dport: "8")
    result = evaluate([ entry, numeric_rule(2) ], numeric_set(protocol: 1..6))
    assert result.unknown.include?(packet(protocol: 1))
    refute result.unknown.include?(packet(protocol: 6))
  end

  test "PAN native any retains dual family provenance through semantic document" do
    parsed = Algosec::Config::Parser.perform(<<~CONFIG, vendor: :palo_alto, device_id: 1)
      set rulebase security rules allow from inside
      set rulebase security rules allow to outside
      set rulebase security rules allow source any
      set rulebase security rules allow destination any
      set rulebase security rules allow service any
      set rulebase security rules allow action allow
    CONFIG
    [ parsed, Algosec::Config::Document.load(JSON.parse(JSON.generate(Algosec::Config::Document.dump(parsed)))) ].each do |config|
      result = P::Evaluation.new(P::Snapshot.from_config(config)).perform(packet(family: :ipv6), from_zone: "inside", to_zone: "outside")
      assert_equal "allow", result.partitions.first.action
      assert_equal "allow", result.partitions.first.rule.name
      assert_equal [ { "type" => "any", "value" => "any" } ], config.rules.first.sources.members.values.first.direct_member
      assert_equal Algosec::IPAddr.parse("0.0.0.0/0"), config.rules.first.sources.set
    end
    explicit = numeric_rule(1, source: 0..::IPAddr::IN4MASK, destination: 0..::IPAddr::IN4MASK)
    assert_equal "deny", evaluate([ explicit ], packet(family: :ipv6)).partitions.first.action
  end

  test "injected IPv6 DNS evidence survives source free document and remains conditional" do
    at = Time.utc(2026, 10, 22)
    answer = { "status" => "resolved", "addresses" => [ "192.0.2.1", "2001:db8::1" ],
      "resolved_at" => at.iso8601, "expires_at" => (at + 60).iso8601 }
    resolver = Object.new
    resolver.define_singleton_method(:resolve) { |_name| answer }
    resolver.define_singleton_method(:context) { {} }
    parsed = Algosec::Config::Parser.perform("address dns\n host example.test\nexit\n", vendor: :hillstone, device_id: 1, dns_resolver: resolver, reference_time: at)
    restored = Algosec::Config::Document.load(JSON.parse(JSON.generate(Algosec::Config::Document.dump(parsed))))
    address = restored.find(E::AddressObject, name: "dns")
    projection = address.address_projection(at: at, family: :ipv6)
    assert projection[:resolution]["complete"]
    assert projection[:resolution]["conditional"]
    assert_equal Algosec::IPv6.parse("2001:db8::1"), projection[:set]
    refute address.address_projection(at: at)[:resolution]["complete"]
    assert_equal Algosec::IPAddr.parse("192.0.2.1"), address.address_projection(at: at, family: :ipv4)[:set]
    refute address.address_projection(at: at + 61, family: :ipv6)[:resolution]["complete"]
  end

  test "unrestricted ICMP marker does not invent a destination port restriction" do
    entry = numeric_rule(1, protocol: "icmp", dport: "1-65535")
    result = evaluate([ entry ], packet(protocol: 1, dport: 0))
    assert_equal "allow", result.partitions.first.action
  end

  test "equivalent unrestricted ICMP type ranges do not become unknown" do
    { "icmp" => 1, "icmpv6" => 58 }.each do |protocol, number|
      [ "0-65535", "0 65535", "65535-0", "1-65535", "1 65535", "65535-1" ].each do |ports|
        entry = numeric_rule(1, protocol: protocol, dport: ports)
        result = evaluate([ entry ], numeric_set(protocol: number..number))

        assert result.complete?, "#{protocol}/#{ports}: #{result.partitions.map(&:reason).inspect}"
        assert_equal [ "allow" ], result.partitions.map(&:action)
        assert result.partitions.sole.traffic_set.include?(packet(protocol: number, dport: 0))
      end
    end
  end
  test "inactive rules do not make active order ambiguous but unknown status remains" do
    now = Time.utc(2026, 10, 22)
    active = numeric_rule(1)
    disabled = numeric_rule(2, status: "disable", rule_number: nil)
    future = numeric_rule(3, rule_number: nil, conditions: { starts_at: (now + 3600).iso8601 })
    expired = numeric_rule(4, rule_number: nil, conditions: { expires_at: (now - 3600).iso8601 })
    result = P::Evaluation.new(snapshot(:palo_alto, [ active, disabled, future, expired ]), at: now)
      .perform(numeric_set, from_zone: "inside", to_zone: "outside")
    assert result.complete?
    assert_equal "r1", result.partitions.first.rule.name
    ambiguous = numeric_rule(5, status: "unsupported", rule_number: nil)
    refute evaluate([ active, ambiguous ]).complete?
  end

  test "unknown chain cannot borrow PAN native default or another chain rules" do
    entry = numeric_rule(1, rule_set: "vsys1/rulebase")
    result = evaluate([ entry ], rule_set: "missing-chain")
    refute result.complete?
    assert_nil result.partitions.first.action
    assert result.remaining.cover?(numeric_set)
  end

  test "incomplete configuration cannot produce a complete proof for an empty request" do
    parsed = Algosec::Config::Parser.perform("", vendor: :palo_alto, device_id: 1, source_complete: false)
    current = P::Snapshot.from_config(parsed, allow_incomplete: true)
    result = P::Evaluation.new(current).perform(P::TrafficSet.new, from_zone: "inside", to_zone: "outside")
    refute result.complete?
    assert result.unknown.empty?
  end
  test "PAN authentication selectors cannot be compared as exact principal names" do
    %w[known-user unknown pre-logon].each do |selector|
      parsed = Algosec::Config::Parser.perform(<<~CONFIG, vendor: :palo_alto, device_id: 1)
        set rulebase security rules web from inside
        set rulebase security rules web to outside
        set rulebase security rules web source-user #{selector}
        set rulebase security rules web service any
        set rulebase security rules web action allow
      CONFIG
      current = P::Snapshot.from_config(parsed, allow_incomplete: true)
      result = P::Evaluation.new(current).perform(packet(source_user: "alice"), from_zone: "inside", to_zone: "outside")
      assert_equal :unknown, result.partitions.first.status
      assert_nil result.partitions.first.action
    end
  end
end
