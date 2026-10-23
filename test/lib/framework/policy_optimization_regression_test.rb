# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "support/policy_factory"
require "algosec/policy/traffic_ranges"

class PolicyOptimizationRegressionTest < Minitest::Test
  include PolicyFactory

  def test_design_cannot_reuse_a_rule_from_an_ambiguous_chain
    entries = [ rule(:srx, name: "first", rule_set: "first", rule_number: 1),
                rule(:srx, name: "second", rule_set: "second", rule_number: 2, action: "deny") ]
    config = snapshot(:srx, entries)
    traffic = P::TrafficMatcher.new(config).perform(source: "10.0.0.1", destination: "192.0.2.1", protocol: "tcp",
                                                   source_port: "1024", destination_port: "443", from_zone: "inside", to_zone: "outside")
    assert_equal :unknown, traffic.status

    error = assert_raises(P::Error) { P::RuleMatcher.new(config).match(group(:srx)) }

    assert_equal :unknown_order, error.code
  end

  def test_an_unrelated_chain_does_not_prevent_design_reuse
    allowed = rule(:srx, name: "first", rule_set: "first", rule_number: 1)
    unrelated = rule(:srx, name: "second", rule_set: "second", rule_number: 2, action: "deny", from_zones: "dmz")

    result = P::RuleMatcher.new(snapshot(:srx, [ allowed, unrelated ])).match(group(:srx))

    assert_equal :ignore, result.type
    assert_same allowed, result.rule
  end

  def test_palo_alto_parsed_ordinary_and_default_rules_preserve_design_reuse
    config = palo_alto_rules_with_default

    result = P::RuleMatcher.new(config).match(group(:palo_alto))

    assert_equal :ignore, result.type
    assert_equal "allow-web", result.rule.name
    assert_empty result.conflicting_rules
  end

  def test_palo_alto_parsed_ordinary_and_default_rules_preserve_first_match
    config = palo_alto_rules_with_default
    matcher = P::TrafficMatcher.new(config)

    allowed = matcher.perform(**traffic_query)
    denied = matcher.perform(**traffic_query.merge(source: "10.0.0.2", destination: "192.0.2.2"))

    assert_equal :matched, allowed.status
    assert_equal :permit, allowed.decision
    assert_equal "allow-web", allowed.name
    assert_equal :matched, denied.status
    assert_equal :deny, denied.decision
    assert_equal "interzone-default", denied.name
    assert_equal "vsys1/rulebase/default-security-rules", denied.rule.rule_set
    selected = matcher.perform(**traffic_query, rule_set: "vsys1/rulebase/default-security-rules")
    assert_equal :deny, selected.decision
    assert_equal "interzone-default", selected.name
  end

  def test_palo_alto_design_after_an_unrelated_ordinary_rule_keeps_default_deny_evidence
    config = palo_alto_rules_with_default

    result = P::RuleMatcher.new(config).match(group(:palo_alto, sources: [ "10.0.0.2" ], destinations: [ "192.0.2.2" ], services: [ "tcp/22" ]))
    script = result.definition.build_generator(result).perform

    assert_equal :new, result.type
    assert_equal [ "interzone-default" ], result.conflicting_rules.map(&:name)
    assert_includes script, "set rulebase security rules"
    refute_includes script, "move rulebase"
  end

  def test_palo_alto_only_recognizes_its_supported_default_rule_chain
    [ [ "vsys1/rulebase/default-security-rules", "security" ],
      [ "vsys1/rulebase/default-security-rules", nil ],
      [ "vsys2/rulebase/default-security-rules", "default-security-rules" ],
      [ "vsys1/pre-rulebase/default-security-rules", "default-security-rules" ],
      [ "independent/default-security-rules", "default-security-rules" ] ].each do |chain, family|
      allowed = rule(:palo_alto, name: "allow", rule_set: "vsys1/rulebase", rule_number: 1)
      denied = rule(:palo_alto, name: "deny", rule_set: chain, rule_number: 2, action: "deny",
                               vendor_data: { panos: JSON.generate("family" => family) })
      config = snapshot(:palo_alto, [ allowed, denied ])

      assert_equal :unknown, P::TrafficMatcher.new(config).perform(**traffic_query).status, [ chain, family ].inspect
      error = assert_raises(P::Error) { P::RuleMatcher.new(config).match(group(:palo_alto)) }
      assert_equal :unknown_order, error.code
    end
  end

  def test_palo_alto_default_rule_chain_still_requires_unique_execution_order
    [ 1, nil ].each do |number|
      allowed = rule(:palo_alto, name: "allow", rule_set: "vsys1/rulebase", rule_number: 1)
      denied = rule(:palo_alto, name: "deny", rule_set: "vsys1/rulebase/default-security-rules", rule_number: number, action: "deny",
                               vendor_data: { panos: JSON.generate("family" => "default-security-rules") })
      config = snapshot(:palo_alto, [ allowed, denied ])

      match = P::TrafficMatcher.new(config).perform(**traffic_query)
      assert_equal :unknown, match.status
      assert_match(/顺序/, match.reason)
      error = assert_raises(P::Error) { P::RuleMatcher.new(config).match(group(:palo_alto)) }
      assert_equal :unknown_order, error.code
    end
  end

  def test_other_protocol_ports_do_not_exhaust_the_range_query_limit
    entry = rule(:hillstone, services: [], rule_number: 1)
    terms = (1..65).step(2).map { |port| { protocol: "udp", source_port: port.to_s, destination_port: port.to_s } }
    terms << { protocol: "tcp", source_port: "0-65535", destination_port: "0-65535" }
    entry.services.add("mixed", E::ServiceObject.new(**context(:hillstone), name: "mixed", terms: terms))

    rows = P::TrafficRanges.new(snapshot(:hillstone, [ entry ])).perform(
      source: Algosec::IPAddr.parse("10.0.0.1"), destination: Algosec::IPAddr.parse("192.0.2.1"),
      source_port: Algosec::IPAddr.ports("0-66"), destination_port: Algosec::IPAddr.ports("0-66"),
      protocol: "tcp", from_zone: "inside", to_zone: "outside")

    assert_equal 1, rows.size
    assert_equal :matched, rows.first[:status]
    assert_equal :permit, rows.first[:decision]
    assert_equal "0-66", rows.first[:source_port]
    assert_equal "0-66", rows.first[:destination_port]
  end

  def test_any_protocol_terms_reject_source_port_restrictions
    assert_raises(ArgumentError) do
      E::ServiceObject.new(**context(:hillstone), name: "limited", protocol: "any", source_port: "1024")
    end
  end

  def test_tcp_protocol_terms_keep_their_source_port_boundaries
    entry = rule(:hillstone, services: [])
    entry.services.add("limited", E::ServiceObject.new(**context(:hillstone), name: "limited", protocol: "tcp", source_port: "1024", destination_port: "0-65535"))

    rows = P::TrafficRanges.new(snapshot(:hillstone, [ entry ])).perform(
      source: Algosec::IPAddr.parse("10.0.0.1"), destination: Algosec::IPAddr.parse("192.0.2.1"),
      source_port: Algosec::IPAddr.ports("1023-1025"), destination_port: Algosec::IPAddr.ports("443"),
      protocol: "6", from_zone: "inside", to_zone: "outside")

    assert_equal %w[1023 1024 1025], rows.map { |row| row[:source_port] }
    assert_equal [ :unmatched, :matched, :unmatched ], rows.map { |row| row[:status] }
  end

  def test_icmp_type_restrictions_stay_unknown_without_tcp_source_port_partitions
    entry = rule(:hillstone, services: [])
    entry.services.add("mixed", E::ServiceObject.new(**context(:hillstone), name: "mixed", terms: [
      { protocol: "icmp", destination_port: "8" },
      { protocol: "tcp", source_port: "1024", destination_port: "443" }
    ]))

    rows = P::TrafficRanges.new(snapshot(:hillstone, [ entry ])).perform(
      source: Algosec::IPAddr.parse("10.0.0.1"), destination: Algosec::IPAddr.parse("192.0.2.1"),
      source_port: Algosec::IPAddr.ports("1023-1025"), destination_port: Algosec::IPAddr.ports("7-9"),
      protocol: "1", from_zone: "inside", to_zone: "outside")

    assert_equal [ "7-9" ], rows.map { |row| row[:destination_port] }
    assert_equal [ :unknown ], rows.map { |row| row[:status] }
    assert_nil rows.first[:action]
    assert_nil rows.first[:decision]
    assert_equal [ "1023-1025" ], rows.map { |row| row[:source_port] }
  end

  def test_diagonal_service_terms_preserve_every_port_pair_within_the_actual_budget
    entry = rule(:hillstone, services: [])
    terms = (1..65).step(2).map { |port| { protocol: "tcp", source_port: port.to_s, destination_port: port.to_s } }
    entry.services.add("partitioned", E::ServiceObject.new(**context(:hillstone), name: "partitioned", terms: terms))
    ranges = P::TrafficRanges.new(snapshot(:hillstone, [ entry ]))
    query = { source: Algosec::IPAddr.parse("10.0.0.1"), destination: Algosec::IPAddr.parse("192.0.2.1"),
      source_port: Algosec::IPAddr.ports("0-66"), destination_port: Algosec::IPAddr.ports("0-66"),
      protocol: "tcp", from_zone: "inside", to_zone: "outside" }

    rows = ranges.perform(**query)
    indexed = rows.map { |row| [ Algosec::IPAddr.ports(row[:source_port]), Algosec::IPAddr.ports(row[:destination_port]), row ] }
    (0..66).each do |source_port|
      (0..66).each do |destination_port|
        hits = indexed.select { |sources, destinations, _row| sources.include?(source_port) && destinations.include?(destination_port) }
        assert_equal 1, hits.size, "#{source_port} -> #{destination_port}"
        row = hits.first.last
        if source_port == destination_port && source_port.odd?
          assert_equal :matched, row[:status]
          assert_equal "allow", row[:action]
          assert_equal :permit, row[:decision]
        else
          assert_equal :unmatched, row[:status]
          assert_nil row[:action]
          assert_nil row[:decision]
        end
      end
    end
    error = assert_raises(ArgumentError) { ranges.perform(**query, limit: 32) }
    assert_equal "query_too_complex", error.message
  end

  def test_service_term_budget_stops_before_reading_later_group_leaves
    entry = rule(:hillstone, services: [])
    first = E::ServiceObject.new(**context(:hillstone), name: "first", terms: [ 1, 3, 5 ].map do |port|
      { protocol: "tcp", source_port: port.to_s, destination_port: port.to_s }
    end)
    later = E::ServiceObject.new(**context(:hillstone), name: "later", protocol: "tcp", destination_port: "443")
    entry.services.add(first.name, first)
    entry.services.add(later.name, later)
    current = snapshot(:hillstone, [ entry ])
    # 真实服务的读取探针：预算已耗尽后，不应再取后续叶子的项或构造完整项数组。
    later.define_singleton_method(:terms) { raise "Read a later service after the term budget was exhausted" }
    packet = P::Packet.new(source: "10.0.0.1", destination: "192.0.2.1", protocol: 6, source_port: 1, destination_port: 1)
    traffic = P::TrafficSet.from_packet(packet, limit: 2)

    assert_raises(P::TrafficSet::LimitExceeded) do
      P::Evaluation.new(current).perform(traffic, from_zone: "inside", to_zone: "outside")
    end
  end

  def test_migration_rejects_repeated_order_in_overlapping_source_chains
    entries = [ rule(:srx, name: "allow", rule_set: "first", rule_number: 1),
                rule(:srx, name: "deny", rule_set: "second", rule_number: 1, action: "deny") ]

    plan = migration_plan(entries)

    refute plan.ready?
    assert_equal :unknown_order, plan.issues.first.evidence[:code]
    assert_raises(P::Error) { plan.script }
  end

  def test_migration_rejects_repeated_order_when_only_one_zone_pair_overlaps
    entries = [ rule(:palo_alto, name: "allow", rule_set: "first", rule_number: 1, from_zones: %w[inside outside]),
                rule(:palo_alto, name: "deny", rule_set: "second", rule_number: 1, action: "deny") ]

    plan = migration_plan(entries, vendor: :palo_alto)

    refute plan.ready?
    assert_equal :unknown_order, plan.issues.first.evidence[:code]
  end

  def test_migration_keeps_repeated_order_for_disjoint_zone_pairs
    entries = [ rule(:srx, name: "allow", rule_set: "first", rule_number: 1),
                rule(:srx, name: "deny", rule_set: "second", rule_number: 1, action: "deny", from_zones: "outside", to_zones: "inside") ]

    plan = migration_plan(entries)

    assert plan.ready?, plan.issues.map(&:message).join("; ")
    assert_equal [ [ "inside", "outside" ], [ "outside", "inside" ] ],
                 plan.changes.flat_map { |change| change[:results].map { |result| result.values_at(:from_zone, :to_zone) } }
  end

  def test_migration_rejects_unique_numbers_without_a_shared_source_chain
    entries = [ rule(:srx, name: "allow", rule_set: "first", rule_number: 2),
                rule(:srx, name: "deny", rule_set: "second", rule_number: 1, action: "deny") ]

    plan = migration_plan(entries)

    refute plan.ready?
    assert_equal :unknown_order, plan.issues.first.evidence[:code]
  end

  def test_migration_keeps_missing_source_order_unknown
    plan = migration_plan([ rule(:srx, rule_set: "first") ])

    refute plan.ready?
    assert_equal :unknown_order, plan.issues.first.evidence[:code]
  end

  def test_migration_keeps_palo_alto_disjoint_rule_types_with_repeated_order
    entries = %w[interzone intrazone].map do |kind|
      rule(:palo_alto, name: kind, rule_set: kind, rule_type: kind, rule_number: 1, from_zones: %w[inside outside], to_zones: %w[inside outside],
                       vendor_data: { panos: JSON.generate("rule-type" => [ kind ]) })
    end

    plan = migration_plan(entries, vendor: :palo_alto)

    assert plan.ready?, plan.issues.map(&:message).join("; ")
    assert_equal 4, plan.changes.sum { |change| change[:results].size }
  end

  def test_migration_keeps_palo_alto_parsed_default_rule_order
    require "algosec/config"
    content = [ [ "security", "allow", "allow" ], [ "default-security-rules", "interzone-default", "deny" ] ].flat_map do |family, name, action|
      { "from" => "inside", "to" => "outside", "source" => "any", "destination" => "any", "service" => "any", "application" => "any", "action" => action }.map do |field, value|
        "set rulebase #{family} rules #{name} #{field} #{value}"
      end
    end.join("\n")
    parsed = Algosec::Config::Parser.perform(content, vendor: :palo_alto, device_id: 1)
    assert parsed.complete?, parsed.diagnostics.map(&:message).join("; ")
    source = P::Snapshot.from_config(parsed)
    assert_equal 2, source.rules.map(&:rule_set).uniq.size

    plan = P::Migration.new(source: source, target: snapshot(:fortinet, [], device_id: 2),
                            zones: { "inside" => "inside", "outside" => "outside" }).perform

    refute plan.ready?
    assert_equal :unsupported_gap, plan.issues.first.evidence[:code]
    assert_raises(P::Error) { plan.script }

    # 明确 IPv4 的普通规则仍优先于原生默认链；默认规则本身不生成跨厂商用户策略。
    ipv4 = content.gsub(/(source|destination) any$/, '\1 0.0.0.0/0')
    parsed = Algosec::Config::Parser.perform(ipv4, vendor: :palo_alto, device_id: 1)
    assert parsed.complete?, parsed.diagnostics.map(&:message).join("; ")
    source = P::Snapshot.from_config(parsed)
    plan = P::Migration.new(source: source, target: snapshot(:fortinet, [], device_id: 2),
      zones: { "inside" => "inside", "outside" => "outside" }).perform

    assert plan.ready?, plan.issues.map(&:message).join("; ")
    assert_equal [ :permit ], plan.changes.map { |change| change[:decision] }
    packet = P::Packet.new(source: "10.0.0.1", destination: "192.0.2.1", protocol: 6, source_port: 12345, destination_port: 443)
    before = P::Evaluation.new(source).perform(packet, from_zone: "inside", to_zone: "outside")
    after = P::Evaluation.new(plan.change_set.apply).perform(packet, from_zone: "inside", to_zone: "outside")
    assert_equal "allow", before.partitions.sole.rule.name
    assert_equal "allow", before.partitions.sole.action
    assert_equal before.partitions.sole.action, after.partitions.sole.action
    assert_equal 1, plan.change_set.apply.rules.size
  end

  private

  def traffic_query
    { source: "10.0.0.1", destination: "192.0.2.1", protocol: "tcp", source_port: "1024", destination_port: "443",
      from_zone: "inside", to_zone: "outside" }
  end

  def palo_alto_rules_with_default
    require "algosec/config"
    parsed = Algosec::Config::Parser.perform(<<~CONFIG, vendor: :palo_alto, device_id: 1)
      set rulebase default-security-rules rules interzone-default action deny
      set service web protocol tcp port 443
      set rulebase security rules allow-web from inside
      set rulebase security rules allow-web to outside
      set rulebase security rules allow-web source 10.0.0.1
      set rulebase security rules allow-web destination 192.0.2.1
      set rulebase security rules allow-web service web
      set rulebase security rules allow-web application any
      set rulebase security rules allow-web action allow
    CONFIG
    assert parsed.complete?, parsed.diagnostics.map(&:message).join("; ")
    assert_equal [ 1, 2 ], parsed.rules.map(&:rule_number).sort
    assert_equal 2, parsed.rules.map(&:rule_set).uniq.size
    P::Snapshot.from_config(parsed)
  end

  def migration_plan(entries, vendor: :srx)
    P::Migration.new(source: snapshot(vendor, entries), target: snapshot(:fortinet, [], device_id: 2),
                     zones: { "inside" => "inside", "outside" => "outside" }).perform
  end
end
