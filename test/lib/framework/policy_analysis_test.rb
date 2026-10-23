# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "support/policy_factory"

class PolicyAnalysisTest < Minitest::Test
  include PolicyFactory

  class NetworkStandard < P::Analysis
    check :any_to_any, severity: :critical, message: "禁止任意地址间放行" do |view|
      view.enabled? && view.permit? && view.any?(:sources) && view.any?(:destinations)
    end
    check :telnet, message: "禁止 Telnet 放行" do |view|
      view.enabled? && view.permit? && view.services_overlap?([ "tcp/23" ])
    end
  end

  def test_compliance_keeps_pass_fail_and_unknown_separate
    any = rule(:fortinet, name: "1", source: "0.0.0.0/0", destination: "0.0.0.0/0", services: [ "tcp/23" ])
    safe = rule(:fortinet, name: "2", action: "deny")
    missing = rule(:fortinet, name: "3")
    snap = snapshot(:fortinet, [ any, safe, missing ])
    missing.sources.add("missing")
    report = NetworkStandard.new(snap).perform
    assert_equal [ :any_to_any, :telnet ], report.violations.map(&:check)
    assert_equal 2, report.unknowns.size
    assert report.findings.select { |finding| finding.rule_id == snap.signature(safe) }.all? { |finding| finding.status == :pass }
    refute report.complete?
    refute report.passed?
    assert_equal :unresolved_reference, report.unknowns.first.evidence[:code]
  end

  def test_empty_matches_and_restricted_service_are_not_widened
    restricted = rule(:asa)
    restricted.services.replace("service0", E::ServiceObject.new(**context(:asa), name: "restricted",
                                                           protocol: "tcp", source_port: "1024-2048", destination_port: "23"))
    snap = snapshot(:asa, [ restricted ])
    report = NetworkStandard.new(snap).perform
    assert report.unknowns.any? { |finding| finding.evidence[:code] == :unsupported_service }
    assert_empty report.violations
    restricted.services.delete("service0")
    assert NetworkStandard.new(snap).perform.unknowns.any? { |finding| finding.evidence[:code] == :empty_match }
  end

  def test_declarations_are_validated_inherited_and_traceable
    parent = Class.new(P::Analysis) do
      check(:one, message: "第一项") { |_view| false }
    end
    child = Class.new(parent) do
      check(:two, message: "第二项") { |_view| true }
    end
    assert_equal [ :one ], parent.declarations.keys
    assert_equal [ :one, :two ], child.declarations.keys
    assert_match(/policy_analysis_test.rb/, child.declarations[:two].source_location.first)
    assert_raises(FrozenError) { child.declarations[:two].options[:message].replace("changed") }
    assert_raises(ArgumentError) { child.check(:two, message: "重复") { false } }
    assert_raises(ArgumentError) { P::Analysis.new(snapshot(:fortinet)) }
    invalid = Class.new(P::Analysis) { check :broken, message: "错误方法", using: :missing }
    assert_raises(ArgumentError) { invalid.validate_declarations! }
  end

  def test_custom_facts_do_not_turn_missing_statistics_into_zero_hits
    standard = Class.new(P::Analysis) do
      check :unused, message: "观察期内未命中" do |view, context|
        sample = context[:facts].fetch(:hits, {})[view.id]
        view.unknown!("缺少命中统计", :missing_statistics) if sample.nil?
        sample.zero? ? { hits: sample } : false
      end
    end
    snap = snapshot(:fortinet, [ rule(:fortinet) ])
    assert_equal :missing_statistics, standard.new(snap).perform.unknowns.first.evidence[:code]
    facts = { hits: { snap.signature(snap.rules.first) => 0 } }
    analyzer = standard.new(snap, facts: facts)
    facts[:hits].clear
    assert_equal({ hits: 0 }, analyzer.perform.violations.first.evidence)
    assert_raises(FrozenError) { analyzer.perform.violations.first.evidence[:hits] = 1 }
  end

  def test_check_programming_errors_are_not_swallowed
    broken = Class.new(P::Analysis) { check(:bug, message: "代码错误") { raise NoMethodError, "bug" } }
    assert_raises(NoMethodError) { broken.new(snapshot(:fortinet, [ rule(:fortinet) ])).perform }
    wrong = Class.new(P::Analysis) { check(:bug, message: "返回值错误") { nil } }
    assert_raises(ArgumentError) { wrong.new(snapshot(:fortinet, [ rule(:fortinet) ])).perform }
  end

  def test_each_analysis_observes_later_group_changes
    current = rule(:fortinet)
    analyzer = NetworkStandard.new(snapshot(:fortinet, [ current ]))
    assert analyzer.perform.passed?
    current.services.add("telnet", E::ServiceObject.new(**context(:fortinet), name: "telnet", protocol: "tcp", destination_port: "23"))
    assert_equal [ :telnet ], analyzer.perform.violations.map(&:check)
  end

  def test_mixed_hostname_and_ipv4_members_do_not_look_complete
    current = rule(:fortinet)
    snap = snapshot(:fortinet, [ current ])
    current.sources.leaves.first.add(type: "domain", value: "example.test")
    report = NetworkStandard.new(snap).perform
    assert report.unknowns.any? { |finding| finding.evidence[:code] == :unsupported_address }
    assert_empty report.violations
  end

  def test_name_index_is_scoped_exact_and_rebuilt_after_member_changes
    addresses = %w[z a].map do |name|
      E::AddressObject.new(**context(:srx), name: name, zone: "inside", member: [ { type: "host", value: "10.0.0.1" } ])
    end
    addresses << E::AddressObject.new(**context(:srx), name: "elsewhere", zone: "outside", member: [ { type: "host", value: "10.0.0.1" } ])
    service = E::ServiceObject.new(**context(:srx), name: "WEB", protocol: "tcp", destination_port: "443")
    matcher = P::RuleMatcher.new(snapshot(:srx, addresses + [ service ]))
    assert_equal({ "10.0.0.1" => %w[a z], "10.0.0.2" => nil },
                 matcher.names_for(:sources, { "10.0.0.1" => {}, "10.0.0.2" => {} }, "inside"))
    assert_equal({ "tcp/443" => [ "WEB" ] }, matcher.names_for(:services, { "tcp/443" => {} }, "inside"))
    service.add(term: "DNS", protocol: "udp", destination_port: "53")
    assert_equal({ "tcp/443" => nil }, matcher.names_for(:services, { "tcp/443" => {} }, "inside"))
  end

  def test_ordered_matching_preserves_interface_and_vlan_conditions
    [ { from_interface: "ethernet0/1" }, { dst_interfaces: [ "ethernet0/2" ] },
      { conditions: { from_vlans: { "ethernet0/1" => "100" } } },
      { conditions: { to_vlans: { "ethernet0/2" => "200" } } } ].each do |conditions|
      restricted = rule(:hillstone, **conditions)
      matcher = P::RuleMatcher.new(snapshot(:hillstone, [ restricted ]))
      error = assert_raises(P::Error) { matcher.match(group(:hillstone)) }
      assert_equal :conditional_policy, error.code
      assert_equal :new, matcher.match(group(:hillstone, services: [ "tcp/22" ])).type
    end
  end

  def test_service_timeout_is_not_unconditional_coverage_or_a_reusable_name
    service = E::ServiceObject.new(**context(:hillstone), name: "limited", protocol: "tcp", destination_port: "443", timeout: "60")
    restricted = rule(:hillstone, services: [])
    restricted.services.add(service.name, service)
    matcher = P::RuleMatcher.new(snapshot(:hillstone, [ restricted, service ]))
    error = assert_raises(P::Error) { matcher.match(group(:hillstone)) }
    assert_equal :conditional_policy, error.code
    assert_equal({ "tcp/443" => nil }, matcher.names_for(:services, { "tcp/443" => {} }, "inside"))
    assert_equal :new, matcher.match(group(:hillstone, services: [ "tcp/22" ])).type
  end

  def test_every_vendor_preserves_a_preceding_deny_when_selecting_reusable_rules
    VENDORS.each do |vendor|
      denied = rule(vendor, name: "r1", action: "deny", rule_number: 1)
      allowed = rule(vendor, name: "r2", rule_number: 2)
      result = P::RuleMatcher.new(snapshot(vendor, [ denied, allowed ])).match(group(vendor))
      refute_equal :ignore, result.type, vendor.to_s
      assert_equal [ denied ], result.conflicting_rules, vendor.to_s
    end
  end

  def test_every_vendor_rejects_overlapping_unmodeled_rule_conditions
    VENDORS.each do |vendor|
      [ { application_check: "app" }, { security_profiles: { ips: "strict" } },
        { unparsed_commands: [ "unmodeled condition" ] } ].each do |conditions|
        restricted = rule(vendor, conditions: conditions)
        matcher = P::RuleMatcher.new(snapshot(vendor, [ restricted ]))
        error = assert_raises(P::Error, vendor.to_s) { matcher.match(group(vendor)) }
        assert_equal :conditional_policy, error.code
      end
    end
  end

  def test_asa_deny_in_an_unbound_acl_does_not_conflict
    denied = rule(:asa, name: "r1", rule_number: 1, action: "deny", rule_set: "unbound")
    allowed = rule(:asa, name: "r2", rule_number: 2)
    result = P::RuleMatcher.new(snapshot(:asa, [ denied, allowed ])).match(group(:asa))
    assert_equal :ignore, result.type
    assert_same allowed, result.rule
    assert_empty result.conflicting_rules
  end

  def test_topsec_vlan_zone_mapping_applies_to_deny_rules_and_preserves_reuse
    interface = E::Interface.new(**context(:topsec), name: "vlan100", zone: "inside")
    attributes = { from_zones: nil, conditions: { from_vlans: { "vlan100" => nil } } }
    allowed = rule(:topsec, name: "r2", rule_number: 2, **attributes)
    result = P::RuleMatcher.new(snapshot(:topsec, [ interface, allowed ])).match(group(:topsec))
    assert_equal :ignore, result.type
    denied = rule(:topsec, name: "r1", rule_number: 1, action: "deny", **attributes)
    result = P::RuleMatcher.new(snapshot(:topsec, [ interface, denied, allowed ])).match(group(:topsec))
    refute_equal :ignore, result.type
    assert_equal [ denied ], result.conflicting_rules
  end

  def test_fortinet_parsed_device_order_agrees_with_traffic_matching
    configuration = File.read(TestPaths.root.join("test/fixtures/config/fortinet.cfg"))
    denied_policy = <<~CONFIG
      config firewall policy
          edit 90
              set srcintf "inside"
              set dstintf "outside"
              set srcaddr "internal-web"
              set dstaddr "public-web"
              set action deny
              set schedule "always"
              set service "HTTPS"
          next
      end
    CONFIG
    [ true, false ].each do |deny_first|
      content = deny_first ? configuration.sub("config firewall policy", "#{denied_policy}\nconfig firewall policy") : configuration + denied_policy
      parsed = Algosec::Config::Parser.perform(content, vendor: :fortinet, device_id: 1)
      assert parsed.complete?, parsed.diagnostics.inspect
      current = P::Snapshot.from_config(parsed)
      traffic = P::TrafficMatcher.new(current).perform(source: "10.0.0.10", destination: "198.51.100.20",
                                                       protocol: "tcp", source_port: "12345", destination_port: "443",
                                                       from_zone: "inside", to_zone: "outside")
      result = P::RuleMatcher.new(current).match(group(:fortinet, sources: [ "10.0.0.10" ], destinations: [ "198.51.100.20" ]))
      if deny_first
        assert_equal :deny, traffic.decision
        assert_equal :new, result.type
        assert_equal [ traffic.rule ], result.conflicting_rules
      else
        assert_equal :permit, traffic.decision
        assert_equal :ignore, result.type
        assert_same traffic.rule, result.rule
        assert_empty result.conflicting_rules
      end
    end
  end
end
