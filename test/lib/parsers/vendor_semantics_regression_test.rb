# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "../framework/support/policy_factory"
require_relative "../framework/support/policy_config"
require "algosec/config"

class VendorSemanticsRegressionTest < Minitest::Test
  include PolicyFactory
  include PolicyConfig

  def test_fortinet_missing_action_denies_matching_traffic
    content = File.read(TestPaths.root.join("test/fixtures/config/fortinet.cfg"))
    result = parse(content.lines.reject { |line| line.strip == "set action accept" }.join, :fortinet)
    assert result.complete?, result.diagnostics.inspect
    assert_equal "deny", result.rules.sole.action
    query = { from_zone: "inside", to_zone: "outside", source: "10.0.0.10", destination: "198.51.100.20",
              protocol: "tcp", source_port: 12345, destination_port: 443 }
    assert_equal :deny, P::TrafficMatcher.new(P::Snapshot.from_config(result)).perform(**query).decision
    explicit = parse(content, :fortinet)
    assert explicit.complete?, explicit.diagnostics.inspect
    assert_equal :permit, P::TrafficMatcher.new(P::Snapshot.from_config(explicit)).perform(**query).decision
  end

  def test_topsec_unknown_policy_field_is_attached_to_the_rule
    content = "ID 1 firewall policy add action accept srcarea inside dstarea outside src any dst any service any"
    result = parse("#{content} application restricted\n", :topsec, any_service: "any")
    refute result.complete?
    assert_includes result.diagnostics.map(&:code), :unsupported_rule_condition
    assert_includes result.rules.sole.unparsed_commands, "#{content} application restricted"
    normal = parse("#{content} enable yes log on\n", :topsec, any_service: "any")
    assert normal.complete?, normal.diagnostics.inspect
    assert_empty normal.rules.sole.unparsed_commands
    assert_equal "on", normal.rules.sole.log
  end

  def test_screenos_unknown_policy_tail_is_attached_to_the_rule
    content = "set policy id 1 from inside to outside Any Any ANY permit"
    result = parse("#{content} unsupported-match restricted\n", :netscreen, any_service: "ANY")
    refute result.complete?
    assert_includes result.diagnostics.map(&:code), :unsupported_rule_condition
    assert_includes result.rules.sole.unparsed_commands, "#{content} unsupported-match restricted"
    normal = parse("#{content} log\n", :netscreen, any_service: "ANY")
    assert normal.complete?, normal.diagnostics.inspect
    assert_empty normal.rules.sole.unparsed_commands
    assert_equal "log", normal.rules.sole.log
  end

  def test_srx_generated_range_addresses_round_trip_without_widening
    input = group(:srx, sources: [ "10.0.0.1-10.0.0.9" ], destinations: [ "192.0.2.1-192.0.2.3" ])
    match = P::RuleMatcher.new(snapshot(:srx)).match(input)
    content = P::Planner.new(P::Report.new(results: [ match ])).perform.first[:policy_contents].first[:new][:content]
    result = parse(saved_config(:srx, content), :srx)
    assert result.complete?, result.diagnostics.inspect
    assert_equal Algosec::IPAddr.parse("10.0.0.1-10.0.0.9"), result.rules.sole.sources.resolved_set
    assert_equal Algosec::IPAddr.parse("192.0.2.1-192.0.2.3"), result.rules.sole.destinations.resolved_set
  end

  def test_pan_unknown_source_translation_mode_is_rejected
    result = parse(pan_snat("arbitrary-mode"), :palo_alto)
    refute result.complete?
    assert_includes result.diagnostics.map(&:code), :unsupported_nat_condition
    assert_empty result.elements(E::DynamicNat)
    %w[static-ip dynamic-ip dynamic-ip-and-port].each do |mode|
      normal = parse(pan_snat(mode), :palo_alto)
      assert normal.complete?, "#{mode}: #{normal.diagnostics.inspect}"
      assert_equal Algosec::IPAddr.parse("203.0.113.1"), normal.elements(E::DynamicNat).sole.source_targets
    end
  end

  private

  def parse(content, vendor, any_service: nil)
    builtins = any_service ? { any_service => E::ServiceObject.new(name: any_service, vendor: vendor, protocol: "any", source_port: "0-65535", destination_port: "0-65535") } : {}
    Algosec::Config::Parser.perform(content, vendor: vendor, device_id: 1, builtin_services: builtins)
  end

  def pan_snat(mode)
    <<~CONFIG
      set rulebase nat rules snat from inside
      set rulebase nat rules snat to outside
      set rulebase nat rules snat source any
      set rulebase nat rules snat destination any
      set rulebase nat rules snat service any
      set rulebase nat rules snat source-translation #{mode} translated-address 203.0.113.1
    CONFIG
  end
end
