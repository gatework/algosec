# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "support/policy_factory"
require_relative "support/policy_config"
require "algosec/config"

class PolicyRoundTripTest < Minitest::Test
  include PolicyFactory
  include PolicyConfig

  def test_generated_rules_round_trip_to_exact_request_ranges_for_nine_vendors
    VENDORS.each do |vendor|
      settings = (vendor == :h3c) ? { policy_bindings: [ { name: "objects", from_zone: "inside", to_zone: "outside" } ] } : {}
      input = group(vendor, sources: [ "10.0.0.1", "10.0.0.2" ], destinations: [ "192.0.2.1" ], services: [ "tcp/443", "udp/53" ])
      result = P::RuleMatcher.new(snapshot(vendor, settings: settings)).match(input)
      content = P::Planner.new(P::Report.new(results: [ result ])).perform.first[:policy_contents].first[:new][:content]
      parsed = Algosec::Config::Parser.perform(saved_config(vendor, content), vendor: vendor, device_id: 1)
      assert parsed.complete?, "#{vendor}: #{parsed.diagnostics.map(&:message).join("; ")}"
      refute_empty parsed.rules, vendor.to_s
      targets = { sources: P::Ranges.addresses(input[:sources].keys), destinations: P::Ranges.addresses(input[:destinations].keys), services: P::Ranges.services(input[:services].keys) }
      parsed.rules.each do |rule|
        actual = { sources: rule.sources.resolved_set, destinations: rule.destinations.resolved_set, services: P::Ranges.rule_services(rule) }
        actual.each { |dimension, set| assert targets[dimension].cover?(set), "#{vendor}: wider #{dimension}" }
      end
      input[:sources].keys.product(input[:destinations].keys, input[:services].keys).each do |source, destination, service|
        assert parsed.rules.any? { |rule| rule.sources.resolved_set.cover?(Algosec::IPAddr.parse(source)) && rule.destinations.resolved_set.cover?(Algosec::IPAddr.parse(destination)) && P::Ranges.rule_services(rule).cover?(P::Ranges.service(service)) }, vendor.to_s
      end
    end
  end

  def test_once_schedules_round_trip_with_their_time_zone_and_binding
    schedule = P::Request.new(sources: [ "any" ], destinations: [ "any" ], services: [ "any" ],
                              schedule: { start_at: "2026-09-15T09:00:00+08:00", end_at: "2026-09-16T18:00:00+08:00", time_zone: "Asia/Hong_Kong" }).schedule
    (VENDORS - [ :neteye ]).each do |vendor|
      settings = (vendor == :h3c) ? { policy_bindings: [ { name: "objects", from_zone: "inside", to_zone: "outside" } ] } : {}
      result = P::RuleMatcher.new(snapshot(vendor, settings: settings)).match(group(vendor), schedule: schedule)
      content = P::Planner.new(P::Report.new(results: [ result ])).perform.first[:policy_contents].first[:new][:content]
      parsed = Algosec::Config::Parser.perform(saved_config(vendor, content), vendor: vendor, device_id: 1, time_zone: "Asia/Hong_Kong")
      assert parsed.complete?, "#{vendor}: #{parsed.diagnostics.map(&:message).join("; ")}"
      assert_equal 1, parsed.rules.size, vendor.to_s
      assert_equal schedule.window, parsed.rules.first.schedule&.window, vendor.to_s
    end
  end
end
