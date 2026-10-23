# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "support/policy_factory"

class PolicyPlannerTest < Minitest::Test
  include PolicyFactory

  def build_result(vendor, objects: [], **options)
    P::RuleMatcher.new(snapshot(vendor, objects)).match(group(vendor, **options))
  end

  def test_fortinet_and_hillstone_generate_complete_new_rules
    %i[fortinet hillstone].each do |vendor|
      result = build_result(vendor)
      planner = P::Planner.new(P::Report.new(results: [ result ]))
      devices = planner.perform
      assert_equal :non_exist, devices.first[:policy_state]
      policy = devices.first[:policy_contents].first
      commands = policy[:new][:content]
      assert_match(/#{(vendor == :fortinet) ? "set action accept" : "action permit"}/, commands)
      assert_match(/inside/, commands)
      assert_match(/outside/, commands)
      assert_match(/10\.0\.0\.1/, commands)
      assert_match(/192\.0\.2\.1/, commands)
      assert_match(/443/, commands)
      assert_equal devices, planner.perform
      refute_same result.sources, policy[:sources]
    end
  end

  def test_same_device_keeps_each_mapping_and_reuses_generated_objects
    first = build_result(:hillstone, services: [ "tcp/443" ])
    second = P::RuleMatcher.new(first.snapshot).match(group(:hillstone, services: [ "tcp/8443" ]))
    devices = P::Planner.new(P::Report.new(results: [ first, second ])).perform
    contents = devices.first[:policy_contents]
    assert_equal 2, contents.size
    assert_equal [ "tcp/443" ], contents.first[:services].keys
    assert_equal [ "tcp/8443" ], contents.last[:services].keys
    all = contents.map { |entry| entry[:new][:content] }.join
    assert_equal 1, all.scan('address "Host_10.0.0.1"').size
    assert_equal 2, all.scan("rule top").size
  end

  def test_interleaved_devices_keep_first_seen_order_and_independent_state
    config = snapshot(:hillstone, device_id: 2)
    first = P::RuleMatcher.new(config).match(group(:hillstone, device_id: 2, device_name: "second"))
    second = P::RuleMatcher.new(config).match(group(:hillstone, device_id: 2, device_name: "renamed", services: [ "tcp/8443" ]))
    ignored = build_result(:hillstone, objects: [ rule(:hillstone) ])
    planner = P::Planner.new(P::Report.new(results: [ first, ignored, second ]))
    devices = planner.perform

    assert_equal [ 2, 1 ], devices.map { |device| device[:device_id] }
    assert_equal [ "second", "fw" ], devices.map { |device| device[:device_name] }
    assert_equal [ :non_exist, :all_exist ], devices.map { |device| device[:policy_state] }
    assert_equal [ 2, 1 ], devices.map { |device| device[:policy_contents].size }
    assert_equal({ content: "" }, devices.last[:policy_contents].first[:new])
    contents = devices.first[:policy_contents].map { |entry| entry[:new][:content] }.join
    assert_equal 1, contents.scan('address "Host_10.0.0.1"').size
    assert_equal 2, contents.scan("rule top").size
    assert_equal devices, planner.perform
  end

  def test_modification_preserves_fortinet_members_and_rule_identity
    existing = rule(:fortinet, config: "set srcaddr \"old-source\"\nset dstaddr \"old-destination\"\nset service \"existing-https\"\n")
    result = build_result(:fortinet, objects: [ existing ], sources: [ "10.0.0.0/24" ], services: [ "tcp/443", "tcp/8443" ])
    assert_equal :modify, result.type
    contents = P::Planner.new(P::Report.new(results: [ result ])).perform.first[:policy_contents].first
    assert_includes contents[:new][:content], 'set service "existing-https" "8443"'
    assert_includes contents[:new][:content], "edit r1\n"
    refute_includes contents[:new][:content], "set srcaddr"
    assert_equal existing.config, contents[:existing][:content]
  end

  def test_ignored_result_can_add_nat_without_creating_a_rule
    %i[fortinet hillstone].each do |vendor|
      existing = rule(vendor, source: "10.0.0.1/32")
      config = snapshot(vendor, [ existing ])
      original = group(vendor)
      record = { origin: "10.0.0.1/32", real_ip: "10.0.0.1/32", nat: { type: :dynamic } }
      result = P::Result.new(**original, type: :ignore, rule: existing, snapshot: config,
                             existing: { sources: "10.0.0.1/32", destinations: "192.0.2.1/32", services: "tcp/443" },
                             actions: { new: { nat_sources: { "10.0.0.1/32" => record } } })
      device = P::Planner.new(P::Report.new(results: [ result ])).perform.first
      assert_equal :part_exist, device[:policy_state]
      commands = device[:policy_contents].first[:new][:content]
      assert_match(/#{(vendor == :fortinet) ? "set nat enable" : "snatrule"}/, commands)
      refute_match(/edit 0|rule top/, commands)
    end
  end

  def test_generated_name_collision_does_not_overwrite_existing_address
    existing = E::AddressObject.new(**context(:hillstone), name: "Host_10.0.0.1", member: [ { type: "subnet", value: "10.9.9.9/32" } ])
    result = build_result(:hillstone, objects: [ existing ])
    commands = Algosec::Vendors::Hillstone::Generator.new(result).perform
    assert_includes commands, 'address "Host_10.0.0.1_2"'
    assert_includes commands, 'src-addr "Host_10.0.0.1_2"'
    assert_equal Algosec::IPAddr.parse("10.9.9.9"), existing.set
  end

  def test_generator_is_reentrant_and_discards_commands_on_error
    result = build_result(:hillstone)
    generator = Algosec::Vendors::Hillstone::Generator.new(result)
    assert_equal generator.perform, generator.perform
    bad = build_result(:hillstone, services: [ "tcp/0" ])
    generator = Algosec::Vendors::Hillstone::Generator.new(bad)
    assert_raises(P::Error) { generator.perform }
    assert_empty generator.commands
    report = P::Report.new(error: P::Error.new("failure"))
    assert_raises(P::Error) { P::Planner.new(report).perform }
  end

  def test_failed_generation_keeps_shared_allocations_and_later_calls_can_reuse_them
    state = {}
    good = build_result(:hillstone)
    first = Algosec::Vendors::Hillstone::Generator.new(good, state: state).perform
    committed = P::Value.copy(state)
    bad = build_result(:hillstone, sources: [ "10.0.0.2" ], services: [ "tcp/0" ])
    failed = Algosec::Vendors::Hillstone::Generator.new(bad, state: state)
    assert_raises(P::Error) { failed.perform }
    assert_empty failed.commands
    assert_equal committed, state

    repeated = Algosec::Vendors::Hillstone::Generator.new(good, state: state).perform
    assert_includes first, 'address "Host_10.0.0.1"'
    refute_includes repeated, 'address "Host_10.0.0.1"'
    assert_includes repeated, 'src-addr "Host_10.0.0.1"'
    assert_includes repeated, "rule top"
    assert_equal committed, state
  end

  def test_schedule_preserves_start_and_end_for_both_vendors
    schedule = P::Request.new(sources: [ "any" ], destinations: [ "any" ], services: [ "any" ],
                              schedule: { start_at: "2026-09-15T09:00:00+08:00", end_at: "2026-09-16T18:00:00+08:00", time_zone: "Asia/Hong_Kong" }).schedule
    %i[fortinet hillstone].each do |vendor|
      result = P::RuleMatcher.new(snapshot(vendor)).match(group(vendor), schedule: schedule)
      commands = P::Planner.new(P::Report.new(results: [ result ])).perform.first[:policy_contents].first[:new][:content]
      assert_includes commands, "sch_202609150900_202609161800"
      assert_includes commands, "09:00"
      assert_includes commands, "18:00"
    end
  end
end
