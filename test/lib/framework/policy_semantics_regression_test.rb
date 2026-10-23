# frozen_string_literal: true

require "minitest/autorun"
require "active_support/all"
require_relative "support/policy_factory"

class PolicySemanticsRegressionTest < Minitest::Test
  include PolicyFactory

  def test_request_deduplicates_equivalent_services_and_translated_ports
    request = service_request([
      { services: [ "tcp/443" ], translated_port: 8443 },
      { services: [ "6/00443-00443" ], translated_port: "08443" }
    ])

    assert_equal({ "tcp/443" => { origin: "tcp/443", translated_port: "8443" } }, request.services)
    assert request.services.frozen?
    assert request.services.values.first.frozen?
  end

  def test_request_rejects_conflicting_nat_for_equivalent_services
    assert_raises(ArgumentError) do
      service_request([
        { services: [ "tcp/443" ], translated_port: 8443 },
        { services: [ "6/443" ], translated_port: 9443 }
      ])
    end
  end

  def test_normalized_services_keep_protocols_distinct
    request = service_request([ "6/443", "17/443", "tcp/443", "udp/443" ])

    assert_equal %w[tcp/443 udp/443], request.services.keys
  end

  def test_service_normalization_preserves_accepted_port_range_semantics
    [ "tcp/443 - 445", "6/445-443", "TCP/00443 00445" ].each do |service|
      request = service_request([ service ])
      assert_equal [ "tcp/443-445" ], request.services.keys
      assert_equal P::Ranges.service(service), P::Ranges.service(request.services.keys.first)
      config = snapshot(:srx)
      result = P::RuleMatcher.new(config).match(group(:srx, services: [ service ]))

      assert_includes result.definition.build_generator(result).perform, "destination-port 443-445"
    end
  end

  def test_direct_results_cannot_bypass_publication_conflicts_with_service_aliases
    config = publication_snapshot
    results = [ publication_result(config, "tcp/443", "8443"), publication_result(config, "6/443", "9443") ]
    state = {}
    generator = config.definition.generator.new(snapshot: config, state: state)

    assert_raises(P::Error) { generator.perform(results) }
    assert_empty generator.commands
    assert_empty state
    assert_includes generator.perform(results.first), "translated-port 8443"
  end

  def test_direct_equivalent_publications_share_one_nat_rule
    config = publication_snapshot
    results = [ publication_result(config, "tcp/443", "8443"), publication_result(config, "6/00443", "08443") ]

    script = config.definition.generator.new(snapshot: config).perform(results)

    assert_equal 1, script.lines.count { |line| line.include?("destination-translation translated-port") }
    assert_equal 1, script.lines.count { |line| line.match?(/rulebase nat rules .* service "tcp_443"/) }
    assert_includes script, "translated-port 8443"
  end

  def test_migration_does_not_merge_independent_chains_with_unique_numbers
    rules = [ rule(:srx, name: "allow", rule_set: "first", rule_number: 2),
              rule(:srx, name: "deny", rule_set: "second", rule_number: 1, action: "deny") ]

    plan = migration_plan(snapshot(:srx, rules))

    refute plan.ready?
    assert_equal :unknown_order, plan.issues.first.evidence[:code]
    assert_raises(P::Error) { plan.script }
  end

  def test_independent_chains_in_different_zone_pairs_do_not_block_migration
    rules = [ rule(:srx, name: "allow", rule_set: "first", rule_number: 1),
              rule(:srx, name: "deny", rule_set: "second", rule_number: 1, action: "deny", from_zones: "outside", to_zones: "inside") ]

    plan = migration_plan(snapshot(:srx, rules))

    assert plan.ready?, plan.issues.map(&:message).join("; ")
    assert_equal 2, plan.changes.size
  end

  def test_palo_alto_ordinary_ipv4_chain_migrates_but_native_dual_family_any_blocks
    require "algosec/config"
    content = [ [ "security", "allow", "allow" ], [ "default-security-rules", "interzone-default", "deny" ] ].flat_map do |family, name, action|
      { "from" => "inside", "to" => "outside", "source" => "any", "destination" => "any", "service" => "any", "application" => "any", "action" => action }.map do |field, value|
        "set rulebase #{family} rules #{name} #{field} #{value}"
      end
    end.join("\n")
    parsed = Algosec::Config::Parser.perform(content, vendor: :palo_alto, device_id: 1)
    assert parsed.complete?, parsed.diagnostics.map(&:message).join("; ")

    plan = migration_plan(P::Snapshot.from_config(parsed))

    refute plan.ready?
    assert_equal :unsupported_gap, plan.issues.first.evidence[:code]
    assert_raises(P::Error) { plan.script }

    ipv4 = content.gsub(/(source|destination) any$/, '\1 0.0.0.0/0')
    parsed = Algosec::Config::Parser.perform(ipv4, vendor: :palo_alto, device_id: 1)
    assert parsed.complete?, parsed.diagnostics.map(&:message).join("; ")
    source = P::Snapshot.from_config(parsed)
    plan = migration_plan(source)

    assert plan.ready?, plan.issues.map(&:message).join("; ")
    assert_equal [ :permit ], plan.changes.map { |change| change[:decision] }
    assert_equal [ source.rules.find { |rule| rule.name == "allow" }.rule_id ], plan.changes.map { |change| change[:source_rule_id] }
    refute plan.changes.any? { |change| change[:source_rule_id].include?("interzone-default") }
    assert_equal 1, plan.change_set.apply.rules.size
  end

  def test_plans_generate_one_command_frame_per_device
    %i[srx palo_alto fortinet].each do |vendor|
      config = snapshot(vendor, settings: vendor == :fortinet ? { vdom: "tenant" } : {})
      results = %w[tcp/443 tcp/8443].map { |service| new_result(config, services: [ service ]) }
      planner = P::Planner.new(P::Report.new(results: results))

      plan = planner.plans.first

      assert_equal config.definition.generator.new(snapshot: config).perform(results), plan.script
      assert_equal 2, plan.changes.size
      frame = vendor == :fortinet ? "config vdom\n" : "commit\n"
      assert_equal 1, plan.script.lines.count(frame), vendor.to_s
      assert_equal 2, planner.perform.first[:policy_contents].size
    end
  end

  def test_empty_ignored_and_failed_reports_keep_their_plan_contracts
    error = assert_raises(P::Error) { P::Planner.new(P::Report.new).plans }
    assert_equal :incomplete_query, error.code
    assert_raises(P::Error) { P::Planner.new(P::Report.new(error: P::Error.new("failed"))).plans }

    config = snapshot(:srx, [ rule(:srx) ])
    ignored = P::RuleMatcher.new(config).match(group(:srx))
    plans = P::Planner.new(P::Report.new(results: [ ignored ])).plans

    assert_equal 1, plans.size
    assert_empty plans.first.script
    assert_equal [ :ignore ], plans.first.changes.map { |change| change[:operation] }
  end

  def test_late_generation_failure_does_not_return_a_partial_plan
    config = snapshot(:hillstone)
    first = new_result(config)
    invalid = new_result(config, services: [ "tcp/0" ])
    expected = first.definition.build_generator(first).perform

    assert_raises(P::Error) { P::Planner.new(P::Report.new(results: [ first, invalid ])).plans }
    assert_equal expected, P::Planner.new(P::Report.new(results: [ first ])).plans.first.script
  end

  def test_plan_batch_preserves_device_order_and_rejects_mixed_snapshots
    first = snapshot(:srx, device_id: 2)
    second = snapshot(:srx)
    results = [ new_result(first), new_result(second), new_result(first, services: [ "tcp/8443" ]) ]

    plans = P::Planner.new(P::Report.new(results: results)).plans

    assert_equal [ 2, 1 ], plans.map(&:device_id)
    assert_equal [ 2, 1 ], plans.map { |plan| plan.changes.size }
    mixed = [ new_result(second), new_result(snapshot(:srx)) ]
    error = assert_raises(P::Error) { P::Planner.new(P::Report.new(results: mixed)).plans }
    assert_equal :mixed_snapshots, error.code
  end

  def test_plan_and_generator_batches_reject_mixed_explicit_definitions
    config = snapshot(:srx)
    results = 2.times.map { new_result(config, definition: Class.new(config.definition)) }

    state = {}
    generator = results.first.definition.build_generator(results.first, state: state)
    error = assert_raises(P::Error) { generator.perform(results) }
    assert_equal :mixed_definitions, error.code
    assert_empty generator.commands
    assert_empty state
    assert_same results.first, generator.result

    error = assert_raises(P::Error) { P::Planner.new(P::Report.new(results: results)).plans }
    assert_equal :mixed_definitions, error.code
  end

  def test_plan_batch_preserves_a_shared_explicit_definition_and_its_factory_hook
    config = snapshot(:srx)
    definition = Class.new(config.definition)
    calls = []
    definition.define_singleton_method(:build_generator) do |result, state: nil|
      calls << result
      super(result, state: state)
    end
    results = %w[tcp/443 tcp/8443].map { |service| new_result(config, services: [ service ], definition: definition) }

    plan = P::Planner.new(P::Report.new(results: results)).plans.first

    assert_equal 1, calls.size
    assert_same results.first, calls.first
    assert_equal 2, plan.changes.size
    assert_equal 1, plan.script.lines.count("commit\n")
  end

  private

  def service_request(services)
    P::Request.new(sources: [ "10.0.0.1" ], destinations: [ "192.0.2.1" ], services: services)
  end

  def new_result(config, **options)
    attributes = group(config.vendor, device_id: config.device_id, **options)
    members = P::Result::DIMENSIONS.to_h { |dimension| [ dimension, attributes.fetch(dimension).transform_values { nil } ] }
    P::Result.new(**attributes, type: :new, actions: { new: members }, snapshot: config)
  end

  def publication_snapshot
    routes = [
      E::Route.new(**context(:palo_alto), name: "internet", subnet: "0.0.0.0/0", zone: "outside", vrf: "default"),
      E::Route.new(**context(:palo_alto), name: "servers", subnet: "10.0.0.0/24", zone: "inside", vrf: "default")
    ]
    snapshot(:palo_alto, routes)
  end

  # 直接构造 Result，证明生成边界不依赖调用方先经过 Request。
  def publication_result(config, service, translated_port)
    data = group(:palo_alto, from_zone: "outside", to_zone: "inside", sources: [ "198.51.100.9" ], destinations: [ "203.0.113.7" ])
    data[:services] = { service => { origin: service, translated_port: translated_port } }
    members = P::Result::DIMENSIONS.to_h { |dimension| [ dimension, data.fetch(dimension).transform_values { nil } ] }
    members[:nat_destinations] = { "203.0.113.7" => { real_ip: "10.0.0.9", nat: { type: :static, address: "203.0.113.7" } } }
    P::Result.new(**data, type: :new, snapshot: config, actions: { new: members })
  end

  def migration_plan(source)
    P::Migration.new(source: source, target: snapshot(:fortinet, [], device_id: 2),
      zones: { "inside" => "inside", "outside" => "outside" }).perform
  end
end
