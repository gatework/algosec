# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "support/policy_factory"
require_relative "support/connector_fake"

class PolicyGenerationTest < Minitest::Test
  include PolicyFactory

  def new_result(config, **options)
    attributes = group(config.vendor, device_id: config.device_id, **options)
    members = P::Result::DIMENSIONS.to_h { |dimension| [ dimension, attributes.fetch(dimension).transform_values { nil } ] }
    P::Result.new(**attributes, type: :new, actions: { new: members }, snapshot: config)
  end

  def test_perform_accepts_single_result_and_batch_with_the_same_output
    config = snapshot(:srx)
    result = new_result(config)
    generator = config.definition.generator.new(snapshot: config)
    script = config.definition.build_generator(result).perform

    assert_equal script, generator.perform(result)
    assert_equal script, generator.perform([ result ])
    assert_nil generator.result
    assert_raises(ArgumentError) { generator.perform }
    assert_empty generator.commands
  end

  def test_batch_reuses_objects_and_schedule_and_commits_once
    config = snapshot(:srx)
    schedule = E::Schedule.new(**context(:srx), name: "window", start_at: Time.utc(2026, 10, 1), end_at: Time.utc(2026, 10, 2))
    first = new_result(config, schedule: schedule, source_rule_id: "source-1")
    second = new_result(config, schedule: schedule, source_rule_id: "source-2", services: [ "tcp/8443" ])
    generator = config.definition.generator.new(first)
    script = generator.perform([ first, second ])

    assert_equal 1, script.lines.count { |line| line.include?("address-book address Host_10.0.0.1 ") }
    assert_equal 1, script.lines.count { |line| line.start_with?("set schedulers scheduler ") }
    assert_equal 2, script.lines.count { |line| line.end_with?(" then permit\n") }
    assert_equal 1, script.lines.count("commit check\n")
    assert_equal 1, script.lines.count("commit\n")
    assert_same first, generator.result
    assert_equal script, generator.perform([ first, second ])
    assert_equal config.definition.generator.new(first).perform, generator.perform
  end

  def test_vdom_wraps_the_whole_batch_and_empty_batch_has_no_shell
    config = snapshot(:fortinet, settings: { vdom: "tenant" })
    results = [ new_result(config), new_result(config, services: [ "tcp/8443" ]) ]
    generator = config.definition.generator.new(snapshot: config)
    script = generator.perform(results)

    assert_equal 1, script.lines.count("config vdom\n")
    assert_equal 1, script.lines.count("edit \"tenant\"\n")
    assert_equal 2, script.lines.count("edit 0\n")
    assert script.end_with?("next\nend\nend\n")
    assert_nil generator.result
    assert_equal "", generator.perform([])
    assert_empty generator.commands
  end

  def test_late_failure_keeps_committed_state_and_restores_original_result
    config = snapshot(:hillstone)
    state = {}
    existing = new_result(config)
    config.definition.generator.new(existing, state: state).perform
    committed = P::Value.copy(state)
    first = new_result(config, sources: [ "10.0.0.2" ])
    second = new_result(config, sources: [ "10.0.0.3" ], services: [ "tcp/0" ])
    generator = config.definition.generator.new(existing, state: state)

    assert_raises(P::Error) { generator.perform([ first, second ]) }
    assert_empty generator.commands
    assert_equal committed, state
    assert_same existing, generator.result
    script = generator.perform([ first ])
    assert_includes script, 'address "Host_10.0.0.2"'
    refute_includes script, 'address "Host_10.0.0.1"'
    assert_same existing, generator.result
  end

  def test_batch_rejects_results_from_another_snapshot_before_generation
    config = snapshot(:srx)
    first = new_result(config)
    other = new_result(snapshot(:srx))
    state = {}
    generator = config.definition.generator.new(first, state: state)

    [ nil, {}, [ first, other ], [ first, nil ] ].each do |invalid|
      assert_raises(ArgumentError) { generator.perform(invalid) }
      assert_empty generator.commands
      assert_empty state
      assert_same first, generator.result
    end
  end

  def test_shared_allocations_cannot_escape_their_original_snapshot
    original = snapshot(:srx)
    state = {}
    original.definition.build_generator(new_result(original), state: state).perform
    committed = P::Value.copy(state)
    alternatives = [ snapshot(:srx), snapshot(:srx, device_id: 2), snapshot(:palo_alto) ]

    alternatives.each do |config|
      generator = config.definition.build_generator(new_result(config), state: state)
      error = assert_raises(P::Error) { generator.perform }
      assert_equal :mixed_snapshots, error.code
      assert_empty generator.commands
      assert_equal committed, state

      fresh = config.definition.build_generator(new_result(config), state: {}).perform
      assert_match(/set (applications application|service)/, fresh)
    end

    reused = original.definition.build_generator(new_result(original, services: [ "tcp/8443" ]), state: state).perform
    assert_includes reused, "destination-port 8443-8443"
    refute_includes reused, "address-book address Host_10.0.0.1 "
  end

  def test_unbound_legacy_state_cannot_suppress_object_commands
    config = snapshot(:srx)
    state = { commands: { "old command" => true } }
    generator = config.definition.build_generator(new_result(config), state: state)

    error = assert_raises(P::Error) { generator.perform }
    assert_equal :mixed_snapshots, error.code
    assert_equal({ commands: { "old command" => true } }, state)
    assert_empty generator.commands
  end

  def test_generation_state_must_be_a_mutable_hash_or_nil
    config = snapshot(:srx)
    [ false, [], Object.new, {}.freeze ].each do |state|
      assert_raises(ArgumentError) { config.definition.build_generator(new_result(config), state: state) }
    end
  end

  def test_shared_allocations_cannot_cross_generator_implementations
    config = snapshot(:srx)
    state = {}
    original = config.definition.build_generator(new_result(config), state: state)
    original.perform
    committed = P::Value.copy(state)
    custom = Class.new(config.definition.generator)
    generator = custom.new(new_result(config), state: state)

    error = assert_raises(P::Error) { generator.perform }
    assert_equal :mixed_definitions, error.code
    assert_empty generator.commands
    assert_equal committed, state
    assert_includes custom.new(new_result(config), state: {}).perform, "destination-port 443-443"
  end

  def test_generation_publishes_the_snapshot_graph_before_allocating_shared_names
    service = E::ServiceObject.new(**context(:srx), name: "builtin", protocol: "tcp", destination_port: "80")
    config = P::Snapshot.new(**context(:srx), catalog: snapshot(:srx).catalog, builtin_services: [ service ])
    config.definition.build_generator(new_result(config), state: {}).perform

    assert config.catalog.sealed?
    assert service.sealed?
    assert_raises(FrozenError) { config.catalog.add(rule(:srx)) }
    assert_raises(FrozenError) { config.zone("inside").interfaces.clear }
  end

  def test_h3c_ids_are_scoped_to_object_policy_and_canonicalize_existing_numbers
    existing = [ rule(:h3c, name: "00"), rule(:h3c, name: "1", rule_set: "elsewhere", from_zones: "outside", to_zones: "inside") ]
    config = snapshot(:h3c, existing)
    first = new_result(config, source_rule_id: "source-1", sources: [ "10.0.0.1", "10.0.0.2" ])
    second = new_result(config, source_rule_id: "source-2", sources: [ "10.0.0.1", "10.0.0.2" ])
    script = config.definition.generator.new(snapshot: config).perform([ first, second ])

    assert_equal %w[1 2], script.scan(/^rule (\d+) pass /).flatten
    assert_equal %w[1 2], script.scan(/^rule (\d+) append source-ip /).flatten
    assert_equal 1, script.lines.count("sys\n")
    assert_equal 1, script.lines.count("save\n")
  end

  def test_netscreen_ids_are_device_wide_and_additions_use_the_allocated_id
    existing = [ rule(:netscreen, name: "01"), rule(:netscreen, name: "2", from_zones: "outside", to_zones: "inside") ]
    config = snapshot(:netscreen, existing)
    first = new_result(config, source_rule_id: "source-1", services: [ "tcp/443", "udp/53" ])
    second = new_result(config, source_rule_id: "source-2", services: [ "tcp/443", "udp/53" ])
    script = config.definition.generator.new(snapshot: config).perform([ first, second ])

    assert_equal %w[3 4], script.scan(/^set policy id (\d+) top /).flatten
    assert_equal %w[3 4], script.scan(/^set policy id (\d+)$/).flatten
    assert_equal 1, script.lines.count("save\n")
    refute_match(/\bX{3,}\b/, script)
  end

  def test_id_exhaustion_rolls_back_allocations_and_commands_for_the_whole_batch
    config = snapshot(:netscreen)
    limited = Class.new(config.definition.generator) do
      def available_id(kind, key, _range, used)
        super(kind, key, 1..2, used)
      end
    end
    state = {}
    first, second, third = (1..3).map { |id| new_result(config, source_rule_id: "source-#{id}") }
    limited.new(first, state: state).perform
    committed = P::Value.copy(state)
    generator = limited.new(snapshot: config, state: state)

    assert_raises(P::Error) { generator.perform([ second, third ]) }
    assert_equal committed, state
    assert_empty generator.commands
    assert_nil generator.result
    assert_includes generator.perform([ second ]), "set policy id 2 top "
  end

  def test_numbered_scripts_execute_without_discovering_ids_from_device_responses
    { h3c: "[fw]", netscreen: "fw->" }.each do |vendor, prompt|
      settings = (vendor == :h3c) ? { policy_bindings: [ { name: "objects", from_zone: "inside", to_zone: "outside" } ] } : {}
      config = snapshot(vendor, settings: settings)
      result = new_result(config, sources: [ "10.0.0.1", "10.0.0.2" ], services: [ "tcp/443", "udp/53" ])
      script = config.definition.generator.new(result).perform
      transport = ConnectorFake.new(prompt, *script.lines.map { |line| "#{line}#{prompt}" })
      device = Algosec::Connector.build(vendor, host: "192.0.2.1", transport: transport)
      executed = device.execute_script(Net::Connector::Script.parse(script))

      assert executed.success?, executed.error&.message
      assert_equal script.lines, transport.writes, vendor.to_s
      assert_equal script.lines.size, executed.steps.size
      assert_equal 1, transport.opens
      device.close
      assert_equal 1, transport.closes
    ensure
      device&.close
    end
  end
end
