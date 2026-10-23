# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "support/policy_factory"

class PolicyScriptTest < Minitest::Test
  include PolicyFactory

  def test_preview_uses_the_allocated_name_and_reuses_one_generated_batch_for_plans
    address = E::AddressObject.new(**context(:hillstone), name: "Host_10.0.0.1",
      member: [ { type: "subnet", value: "10.9.9.9/32" } ])
    config = snapshot(:hillstone, [ address ])
    definition = Class.new(config.definition)
    calls = []
    definition.define_singleton_method(:build_generator) do |result, state: nil|
      calls << result
      super(result, state: state)
    end
    results = %w[tcp/443 tcp/8443].map { |service| new_result(config, services: [ service ], definition: definition) }
    planner = P::Planner.new(P::Report.new(results: results))

    contents = planner.perform.sole.fetch(:policy_contents)
    assert_equal "Host_10.0.0.1_2", contents.first.fetch(:new).fetch(:sources)
    assert_equal "Host_10.0.0.1_2", contents.last.fetch(:new).fetch(:sources)
    assert_includes contents.first.fetch(:new).fetch(:content), 'src-addr "Host_10.0.0.1_2"'
    script = planner.plans.sole.script
    assert_equal 1, calls.size
    assert_equal 1, script.lines.count("configure\n")
    assert_equal 1, script.lines.count("save\n")
    assert_equal 1, script.scan('address "Host_10.0.0.1_2"').size
  end

  def test_render_keeps_result_mapping_and_real_references_after_object_reuse
    config = snapshot(:fortinet, settings: { vdom: "tenant" })
    results = [ new_result(config), new_result(config, services: [ "tcp/8443" ]) ]
    script = config.definition.build_generator(results.first).render(results)

    assert_equal results, script.entries.map(&:result)
    assert_equal [ "10.0.0.1/32" ], script.entries.first.references.fetch(:sources)
    assert_equal [ "443" ], script.entries.first.references.fetch(:services)
    assert_equal [ "8443" ], script.entries.last.references.fetch(:services)
    assert_equal 1, script.text.lines.count("config vdom\n")
    assert_equal 1, script.entries.last.text.lines.count("config vdom\n")
    refute_includes script.entries.last.text, "config firewall address\n"
    assert_raises(FrozenError) { script.entries.first.references[:sources] << "changed" }
    assert_raises(FrozenError) { script.entries.first.text << "changed" }
  end

  def test_late_render_failure_keeps_prior_output_and_shared_state_intact
    config = snapshot(:hillstone)
    first = new_result(config)
    state = {}
    generator = config.definition.build_generator(first, state: state)
    prior = generator.render
    saved_state = P::Value.copy(state)
    bad = new_result(config, services: [ "tcp/0" ])

    assert_raises(P::Error) { generator.render([ first, bad ]) }
    assert_empty generator.commands
    assert_equal saved_state, state
    assert_includes prior.text, 'src-addr "Host_10.0.0.1"'
    assert_equal [ "Host_10.0.0.1" ], prior.entries.sole.references.fetch(:sources)
    refute_includes generator.render(first).text, 'address "Host_10.0.0.1"'
  end

  def test_inline_vendor_arguments_are_preserved_in_preview
    {
      asa: { sources: "host 10.0.0.1", services: "tcp eq 443" },
      huawei: { sources: "10.0.0.1 32", services: "TCP_443" }
    }.each do |vendor, expected|
      result = new_result(snapshot(vendor))
      generated = P::Planner.new(P::Report.new(results: [ result ])).perform.sole[:policy_contents].sole.fetch(:new)
      expected.each { |dimension, value| assert_equal value, generated.fetch(dimension) }
    end
  end

  private

  def new_result(config, **options)
    fields = group(config.vendor, **options)
    members = P::Result::DIMENSIONS.to_h { |dimension| [ dimension, fields.fetch(dimension).transform_values { nil } ] }
    P::Result.new(**fields, type: :new, actions: { new: members }, snapshot: config)
  end
end
