# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "support/policy_factory"

class FortinetVipGenerationTest < Minitest::Test
  include PolicyFactory

  def publication(config, external: "203.0.113.1", internal: "10.0.0.1", interface: "inside", protocol: "tcp", port: nil, target_port: port)
    record = { origin: internal, real_ip: internal, action: :new_nat,
      nat: { type: :static, address: external, interface: interface } }
    services = port ? [ { services: [ "#{protocol}/#{port}" ], translated_port: target_port } ] : [ "tcp/443" ]
    P::RuleMatcher.new(config).match(group(:fortinet, services: services).merge(destinations: { external => record }))
  end

  def assert_conflict(config, first, second)
    state = {}
    config.definition.build_generator(first, state: state).perform
    committed = P::Value.copy(state)
    generator = config.definition.build_generator(second, state: state)

    error = assert_raises(P::Error) { generator.perform }
    assert_equal :nat_scope_conflict, error.code
    assert_equal committed, state
    assert_empty generator.commands
    repeated = config.definition.build_generator(first, state: state).perform
    refute_includes repeated, "config firewall vip"

    batch = config.definition.generator.new(snapshot: config, state: {})
    assert_raises(P::Error) { batch.render([ first, second ]) }
    assert_empty batch.commands
  end

  def test_same_external_port_cannot_be_assigned_two_internal_ports
    config = snapshot(:fortinet)
    first, second = [ 8443, 9443 ].map { |port| publication(config, port: 443, target_port: port) }
    assert_conflict(config, first, second)
  end

  def test_vip_names_reserve_existing_addresses_and_groups
    preferred = "vip203.0.113.1_inside"
    objects = [ E::AddressObject.new(**context(:fortinet), name: preferred, member: [ { type: "host", value: "10.9.9.9" } ]),
      E::AddressGroup.new(**context(:fortinet), name: preferred) ]
    objects.each do |existing|
      config = snapshot(:fortinet, [ existing ])
      result = publication(config)
      script = config.definition.build_generator(result).render

      assert_equal [ "#{preferred}_2" ], script.entries.sole.references[:destinations], existing.class.name
      assert_includes script.text, "set dstaddr \"#{preferred}_2\""
    end
  end

  def test_partially_overlapping_external_ranges_require_the_same_translation
    [ false, true ].each do |reverse|
      config = snapshot(:fortinet)
      pair = [ publication(config, external: "203.0.113.0/24", internal: "10.0.0.0/24"),
        publication(config, external: "203.0.113.9", internal: "10.1.0.9") ]
      pair.reverse! if reverse
      assert_conflict(config, *pair)
    end
  end

  def test_wildcard_interface_and_full_protocol_mapping_participate_in_overlap
    config = snapshot(:fortinet)
    assert_conflict(config, publication(config, interface: "any"), publication(config, internal: "10.0.0.2"))
    config = snapshot(:fortinet)
    assert_conflict(config, publication(config), publication(config, port: 443, target_port: 8443))
  end

  def test_interface_comparison_uses_the_emitted_text
    [ [ "inside", :inside ], [ :any, "inside" ], [ "inside", :any ] ].each do |left, right|
      config = snapshot(:fortinet)
      assert_conflict(config, publication(config, interface: left), publication(config, interface: right, internal: "10.0.0.2"))
    end
  end

  def test_equivalent_interface_forms_reuse_the_same_vip
    config = snapshot(:fortinet)
    state = {}
    first = config.definition.build_generator(publication(config), state: state).render
    repeated = config.definition.build_generator(publication(config, interface: :inside), state: state).render

    assert_equal first.entries.sole.references, repeated.entries.sole.references
    refute_includes repeated.text, "config firewall vip"
  end

  def test_disjoint_matches_and_equal_translation_on_the_overlap_remain_available
    pairs = [
      [ { port: 443, target_port: 8443 }, { port: 443, target_port: 9443, protocol: "udp" } ],
      [ { port: 443, target_port: 8443 }, { port: 444, target_port: 9443 } ],
      [ { interface: "inside" }, { interface: "outside", internal: "10.0.0.2" } ],
      [ {}, { external: "203.0.113.2", internal: "10.0.0.2" } ],
      [ { external: "203.0.113.0/24", internal: "10.0.0.0/24" }, { external: "203.0.113.9", internal: "10.0.0.9" } ],
      [ {}, { port: 443, target_port: 443 } ]
    ]
    pairs.each do |left, right|
      config = snapshot(:fortinet)
      results = [ left, right ].map { |options| publication(config, **options) }
      script = config.definition.generator.new(snapshot: config).render(results).text
      assert_equal 2, script.scan("config firewall vip").size, [ left, right ].inspect
      refute P::Planner.new(P::Report.new(results: results)).plans.sole.executable?, "VIP allocation is not NAT effect proof"
    end
  end
end
