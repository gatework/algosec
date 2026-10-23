# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "support/policy_factory"
require_relative "support/policy_config"

class GenerationNamespaceTest < Minitest::Test
  include PolicyFactory
  include PolicyConfig

  SERVICE_NAMES = { palo_alto: "tcp_443", fortinet: "443", hillstone: "TCP_443", srx: "TCP_443",
    netscreen: "443", huawei: "TCP_443", topsec: "TCP_443", neteye: "TCP_443", h3c: "TCP_443" }.freeze

  def config(vendor, objects = [], builtins: [])
    settings = vendor == :h3c ? { policy_bindings: [ { name: "objects", from_zone: "inside", to_zone: "outside" } ] } : {}
    base = snapshot(vendor, objects, settings: settings)
    P::Snapshot.new(**context(vendor), catalog: base.catalog, settings: settings, builtin_services: builtins)
  end

  def render(current, **options)
    result = P::RuleMatcher.new(current).match(group(current.vendor, **options))
    current.definition.build_generator(result).render
  end

  SERVICE_NAMES.each do |vendor, preferred|
    define_method("test_#{vendor}_service_group_names_are_reserved") do
      leaf = E::ServiceObject.new(**context(vendor), name: "legacy_dns", protocol: "udp", destination_port: "53")
      existing = E::ServiceGroup.new(**context(vendor), name: preferred)
      existing.add(leaf.name, leaf)
      script = render(config(vendor, [ leaf, existing ]))

      assert_equal [ "#{preferred}_2" ], script.entries.sole.references[:services]
      assert_includes script.text, "#{preferred}_2"
      assert_equal [ [ leaf.name, leaf ] ], existing.to_a
    end

    define_method("test_#{vendor}_external_builtin_names_are_reserved") do
      existing = E::ServiceObject.new(**context(vendor), name: preferred, protocol: "udp", destination_port: "53")
      script = render(config(vendor, builtins: [ existing ]))

      assert_equal [ "#{preferred}_2" ], script.entries.sole.references[:services]
      assert_includes script.text, "#{preferred}_2"
      assert_equal "udp", existing.terms.sole.fetch(:protocol)
    end
  end

  def test_pan_address_group_name_cannot_be_reused_for_a_new_address
    leaf = E::AddressObject.new(**context(:palo_alto), name: "legacy", member: [ { type: "host", value: "10.9.9.9" } ])
    existing = E::AddressGroup.new(**context(:palo_alto), name: "addr_10.0.0.1/32")
    existing.add(leaf.name, leaf)
    script = render(config(:palo_alto, [ leaf, existing ]))

    assert_equal [ "addr_10.0.0.1/32_2" ], script.entries.sole.references[:sources]
    assert_includes script.text, 'set address "addr_10.0.0.1/32_2" ip-netmask 10.0.0.1/32'
    assert_equal Algosec::IPAddr.parse("10.9.9.9"), existing.resolved_set
  end

  def test_pan_service_group_references_keep_their_meaning_after_generated_commands
    original = <<~CONFIG
      set service dns protocol udp port 53
      set service-group tcp_443 members dns
      set address old_source ip-netmask 10.9.9.9/32
      set rulebase security rules preserve from inside
      set rulebase security rules preserve to outside
      set rulebase security rules preserve source old_source
      set rulebase security rules preserve destination any
      set rulebase security rules preserve service tcp_443
      set rulebase security rules preserve application any
      set rulebase security rules preserve action allow
    CONFIG
    parsed = Algosec::Config::Parser.perform(original, vendor: :palo_alto, device_id: 1)
    assert parsed.complete?, parsed.diagnostics.inspect
    current = P::Snapshot.from_config(parsed)
    result = P::RuleMatcher.new(current).match(group(:palo_alto))
    plan = P::Planner.new(P::Report.new(results: [ result ])).plans.sole
    assert plan.executable?, plan.issues.map(&:message).join("; ")

    readback = Algosec::Config::Parser.perform(original + saved_config(:palo_alto, plan.script), vendor: :palo_alto, device_id: 1)
    assert readback.complete?, readback.diagnostics.inspect
    retained = readback.elements(E::SecurityRule).find { |entry| entry.name == "preserve" }
    assert_equal P::Ranges.service("udp/53"), P::Ranges.rule_services(retained)
    assert plan.verify_readback(P::Snapshot.from_config(readback)).verified?
  end

  def test_address_book_collisions_respect_the_selected_zone
    { srx: "Host_10.0.0.1", netscreen: "10.0.0.1/32" }.each do |vendor, preferred|
      [ "inside", "outside", vendor == :srx ? "global" : "Global" ].each do |zone|
        leaf = E::AddressObject.new(**context(vendor), name: "legacy", zone: zone, member: [ { type: "host", value: "10.9.9.9" } ])
        existing = E::AddressGroup.new(**context(vendor), name: preferred, zone: zone)
        existing.add(leaf.name, leaf)
        script = render(config(vendor, [ leaf, existing ]))

        assert_equal [ zone == "outside" ? preferred : "#{preferred}_2" ], script.entries.sole.references[:sources]
        assert_equal Algosec::IPAddr.parse("10.9.9.9"), existing.resolved_set
      end
    end
  end

  def test_new_local_addresses_do_not_shadow_global_references_in_old_rules
    originals = {
      srx: <<~CONFIG,
        set security address-book global address Host_10.0.0.1 10.9.9.9/32
        set applications application dns protocol udp
        set applications application dns destination-port 53
        set security policies from-zone inside to-zone outside policy preserve match source-address Host_10.0.0.1
        set security policies from-zone inside to-zone outside policy preserve match destination-address any
        set security policies from-zone inside to-zone outside policy preserve match application dns
        set security policies from-zone inside to-zone outside policy preserve then permit
      CONFIG
      netscreen: <<~CONFIG
        set address "Global" "10.0.0.1/32" 10.9.9.9 255.255.255.255
        set service "dns" protocol udp src-port 0-65535 dst-port 53-53
        set policy id 1 from "inside" to "outside" "10.0.0.1/32" "any" "dns" permit
      CONFIG
    }
    originals.each do |vendor, original|
      parsed = Algosec::Config::Parser.perform(original, vendor: vendor, device_id: 1)
      assert parsed.complete?, parsed.diagnostics.inspect
      current = P::Snapshot.from_config(parsed)
      retained_id = current.rules.sole.rule_id
      expected = P::Ranges.rule_addresses(current.rules.sole.sources)
      assert_equal Algosec::IPAddr.parse("10.9.9.9"), expected
      result = P::RuleMatcher.new(current).match(group(vendor))
      plan = P::Planner.new(P::Report.new(results: [ result ])).plans.sole
      assert plan.executable?, plan.issues.map(&:message).join("; ")

      readback = Algosec::Config::Parser.perform(original + saved_config(vendor, plan.script), vendor: vendor, device_id: 1)
      assert readback.complete?, readback.diagnostics.inspect
      actual = P::Snapshot.from_config(readback)
      retained = actual.rules.find { |entry| entry.rule_id == retained_id }
      assert_equal expected, P::Ranges.rule_addresses(retained.sources), vendor.to_s
      assert plan.verify_readback(actual).verified?, vendor.to_s
    end
  end

  def test_generated_range_group_avoids_existing_addresses
    current = config(:netscreen)
    preferred = render(current, sources: [ "10.0.0.1-10.0.0.3" ]).entries.sole.references[:sources].sole
    existing = E::AddressObject.new(**context(:netscreen), name: preferred, zone: "inside", member: [ { type: "host", value: "10.9.9.9" } ])
    script = render(config(:netscreen, [ existing ]), sources: [ "10.0.0.1-10.0.0.3" ])

    assert_equal [ "#{preferred}_2" ], script.entries.sole.references[:sources]
    assert_includes script.text, "set group address \"inside\" \"#{preferred}_2\""
    assert_equal Algosec::IPAddr.parse("10.9.9.9"), existing.resolved_set
  end

  def test_asa_network_groups_reserve_address_and_service_object_names
    sources = %w[10.0.0.1 10.0.0.3 10.0.0.5 10.0.0.7]
    preferred = render(config(:asa), sources: sources).entries.sole.references[:sources].sole.delete_prefix("object-group ")
    objects = [
      E::AddressObject.new(**context(:asa), name: preferred, member: [ { type: "host", value: "10.9.9.9" } ]),
      E::ServiceObject.new(**context(:asa), name: preferred, protocol: "udp", destination_port: "53"),
      E::ServiceGroup.new(**context(:asa), name: preferred)
    ]
    objects.each do |existing|
      script = render(config(:asa, [ existing ]), sources: sources)
      assert_equal [ "object-group #{preferred}_2" ], script.entries.sole.references[:sources], existing.class.name
      assert_includes script.text, "object-group network #{preferred}_2"
    end
    script = render(config(:asa, builtins: [ objects[1] ]), sources: sources)
    assert_equal [ "object-group #{preferred}_2" ], script.entries.sole.references[:sources]
  end

  def test_asa_network_objects_reserve_service_names
    preferred = "range_10.0.0.1-10.0.0.3"
    objects = [ E::ServiceObject.new(**context(:asa), name: preferred, protocol: "udp", destination_port: "53"),
      E::ServiceGroup.new(**context(:asa), name: preferred) ]
    objects.each do |existing|
      script = render(snapshot(:asa, [ existing ], version: "9.12"), sources: [ "10.0.0.1-10.0.0.3" ])
      assert_equal [ "object #{preferred}_2" ], script.entries.sole.references[:sources], existing.class.name
      assert_includes script.text, "object network #{preferred}_2"
    end
  end

  def test_fortinet_addresses_reserve_vip_names
    vip = E::StaticNat.new(**context(:fortinet), name: "10.0.0.1/32", real_ip: "10.9.9.9", mapped_ip: "203.0.113.9", interface: "outside")
    script = render(config(:fortinet, [ vip ]))

    assert_equal [ "10.0.0.1/32_2" ], script.entries.sole.references[:sources]
    assert_includes script.text, 'edit "10.0.0.1/32_2"'
    assert_equal Algosec::IPAddr.parse("10.9.9.9"), vip.real_set
  end

  def test_mixed_service_names_and_committed_allocations_keep_one_stable_reference
    vendor = :hillstone
    leaf = E::ServiceObject.new(**context(vendor), name: "TCP_443_3", protocol: "udp", destination_port: "53")
    aggregate = E::ServiceGroup.new(**context(vendor), name: "TCP_443", members: { leaf.name => leaf })
    builtin = E::ServiceObject.new(**context(vendor), name: "TCP_443_2", protocol: "udp", destination_port: "53")
    current = config(vendor, [ leaf, aggregate ], builtins: [ builtin ])
    result = P::RuleMatcher.new(current).match(group(vendor))
    state = {}
    first = current.definition.build_generator(result, state: state).render
    repeated = current.definition.build_generator(result, state: state).render

    assert_equal [ "TCP_443_4" ], first.entries.sole.references[:services]
    assert_equal first.entries.sole.references, repeated.entries.sole.references
    assert_includes first.text, "tcp dst-port 443"
    refute_includes repeated.text, "tcp dst-port 443"
    assert_includes repeated.text, 'service "TCP_443_4"'
  end
end
