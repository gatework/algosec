# frozen_string_literal: true

require "minitest/autorun"
require "algosec"

class ElementsReferenceTest < Minitest::Test
  E = Algosec::Elements

  def test_rule_exposes_its_current_dependencies_through_the_element_protocol
    rule = E::SecurityRule.new(name: "allow")
    schedule = E::Schedule.new(name: "window", end_at: Time.utc(2030))

    assert_equal [ rule.sources, rule.destinations, rule.services ], rule.dependencies
    rule.schedule = schedule
    assert_equal [ rule.sources, rule.destinations, rule.services, schedule ], rule.dependencies
    rule.schedule = nil
    refute_includes rule.dependencies, schedule
  end

  def test_static_nat_resolves_objects_and_schedule_in_its_match_rule
    address = E::AddressObject.new(name: "client", member: [ { type: "host", value: "192.0.2.1" } ])
    service = E::ServiceObject.new(name: "https", protocol: "tcp", destination_port: "443")
    schedule = E::Schedule.new(name: "window", end_at: Time.utc(2030))
    rule = E::SecurityRule.new(name: "nat-match", schedule_name: "window",
      sources: E::AddressGroup.new(name: "sources", members: { "client" => nil }),
      services: E::ServiceGroup.new(name: "services", members: { "https" => nil }))
    nat = E::StaticNat.new(name: "mapping", real_ip: "10.0.0.1", mapped_ip: "192.0.2.1", match_rule: rule)

    E::Catalog.new([ nat, address, service, schedule ]).resolve!

    assert_same address, rule.sources.members.fetch("client")
    assert_same service, rule.services.members.fetch("https")
    assert_same schedule, rule.schedule
  end

  def test_dynamic_nat_resolves_service_dependencies_outside_the_catalog
    service = E::ServiceObject.new(name: "https", protocol: "tcp", destination_port: "443")
    group = E::ServiceGroup.new(name: "nat-service", members: { "https" => nil })
    nat = E::DynamicNat.new(id: "nat", direction: :source, service: group)

    E::Catalog.new([ nat, service ]).resolve!

    assert_same service, group.members.fetch("https")
    assert_equal Algosec::Set.new(393659..393659), group.set
  end

  def test_missing_nat_dependency_aborts_before_committing_any_references
    address = E::AddressObject.new(name: "client", member: [ { type: "host", value: "192.0.2.1" } ])
    first = E::AddressGroup.new(name: "first", members: { "client" => nil })
    rule = E::SecurityRule.new(name: "nat-match", sources: E::AddressGroup.new(name: "sources", members: { "missing" => nil }))
    nat = E::DynamicNat.new(id: "nat", direction: :source, match_rule: rule)
    catalog = E::Catalog.new([ first, address, nat ])

    assert_raises(E::Group::UnresolvedReference) { catalog.resolve! }
    assert_nil first.members.fetch("client")
    assert_nil rule.sources.members.fetch("missing")
  end

  def test_permissive_nat_resolution_keeps_missing_dependencies_explicit
    service = E::ServiceObject.new(name: "https", protocol: "tcp", destination_port: "443")
    group = E::ServiceGroup.new(name: "nat-service", members: { "https" => nil, "missing" => nil })
    nat = E::DynamicNat.new(id: "nat", direction: :source, service: group)
    missing = []

    E::Catalog.new([ nat, service ]).resolve!(strict: false, on_missing: ->(owner, name) { missing << [ owner, name ] })

    assert_same service, group.members.fetch("https")
    assert_nil group.members.fetch("missing")
    assert_equal [ [ group, "missing" ] ], missing
    refute group.resolved?
    assert_raises(E::Group::UnresolvedReference) { group.set }
  end

  def test_direct_references_reject_another_vendor_even_with_the_same_device_id
    group = E::AddressGroup.new(name: "group", vendor: :fortinet, device_id: 1)
    address = E::AddressObject.new(name: "host", vendor: :asa, device_id: 1)
    assert_raises(ArgumentError) { group.add("host", address) }
    assert_empty group.members

    rule = E::SecurityRule.new(native_rule_id: "1", vendor: :fortinet, device_id: 1)
    schedule = E::Schedule.new(name: "window", vendor: :asa, device_id: 1, end_at: Time.utc(2030))
    assert_raises(ArgumentError) { rule.schedule = schedule }
    assert_nil rule.schedule
  end

  def test_external_resolver_rejects_another_vendor_before_any_reference_is_committed
    first = E::AddressGroup.new(name: "first", vendor: :fortinet, members: { "local" => nil })
    last = E::AddressGroup.new(name: "last", vendor: :fortinet, members: { "foreign" => nil })
    local = E::AddressObject.new(name: "local", vendor: :fortinet)
    foreign = E::AddressObject.new(name: "foreign", vendor: :asa)
    catalog = E::Catalog.new([ first, last ], vendor: :fortinet)

    error = assert_raises(ArgumentError) do
      catalog.resolve! { |_owner, name, _types| name == "local" ? local : foreign }
    end

    assert_match(/vendor/, error.message)
    assert_nil first.members.fetch("local")
    assert_nil last.members.fetch("foreign")
  end

  def test_parser_clones_generic_builtin_services_into_the_device_context
    template = E::ServiceObject.new(name: "HTTP", terms: [ { protocol: "tcp", destination_port: "80" } ])
    result = Algosec::Config::Parser.perform(<<~CONFIG, vendor: :fortinet, device_id: 1, builtin_services: { "HTTP" => template })
      config firewall service group
       edit web
        set member HTTP
       next
      end
    CONFIG
    service = result.find(E::ServiceGroup, name: "web").members.fetch("HTTP")

    assert result.complete?, result.diagnostics.inspect
    assert_equal :fortinet, service.vendor
    assert_equal 1, service.device_id
    assert_equal :generic, template.vendor
    refute_same template, service
  end

  def test_once_schedule_without_a_complete_window_remains_unknown
    result = Algosec::Config::Parser.perform(<<~CONFIG, vendor: :fortinet, device_id: 1)
      config firewall schedule onetime
       edit incomplete
       next
      end
    CONFIG
    schedule = result.find(E::Schedule, name: "incomplete")

    refute schedule.resolved?
    refute schedule.expired?(at: Time.utc(2030))
    assert_raises(ArgumentError) { schedule.active?(at: Time.utc(2026)) }
    refute E::Schedule.new(name: "start-only", start_at: Time.utc(2026)).resolved?
  end

  def test_empty_weekly_and_supported_end_only_schedules_keep_their_semantics
    weekly = E::Schedule.new(name: "empty", kind: :weekly)
    assert weekly.resolved?
    refute weekly.active?(at: Time.utc(2026))

    once = E::Schedule.new(name: "end-only", vendor: :asa, end_at: Time.utc(2030))
    assert once.resolved?
    assert once.active?(at: Time.utc(2026))
    assert once.expired?(at: Time.utc(2031))
  end
end
