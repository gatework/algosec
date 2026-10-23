# frozen_string_literal: true

require "test_helper"
require_relative "../framework/support/policy_factory"
require "algosec/policy/generator"

class GeneratedRuleSemanticsTest < Minitest::Test
  include PolicyFactory

  def test_modification_preserves_group_type_scope_and_service_attributes
    scope = E::Scope.new(device_id: 1, virtual_system: "vsys1", address_book: "shared")
    excluded = E::AddressObject.new(**context(:palo_alto), name: "excluded", member: [ { type: "host", value: "10.0.0.1" } ])
    sources = E::AddressGroup::Negated.new(**context(:palo_alto), scope: scope, zone: "inside", name: "excluded-sources",
      config: "source declaration", members: { "excluded" => excluded })
    service = E::ServiceObject.new(**context(:palo_alto), name: "https", protocol: "tcp", destination_port: "443")
    services = E::ServiceGroup.new(**context(:palo_alto), scope: scope, name: "tcp-services", protocol: "tcp", members: { "https" => service })
    entry = E::SecurityRule.new(**context(:palo_alto), name: "allow-rest", sources: sources, services: services)
    current = snapshot(:palo_alto, [ entry ])
    current.catalog.seal!
    maps = group(:palo_alto, sources: [ "10.0.0.2" ], services: [ "tcp/8443" ])
    additions = maps.slice(:sources, :services).transform_values { |members| members.transform_values { nil } }
    result = P::Result.new(**maps, type: :modify, actions: { add: additions }, rule: entry, snapshot: current)

    updated = P::Generator::Rule.new(current, result).modify

    assert_instance_of E::AddressGroup::Negated, updated.sources
    assert_equal sources.scope, updated.sources.scope
    assert_equal sources.name, updated.sources.name
    assert_equal sources.zone, updated.sources.zone
    assert_equal sources.config, updated.sources.config
    refute updated.sources.set.include?(Algosec::IPAddr.to_i("10.0.0.1"))
    refute updated.sources.set.include?(Algosec::IPAddr.to_i("10.0.0.2"))
    assert updated.sources.set.include?(Algosec::IPAddr.to_i("10.0.0.3"))
    assert sources.set.include?(Algosec::IPAddr.to_i("10.0.0.2"))
    assert_equal [ "excluded" ], sources.members.keys
    assert_same excluded, updated.sources.members.fetch("excluded")
    assert_equal services.scope, updated.services.scope
    assert_equal services.name, updated.services.name
    assert_equal "tcp", updated.services.protocol
    assert_equal [ "https" ], services.members.keys
    assert_equal 2, updated.services.members.size
    assert updated.sealed?
    assert_same entry.destinations, updated.destinations
  end
end
