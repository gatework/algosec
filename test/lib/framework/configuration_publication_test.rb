# frozen_string_literal: true

require_relative "../../test_helper"
require "active_support/cache"
require "tmpdir"
require "json"

class ConfigurationPublicationTest < Minitest::Test
  E = Algosec::Elements

  def parse(content = configuration, **options)
    Algosec::Config::Parser.perform(content, vendor: :hillstone, device_id: 1, **options)
  end

  def configuration
    "address host\n ip 192.0.2.1/32\nexit\nrule id 1\n action permit\n src-addr host\nexit\n"
  end

  def test_published_rules_addresses_and_catalog_cannot_change_the_source_graph
    result = parse.bind_source!("version-1")
    rule = result.rules.first
    address = result.find(E::AddressObject, name: "host")

    assert_raises(FrozenError) { rule.action = "deny" }
    assert_raises(FrozenError) { rule.sources.delete("host") }
    assert_raises(FrozenError) { rule.sources.add("other", address) }
    assert_raises(FrozenError) { address.add(type: "host", value: "192.0.2.2") }
    assert_raises(FrozenError) { result.catalog.add(E::AddressObject.new(name: "other", vendor: :hillstone)) }
    assert_raises(FrozenError) { rule.replace_config("private-change") }
    assert_equal "allow", rule.action
    assert_equal "version-1", result.source_key
    assert_same result, result.bind_source!("version-1")
    assert_raises(ArgumentError) { result.bind_source!("version-2") }
  end

  def test_unpublished_drafts_remain_mutable_until_explicitly_sealed
    address = E::AddressObject.new(name: "host")
    group = E::AddressGroup.new(name: "group", members: { "host" => address })
    rule = E::SecurityRule.new(name: "rule", sources: group)
    address.add(type: "host", value: "192.0.2.1")
    rule.action = "deny"
    refute rule.sealed?
    assert_equal "deny", rule.action
    assert_same rule, rule.seal!
    assert rule.sealed?
    assert address.sealed?
    assert_raises(FrozenError) { group.delete("host") }
  end

  def test_network_children_outside_the_catalog_are_sealed_without_freezing_definition_or_time_zone
    definition = Class.new(E::Definition)
    zone = Time.find_zone!("UTC")
    route = E::Route.new(subnet: "198.51.100.0/24", definition: definition)
    child = E::Interface.new(name: "vlan1", mode: :layer3, routes: [ route ], definition: definition)
    interface = E::Interface.new(name: "parent", definition: definition)
    interface.add_vlan(child)
    network = E::Zone.new(name: "inside", interfaces: [ interface ], definition: definition)
    network.seal!

    assert_raises(FrozenError) { child.add_route(E::Route.new(subnet: "203.0.113.0/24")) }
    assert_raises(FrozenError) { interface.add_vlan(E::Interface.new(name: "vlan2")) }
    assert_raises(FrozenError) { route.replace_config("changed") }
    refute definition.frozen?
    refute zone.frozen?
  end

  def test_constructor_inputs_remain_independent_of_owned_element_values
    name, type, value, description, config = [ +"host", +"host", +"192.0.2.1", +"description", +"private-config" ]
    members = [ { type: type, value: value } ]
    address = E::AddressObject.new(name: name, member: members, description: description, config: config)
    address.seal!

    refute type.frozen?
    [ name, type, value, description, config ].each { |input| input.replace("changed") }
    members.clear
    assert_equal "host", address.name
    assert_equal [ { "type" => "host", "value" => "192.0.2.1" } ], address.member
    assert_equal "description", address.description
    assert_equal "private-config", address.config
  end

  def test_dns_answers_and_context_are_owned_and_cannot_be_updated_after_publication
    answer = { "status" => +"resolved", "addresses" => [ +"192.0.2.1" ], "expires_at" => +"2030-01-01T00:00:00Z" }
    context = { "servers" => [ +"192.0.2.53" ] }
    resolver = Object.new
    resolver.define_singleton_method(:resolve) { |_name| answer }
    resolver.define_singleton_method(:context) { context }
    result = parse("address domain\n host example.test\nexit\n", dns_resolver: resolver)
    address = result.find(E::AddressObject, name: "domain")
    answer["addresses"].first.replace("203.0.113.1")
    context["servers"].clear

    assert_equal [ "192.0.2.1" ], address.dns_answers.fetch("example.test").fetch("addresses")
    assert_equal [ "192.0.2.53" ], result.dns_context.fetch("servers")
    assert_raises(FrozenError) { address.resolve_domains!(resolver) }
    assert_raises(FrozenError) { address.dns_answers.fetch("example.test").fetch("addresses").clear }
  end

  def test_diagnostics_are_owned_and_generic_summaries_do_not_disclose_raw_text
    secret = +"private-secret-material"
    diagnostic = Algosec::Config::Diagnostic.new(:unsupported_command, secret, 1)
    diagnostics = [ diagnostic ]
    result = Algosec::Config::Result.new(reader: Algosec::Config::Reader.new(secret, vendor: :hillstone),
      catalog: E::Catalog.new([ E::AddressObject.new(name: "a", config: secret) ]), diagnostics: diagnostics, at: Time.current)
    secret.replace("changed")
    refute diagnostics.frozen?
    diagnostics.clear

    refute result.complete?
    assert_equal "private-secret-material", result.diagnostics.first.message
    [ result, result.reader, result.catalog, result.catalog.first, result.diagnostics.first ].each do |object|
      refute_includes object.inspect, "private-secret-material"
      refute_includes JSON.generate(object.as_json), "private-secret-material"
    end
    assert_equal "private-secret-material", result.diagnostics.first.to_h.fetch(:message)
    assert_equal "private-secret-material", result.reader.content
  end

  def test_reader_cursor_reuse_does_not_change_published_evidence
    borrowed = Algosec::Config::Reader.new(configuration + "private-unknown\n", vendor: :hillstone, device_id: 1, source_complete: false)
    result = parse(borrowed)
    flags = result.reader.parsed_flags
    unparsed = result.unparsed_lines
    borrowed.reset!
    result.reader.cursor.reset!
    assert_equal flags, result.reader.parsed_flags
    assert_equal unparsed, result.unparsed_lines
    reparsed = parse(result.reader)

    assert_equal flags, result.reader.parsed_flags
    assert_equal unparsed, result.unparsed_lines
    refute result.complete?
    refute reparsed.complete?
    refute_same borrowed, result.reader
    refute_same result.reader, reparsed.reader
  end

  def test_cache_restores_sealed_containers_reader_evidence_and_shared_references
    [ ActiveSupport::Cache::MemoryStore.new, nil ].each do |store|
      Dir.mktmpdir("publication-cache-") do |directory|
        cache = Algosec::Config::Cache.new(**(store ? { store: store } : { directory: directory }))
        result = parse.bind_source!("version-1")
        result.reader.cursor.reset!
        cache.save(result, source_key: "version-1")
        restored = cache.load(1, source_key: "version-1")
        address = restored.find(E::AddressObject, name: "host")

        assert_same address, restored.rules.first.sources.members.fetch("host")
        assert restored.catalog.sealed?
        assert_raises(FrozenError) { restored.rules.first.sources.add("other", address) }
        assert_raises(FrozenError) { address.add(type: "host", value: "192.0.2.2") }
        assert_raises(FrozenError) { restored.catalog.add(address) }
        assert restored.reader.parsed_flags.all?
        assert_equal "version-1", restored.source_key
        assert_same restored, restored.bind_source!("version-1")
      end
    end
  end

  def test_snapshot_from_published_result_preserves_graph_without_resolving_it_again
    result = parse
    snapshot = Algosec::Policy::Snapshot.from_config(result)
    assert_same result.catalog, snapshot.catalog
    assert_same result.rules.first, snapshot.rules.first
    assert snapshot.complete?
    assert_raises(FrozenError) { snapshot.rules.first.action = "deny" }
  end
end
