# frozen_string_literal: true

require "test_helper"
require_relative "support/policy_factory"

class PolicyReviewRegressionTest < ActiveSupport::TestCase
  include PolicyFactory

  def test_shadowed_fortinet_nat_is_not_reported_as_an_existing_policy
    content = fortinet_config + <<~CONFIG
      config firewall policy
      edit 2
      set srcintf "inside"
      set dstintf "outside"
      set srcaddr "internal-web"
      set dstaddr "public-web"
      set action accept
      set schedule "always"
      set service "HTTPS"
      set nat enable
      next
      end
    CONFIG
    config = parse_fortinet(content)
    report = P::Searcher.new(networks: networks(:fortinet, nat_mode: 1, address_type: :private), snapshots: { 1 => config })
                        .perform!(sources: [ "10.0.0.10" ], destinations: [ "198.51.100.20" ], services: [ "tcp/443" ])
    result = report.results.sole
    assert_equal :new, result.type
    assert_equal [ "1" ], result.conflicting_rules.map(&:native_rule_id)
    planner = P::Planner.new(report)
    refute planner.plans.sole.ready?
    commands = planner.perform.sole[:policy_contents].sole[:new][:content]
    assert_includes commands, "set nat enable"
  end

  def test_configuration_plan_keeps_preceding_deny_evidence
    deny = <<~CONFIG
      config firewall policy
      edit 90
      set srcintf "inside"
      set dstintf "outside"
      set srcaddr "internal-web"
      set dstaddr "public-web"
      set action deny
      set schedule "always"
      set service "HTTPS"
      next
      end
    CONFIG
    config = parse_fortinet(fortinet_config.sub("config firewall policy", deny + "\nconfig firewall policy"))
    result = matching_result(config)
    planner = P::Planner.new(P::Report.new(results: [ result ]))
    conflict = planner.perform.sole[:policy_contents].sole[:conflicting_rules].sole
    plan = planner.plans.sole
    refute plan.ready?, "Appending after a preceding deny cannot prove the requested target"
    assert plan.generated?
    assert_raises(P::Error) { plan.script }
    assert_equal [ conflict ], plan.changes.sole[:conflicting_rules]
    assert_equal "deny", conflict[:action]
    assert_includes conflict[:content], "edit 90"
  end

  def test_public_generator_rejects_repeated_modifications_atomically
    config = parse_fortinet(fortinet_config)
    results = %w[tcp/80 tcp/8443].map { |service| matching_result(config, services: [ service ]) }
    assert_equal [ :modify, :modify ], results.map(&:type)
    generator = config.definition.generator.new(snapshot: config)
    error = assert_raises(P::Error) { generator.perform(results) }
    assert_equal :conflicting_rule_modifications, error.code
    assert_empty generator.commands
    error = assert_raises(P::Error) { P::Planner.new(P::Report.new(results: results)).plans }
    assert_equal :conflicting_rule_modifications, error.code
    assert_includes generator.perform(results.first), 'set service "HTTPS" "80"'
  end

  def test_shared_generation_state_preserves_committed_state_when_modification_conflicts
    config = parse_fortinet(fortinet_config)
    first, second = %w[tcp/80 tcp/8443].map { |service| matching_result(config, services: [ service ]) }
    state = {}
    config.definition.generator.new(first, state: state).perform
    committed = P::Value.copy(state)
    generator = config.definition.generator.new(second, state: state)
    assert_raises(P::Error) { generator.perform }
    assert_empty generator.commands
    assert_equal committed, state
  end

  def test_nat_service_terms_preserve_protocol_source_and_destination_port_pairs
    service = E::ServiceObject.new(**context(:palo_alto), name: "paired", terms: [
      { protocol: "tcp", source_port: "1024", destination_port: "443" },
      { protocol: "udp", source_port: "2048", destination_port: "53" }
    ])
    nat = service_nat(service)
    resolver = P::Nat::Resolver.new(snapshot(:palo_alto, [ nat ]))
    %i[source destination].each do |direction|
      options = nat_options(direction).merge(services: { "tcp/443" => {} })
      assert resolver.find(options.delete(:address), **options, source_port: "1024")
      options = nat_options(direction).merge(services: { "tcp/443" => {} })
      refute resolver.find(options.delete(:address), **options, source_port: "2048")
      options = nat_options(direction).merge(services: { "udp/53" => {} })
      assert resolver.find(options.delete(:address), **options, source_port: "2048")
      options = nat_options(direction).merge(services: { "udp/53" => {} })
      refute resolver.find(options.delete(:address), **options, source_port: "1024")
      options = nat_options(direction).merge(services: { "tcp/443" => {} })
      error = assert_raises(P::Error) { resolver.find(options.delete(:address), **options) }
      assert_equal :conditional_nat, error.code
    end
  end

  def test_nat_service_terms_prove_the_union_without_crossing_port_pairs
    terms = [
      { protocol: "tcp", source_port: "1000", destination_port: "443" },
      { protocol: "tcp", source_port: "1001", destination_port: "443" }
    ]
    service = E::ServiceObject.new(**context(:palo_alto), name: "partitioned", terms: terms)
    resolver = P::Nat::Resolver.new(snapshot(:palo_alto, [ service_nat(service) ]))
    options = nat_options(:source).merge(services: { "tcp/443" => {} }, source_port: "1000-1001")
    assert resolver.find(options.delete(:address), **options)

    terms.last[:destination_port] = "8443"
    service = E::ServiceObject.new(**context(:palo_alto), name: "crossed", terms: terms)
    resolver = P::Nat::Resolver.new(snapshot(:palo_alto, [ service_nat(service) ]))
    options = nat_options(:source).merge(services: { "tcp/443" => {}, "tcp/8443" => {} }, source_port: "1000-1001")
    error = assert_raises(P::Error) { resolver.find(options.delete(:address), **options) }
    assert_equal :conditional_nat, error.code
  end

  def test_explicit_any_nat_zone_matches_both_translation_directions
    service = E::ServiceObject.new(**context(:palo_alto), name: "any", protocol: "any")
    nat = service_nat(service, from_zone: "any", to_zone: "any")
    resolver = P::Nat::Resolver.new(snapshot(:palo_alto, [ nat ]))
    %i[source destination].each do |direction|
      options = nat_options(direction)
      assert_same nat, resolver.find(options.delete(:address), **options)&.fetch(:rule)
    end
  end

  def test_destination_nat_requires_its_explicit_original_source_port
    service = E::ServiceObject.new(**context(:palo_alto), name: "any", protocol: "any")
    resolver = P::Nat::Resolver.new(snapshot(:palo_alto, [ service_nat(service, source_port: "1024") ]))
    options = nat_options(:destination)
    address = options.delete(:address)
    assert resolver.find(address, **options, source_port: "1024")
    refute resolver.find(address, **options, source_port: "2048")
    error = assert_raises(P::Error) { resolver.find(address, **options) }
    assert_equal :conditional_nat, error.code
  end

  def test_incomplete_nat_service_group_cannot_be_excluded_by_its_known_projection
    known = E::ServiceObject.new(**context(:palo_alto), name: "https", protocol: "tcp", destination_port: "443")
    group = E::ServiceGroup.new(**context(:palo_alto), name: "partial", members: { "https" => known, "missing" => nil })
    nat = service_nat(group, service_set: known.set)
    resolver = P::Nat::Resolver.new(snapshot(:palo_alto, [ nat ], resolve_references: false))
    %w[tcp/443 tcp/80].each do |service|
      options = nat_options(:source).merge(services: { service => {} })
      error = assert_raises(P::Error) { resolver.find(options.delete(:address), **options) }
      assert_equal :conditional_nat, error.code
    end
    options = nat_options(:source).except(:address).merge(services: { "tcp/80" => {} })
    assert_nil resolver.find("10.0.0.2", **options)
  end

  def test_inactive_static_nat_remains_in_catalog_without_reserving_or_translating_addresses
    nat = E::StaticNat.new(**context(:hillstone), name: "inactive", id: "1", rule_set: "inactive",
                           real_ip: "10.0.0.1", mapped_ip: "203.0.113.1", real_zone: "inside", mapped_zone: "outside",
                           real_set: Algosec::IPAddr.parse("10.0.0.1"), mapped_set: Algosec::IPAddr.parse("203.0.113.1"), disabled: true)
    config = snapshot(:hillstone, [ nat ])
    resolver = P::Nat::Resolver.new(config)
    assert_equal [ nat ], config.static_nats
    assert_empty config.active_static_nats
    assert_nil resolver.find("10.0.0.1", zone: "outside", direction: :source)
    refute resolver.used?("203.0.113.1", zone: "outside")
    assert_nil resolver.rule_set(:source, zone: "outside", type: :static)
    error = assert_raises(P::Error) { resolver.reverse("203.0.113.1") }
    assert_equal :nat_missing, error.code
  end

  private

  def service_nat(service, **attributes)
    E::DynamicNat.new(**context(:palo_alto), name: "paired-nat", direction: :bidirectional,
                     from_zone: "outside", to_zone: "outside", source_set: Algosec::IPAddr.parse("10.0.0.1"),
                     destination_set: Algosec::IPAddr.parse("192.0.2.1"), translated_source_set: Algosec::IPAddr.parse("203.0.113.1"),
                     translated_destination_set: Algosec::IPAddr.parse("203.0.113.2"), service: service,
                     service_set: attributes.delete(:service_set) || service.set, **attributes)
  end

  def nat_options(direction)
    { address: direction == :source ? "10.0.0.1" : "203.0.113.2", zone: "outside", direction: direction, flow: { from_zone: "outside", to_zone: "outside" },
      peers: { (direction == :source ? "192.0.2.1" : "10.0.0.1") => {} } }
  end

  def fortinet_config = TestPaths.root.join("test/fixtures/config/fortinet.cfg").read

  def parse_fortinet(content)
    parsed = Algosec::Config::Parser.perform(content, vendor: :fortinet, device_id: 1)
    assert parsed.complete?, parsed.diagnostics.map(&:message).join("; ")
    P::Snapshot.from_config(parsed)
  end

  def matching_result(config, services: [ "tcp/443" ])
    P::RuleMatcher.new(config).match(group(:fortinet, sources: [ "10.0.0.10" ], destinations: [ "198.51.100.20" ], services: services))
  end
end
