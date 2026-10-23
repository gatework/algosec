# frozen_string_literal: true

require_relative "../../test_helper"
require "algosec/config"
require "algosec/policy"

class AsaNatAclTest < Minitest::Test
  P = Algosec::Policy

  def test_acl_destination_port_filter_preserves_exact_transport_and_source_port
    parsed = parse(:static, [ "permit tcp host 10.0.0.1 eq 1024 host 192.0.2.1 eq 443" ])
    assert parsed.complete?, parsed.diagnostics.map(&:message).join("; ")
    services = parsed.rules.first.services

    assert services.matches?(protocol: "tcp", source_port: 1024, destination_port: 443)
    refute services.matches?(protocol: "tcp", source_port: 1025, destination_port: 443)
    refute services.matches?(protocol: "tcp", source_port: 1024, destination_port: 444)
    refute services.matches?(protocol: "udp", source_port: 1024, destination_port: 443)
  end

  %i[static dynamic].each do |kind|
    define_method("test_#{kind}_nat_preserves_acl_service_conditions") do
      resolver = resolver_for(kind, [ "permit tcp host 10.0.0.1 host 192.0.2.1 eq 443" ])
      assert_equal "203.0.113.1/32", find(resolver)[:address]
      assert_nil find(resolver, services: { "udp/53" => {} })
    end

    define_method("test_#{kind}_nat_preserves_acl_address_pairs") do
      resolver = resolver_for(kind, [
        "permit tcp host 10.0.0.1 host 192.0.2.1 eq 443",
        "permit tcp host 10.0.0.2 host 192.0.2.2 eq 443"
      ])
      assert find(resolver)
      assert_nil find(resolver, peers: { "192.0.2.2" => {} })
    end

    define_method("test_#{kind}_nat_rejects_acl_denials_instead_of_using_later_permits") do
      resolver = resolver_for(kind, [
        "deny tcp host 10.0.0.1 host 192.0.2.1 eq 443",
        "permit ip any any"
      ])
      error = assert_raises(P::Error) { find(resolver) }
      assert_equal :conditional_nat, error.code
    end

    define_method("test_#{kind}_nat_reports_partial_acl_coverage") do
      resolver = resolver_for(kind, [ "permit tcp host 10.0.0.1 host 192.0.2.1 eq 443" ])
      error = assert_raises(P::Error) { find(resolver, services: { "tcp/443-444" => {} }) }
      assert_equal :ambiguous_nat, error.code
    end

    define_method("test_#{kind}_nat_requires_peers_and_services") do
      resolver = resolver_for(kind, [ "permit tcp host 10.0.0.1 host 192.0.2.1 eq 443" ])
      [ { peers: nil }, { services: nil } ].each do |missing|
        error = assert_raises(P::Error) { find(resolver, **missing) }
        assert_equal :conditional_nat, error.code
      end
    end

    define_method("test_#{kind}_nat_does_not_drop_source_port_conditions") do
      resolver = resolver_for(kind, [ "permit tcp host 10.0.0.1 eq 1024 host 192.0.2.1 eq 443" ])
      error = assert_raises(P::Error) { find(resolver) }
      assert_equal :conditional_nat, error.code
    end

    define_method("test_#{kind}_nat_does_not_drop_unresolved_conditions") do
      [
        "permit tcp host 10.0.0.1 host 192.0.2.1 eq 443 time-range UNKNOWN",
        "permit tcp host 10.0.0.1 host 192.0.2.1 eq 443 user UNKNOWN",
        "permit object-group UNKNOWN host 10.0.0.1 host 192.0.2.1"
      ].each do |acl|
        resolver = resolver_for(kind, [ acl ], incomplete: true)
        error = assert_raises(P::Error, acl) { find(resolver) }
        assert_equal :conditional_nat, error.code, acl
      end
    end

    define_method("test_#{kind}_nat_requires_the_referenced_acl") do
      parsed = parse(kind, [])
      refute parsed.complete?
      assert parsed.diagnostics.any? { |diagnostic| diagnostic.code == :missing_reference }
      error = assert_raises(P::Error) { P::Snapshot.from_config(parsed) }
      assert_equal :incomplete_configuration, error.code
    end
  end

  def test_reverse_acl_nat_requires_matching_context
    resolver = resolver_for(:static, [ "permit tcp host 10.0.0.1 host 192.0.2.1 eq 443" ])
    error = assert_raises(P::Error) { resolver.reverse("203.0.113.1") }
    assert_equal :conditional_nat, error.code
  end

  def test_source_translation_preserves_service_context
    parsed = parse(:static, [ "permit tcp host 10.0.0.1 host 192.0.2.1 eq 443" ])
    snapshot = P::Snapshot.from_config(parsed)
    mapped, = P::Nat::Translator.build(snapshot).map(
      { "203.0.113.1" => { origin: "203.0.113.1", private: "10.0.0.1" } },
      side: :source, mode: 1, hit: :source, zone: "outside",
      peers: { "192.0.2.1" => {} }, services: { "tcp/443" => {} })

    assert_equal "203.0.113.1/32", mapped.fetch("10.0.0.1").fetch(:nat).fetch(:address)
    refute mapped.fetch("10.0.0.1").key?(:action)
  end

  private

  def resolver_for(kind, entries, incomplete: false)
    parsed = parse(kind, entries)
    if incomplete
      refute parsed.complete?, "The fixture must retain unsupported or missing conditions"
      snapshot = P::Snapshot.new(device_id: 1, vendor: :asa, catalog: parsed.catalog, resolve_references: false)
    else
      assert parsed.complete?, parsed.diagnostics.map(&:message).join("; ")
      snapshot = P::Snapshot.from_config(parsed)
    end
    P::Nat::Resolver.new(snapshot)
  end

  def parse(kind, entries)
    nat = if kind == :static
      "static (inside,outside) 203.0.113.1 access-list NAT_ACL"
    else
      "global (outside) 1 203.0.113.1\nnat (inside) 1 access-list NAT_ACL"
    end
    content = [
      "interface GigabitEthernet0/0\n nameif inside\n!",
      "interface GigabitEthernet0/1\n nameif outside\n!",
      *entries.map { |entry| "access-list NAT_ACL extended #{entry}" }, nat
    ].join("\n") + "\n"
    Algosec::Config::Parser.perform(content, vendor: :asa, device_id: 1)
  end

  def find(resolver, peers: { "192.0.2.1" => {} }, services: { "tcp/443" => {} })
    resolver.find("10.0.0.1", zone: "outside", direction: :source, peers: peers, services: services, flow: { from_zone: "inside", to_zone: "outside" })
  end
end
