# frozen_string_literal: true

require_relative "../../test_helper"

class AddressGroupNegationTest < Minitest::Test
  E = Algosec::Elements

  def test_negated_groups_resolve_ordinary_named_groups_and_keep_dependencies
    host = E::AddressObject.new(name: "host", member: [ { type: "host", value: "192.0.2.1" } ])
    excluded = E::AddressGroup.new(name: "excluded", members: { "host" => host })
    negated = E::AddressGroup::Negated.new(name: "allowed", members: { "excluded" => nil })

    E::Catalog.new([ host, excluded, negated ]).resolve!

    assert_equal [ excluded ], negated.dependencies
    assert_equal Algosec::Set.new(0..Algosec::IPAddr::IPV4_MAX) - host.set, negated.resolved_set
  end

  def test_nested_negation_composes_with_union_and_double_negation
    host = E::AddressObject.new(name: "host", member: [ { type: "host", value: "192.0.2.1" } ])
    negated = E::AddressGroup::Negated.new(name: "negated", members: { "host" => host })
    union = E::AddressGroup.new(name: "all", members: { "negated" => negated, "host" => host })
    double = E::AddressGroup::Negated.new(name: "double", members: { "negated" => negated })

    assert_equal Algosec::Set.new(0..Algosec::IPAddr::IPV4_MAX), union.resolved_set
    assert_equal host.set, double.resolved_set
    assert_equal host.set, Algosec::IPAddr.parse(double.member.sole.fetch("value"))
  end

  def test_ipv6_negation_uses_the_ipv6_universe
    host = E::AddressObject.new(name: "host", member: [ { type: "ipv6", value: "2001:db8::1" } ])
    negated = E::AddressGroup::Negated.new(name: "negated", members: { "host" => host })
    projection = negated.address_projection(family: :ipv6)

    assert projection.fetch(:resolution).fetch("complete")
    assert_equal Algosec::Set.new(0..::IPAddr::IN6MASK) - Algosec::IPv6.parse("2001:db8::1"), projection.fetch(:set)
    assert projection.fetch(:member).all? { |leaf| leaf.fetch("type") == "ipv6" }
  end

  def test_missing_or_dns_dependent_exclusions_do_not_become_any_address
    domain = E::AddressObject.new(name: "domain", member: [ { type: "domain", value: "example.test" } ])
    [ nil, domain ].each do |child|
      negated = E::AddressGroup::Negated.new(name: "negated", members: { "excluded" => child })
      parent = E::AddressGroup.new(name: "parent", members: { "negated" => negated })

      refute parent.resolved?
      assert_equal !child.nil?, parent.conditional?
      assert_empty parent.set
      assert_raises(E::Group::UnresolvedReference) { parent.resolved_set }
    end
  end
end
