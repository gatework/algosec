# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "support/policy_factory"
require "algosec/policy/traffic_ranges"

class GroupProjectionRegressionTest < Minitest::Test
  include PolicyFactory
  E = Algosec::Elements

  def test_address_diamond_expands_each_leaf_once_per_projection
    leaf = E::AddressObject.new(name: "leaf", member: [ { type: "host", value: "192.0.2.1" } ])
    reads = 0
    original = leaf.method(:direct_member)
    leaf.define_singleton_method(:direct_member) { reads += 1; original.call }
    root = diamond(E::AddressGroup, leaf)

    assert_equal Algosec::IPAddr.parse("192.0.2.1"), root.set
    assert_equal 1, reads
    leaf.add(type: "host", value: "192.0.2.2")
    assert_equal Algosec::IPAddr.parse("192.0.2.1-192.0.2.2"), root.set
    assert_equal 2, reads
  end

  def test_shared_addresses_keep_each_parents_exclusions_and_missing_reference_evidence
    leaf = E::AddressObject.new(name: "leaf", member: [ { type: "subnet", value: "192.0.2.0/24" } ])
    parents = %w[192.0.2.0/25 192.0.2.128/25].each_with_index.map do |excluded, index|
      E::AddressObject.new(name: "parent#{index}", references: [ "leaf", "missing" ],
                     excluded_member: [ { type: "subnet", value: excluded } ]).resolve!(strict: false) { |name| leaf if name == "leaf" }
    end
    root = E::AddressGroup.new(name: "root", members: parents.to_h { |parent| [ parent.name, parent ] })

    assert_equal Algosec::IPAddr.parse("192.0.2.0/24"), root.set
    assert_equal [ { "type" => "subnet", "value" => "192.0.2.0/24" } ], root.member
    refute root.resolved?
    assert_equal 2, root.resolution.fetch("errors").size
  end

  def test_address_memo_does_not_reuse_dns_answers_between_queries_or_after_expiry
    leaf = E::AddressObject.new(name: "dns", member: [ { type: "domain", value: "*.example.test" } ])
    root = diamond(E::AddressGroup, leaf)
    now = Time.utc(2026, 1, 1)
    answer = { "status" => "resolved", "addresses" => [ "192.0.2.1" ], "expires_at" => (now + 60).iso8601 }

    projection = root.address_projection(at: now, domain: "www.example.test", answer: answer)
    assert projection[:resolution]["complete"]
    assert projection[:resolution]["conditional"]
    assert_equal Algosec::IPAddr.parse("192.0.2.1"), projection[:set]
    refute root.address_projection(at: now)[:resolution]["complete"]
    refute root.address_projection(at: now + 60, domain: "www.example.test", answer: answer)[:resolution]["complete"]
  end

  def test_service_diamond_queries_visit_each_service_once_but_public_leaves_retain_multiplicity
    service = E::ServiceObject.new(name: "https", protocol: "tcp", destination_port: "443")
    root = diamond(E::ServiceGroup, service)
    reads = Hash.new(0)
    %i[set ports matches?].each do |method|
      original = service.method(method)
      service.define_singleton_method(method) do |**options|
        reads[method] += 1
        options.empty? ? original.call : original.call(**options)
      end
    end

    assert root.resolved?
    assert_equal Algosec::IPAddr.service("tcp/443"), root.set
    assert_equal 1, reads[:set]
    assert_equal service.ports, root.ports
    assert_equal 2, reads[:ports]
    refute root.matches?(protocol: "tcp", source_port: "1024", destination_port: "80")
    assert_equal 1, reads[:matches?]
    assert_equal 256, root.leaves.count
    assert_equal [ service ], root.unique_leaves.to_a
    root.add("missing")
    refute root.resolved?
    assert_equal [ service ], root.unique_leaves(strict: false).to_a
    assert_raises(ArgumentError) { root.unique_leaves(strict: nil).to_a }
    assert_raises(E::Group::UnresolvedReference) { root.unique_leaves.to_a }
    assert_raises(E::Group::UnresolvedReference) { root.matches?(protocol: "tcp", source_port: "1024", destination_port: "443") }
  end

  def test_policy_queries_do_not_expand_shared_service_paths_repeatedly
    service = E::ServiceObject.new(**context(:hillstone), name: "https", protocol: "tcp", destination_port: "443")
    nested = diamond(E::ServiceGroup, service)
    existing = rule(:hillstone, services: [], rule_number: 1)
    existing.services.add(nested.name, nested)
    config = snapshot(:hillstone, [ existing ])
    reads = 0
    original = service.method(:terms)
    service.define_singleton_method(:terms) { reads += 1; original.call }

    assert_equal Algosec::IPAddr.service("tcp/443"), P::Ranges.rule_services(existing)
    assert_equal 1, reads, "Range projection must visit each distinct service once"

    reads = 0
    assert_equal :ignore, P::RuleMatcher.new(config).match(group(:hillstone)).type
    assert_operator reads, :<=, 4, "Planning must not enumerate every path through the service graph"

    reads = 0
    result = P::TrafficMatcher.new(config).perform(source: "10.0.0.1", destination: "192.0.2.1",
                                                   source_port: "1024", destination_port: "443", protocol: "tcp",
                                                   from_zone: "inside", to_zone: "outside")
    assert_equal :permit, result.decision
    assert_operator reads, :<=, 2, "Traffic matching must not enumerate every path through the service graph"

    reads = 0
    assert_equal Algosec::IPAddr.service("tcp/443"), P::Analysis::RuleView.new(config, existing, at: Time.current).ranges[:services]
    assert_operator reads, :<=, 2, "Analysis must not enumerate every path through the service graph"

    reads = 0
    segments = P::TrafficRanges.new(config).perform(source: Algosec::IPAddr.parse("10.0.0.1"), destination: Algosec::IPAddr.parse("192.0.2.1"),
                                                    source_port: Algosec::IPAddr.ports("1024"), destination_port: Algosec::IPAddr.ports("443"),
                                                    protocol: "tcp", from_zone: "inside", to_zone: "outside")
    assert_equal [ :permit ], segments.map { |segment| segment[:decision] }
    assert_operator reads, :<=, 3, "Range matching must not enumerate every path through the service graph"

    reads = 0
    nat = E::DynamicNat.new(**context(:hillstone), id: "1", direction: :source, to_zone: "outside",
                           source_set: "10.0.0.0/24", destination_set: "192.0.2.1", translated_source_set: "203.0.113.1", match_rule: existing)
    resolver = P::Nat::Resolver.new(snapshot(:hillstone, [ existing, nat ]))
    assert resolver.find("10.0.0.1", zone: "outside", direction: :source, peers: { "192.0.2.1" => {} }, services: { "tcp/443" => {} })
    assert_operator reads, :<=, 4, "NAT matching must not enumerate every path through the service graph"

    reads = 0
    route = E::Route.new(**context(:hillstone), kind: :policy, sources: existing.sources, destinations: existing.destinations,
                        services: existing.services, next_hop: "192.0.2.254", destination_interface: "outside",
                        extra_conf: { pbr: { bindings: [ { type: "zone", name: "inside" } ], services: [ "https" ] } })
    assert_equal :match, route.policy_match(source: "10.0.0.1", destination: "192.0.2.1", source_zone: "inside", protocol: "tcp",
                                           source_port: "1024", destination_port: "443")
    assert_operator reads, :<=, 2, "Policy routes must not enumerate every path through the service graph"
    assert_equal 256, nested.leaves.count
  end

  private

  def diamond(group_class, leaf)
    8.times.reduce(leaf) do |child, level|
      context = { vendor: leaf.vendor, device_id: leaf.device_id }
      left = group_class.new(**context, name: "left#{level}", members: { child.name => child })
      right = group_class.new(**context, name: "right#{level}", members: { child.name => child })
      group_class.new(**context, name: "level#{level}", members: { left.name => left, right.name => right })
    end
  end
end
