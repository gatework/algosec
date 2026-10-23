# frozen_string_literal: true

require "minitest/autorun"
require "open3"
require "rbconfig"
require "algosec"

class ElementsRoutingTest < Minitest::Test
  Elements = Algosec::Elements

  def test_route_can_be_constructed_without_booting_rails
    library = File.expand_path("../../../lib", __dir__)
    output, status = Open3.capture2e(RbConfig.ruby, "-I", library, "-ralgosec", "-e",
                                    'Algosec::Elements::Route.new(subnet: "192.0.2.0/24")')

    assert status.success?, output
  end

  def test_static_lookup_rejects_ranges_split_by_a_more_specific_route
    narrow = Elements::Route.new(subnet: "192.0.2.0/25", next_hop: "10.0.0.1")
    fallback = Elements::Route.new(subnet: "0.0.0.0/0", next_hop: "10.0.0.2")
    table = Elements::RoutingTable.new([ fallback, narrow ])

    assert_same narrow, lookup(table, "192.0.2.1")
    assert_same fallback, lookup(table, "192.0.2.128/25")
    assert_raises(Elements::RoutingTable::ConditionalRoute) { lookup(table, "192.0.2.0/24") }
  end

  def test_policy_lookup_preserves_partial_destination_matches
    policy = Elements::Route.new(kind: :policy, source: "10.1.1.0/24",
                                 subnet: "192.0.2.0/25", next_hop: "10.0.0.1")
    fallback = Elements::Route.new(subnet: "0.0.0.0/0", next_hop: "10.0.0.2")
    table = Elements::RoutingTable.new([ policy, fallback ])

    assert_same policy, lookup(table, "192.0.2.1")
    assert_same fallback, lookup(table, "192.0.2.128/25")
    assert_raises(Elements::RoutingTable::ConditionalRoute) { lookup(table, "192.0.2.0/24") }
  end

  def test_overlapping_routes_in_other_vrfs_do_not_block_lookup
    other = Elements::Route.new(subnet: "192.0.2.0/25", vrf: "other")
    current = Elements::Route.new(subnet: "192.0.2.0/24", vrf: "current")
    table = Elements::RoutingTable.new([ other, current ])

    assert_same current, table.lookup(source: "10.1.1.1", destination: "192.0.2.0/24", vrf: "current")
  end

  def test_static_lookup_uses_prefix_distance_and_priority_without_policy_context
    policy = Elements::Route.new(kind: :policy, subnet: "192.0.2.0/24", source_interface: "incoming")
    fallback = Elements::Route.new(subnet: "0.0.0.0/0", distance: 1)
    worse_distance = Elements::Route.new(subnet: "192.0.2.0/24", distance: 30)
    worse_priority = Elements::Route.new(subnet: "192.0.2.0/24", distance: 10, priority: 20)
    best = Elements::Route.new(subnet: "192.0.2.0/24", distance: 10, priority: 5)
    table = Elements::RoutingTable.new([ policy, fallback, worse_distance, worse_priority, best ])

    assert_same best, table.lookup_static(destination: "192.0.2.1")
    assert_same fallback, table.lookup_static(destination: "198.51.100.1")
  end

  def test_static_lookup_rejects_partial_coverage
    narrow = Elements::Route.new(subnet: "192.0.2.0/25")
    fallback = Elements::Route.new(subnet: "0.0.0.0/0")
    table = Elements::RoutingTable.new([ fallback, narrow ])

    assert_raises(Elements::RoutingTable::ConditionalRoute) do
      table.lookup_static(destination: "192.0.2.0/24")
    end
  end

  def test_unspecified_vrf_rejects_overlapping_static_routes_across_vrfs
    other = Elements::Route.new(subnet: "192.0.2.0/25", vrf: "other")
    current = Elements::Route.new(subnet: "192.0.2.0/24", vrf: "current")
    table = Elements::RoutingTable.new([ other, current ])

    assert_raises(Elements::RoutingTable::ConditionalRoute) { table.lookup_static(destination: "192.0.2.1") }
    assert_raises(Elements::RoutingTable::ConditionalRoute) { lookup(table, "192.0.2.1") }
    assert_same other, table.lookup_static(destination: "192.0.2.1", vrf: "other")
    assert_same current, table.lookup_static(destination: "192.0.2.1", vrf: :current)
    assert_same current, table.lookup_static(destination: "192.0.2.128/25")
    assert_nil table.lookup_static(destination: "198.51.100.1")
  end

  def test_explicit_external_zone_escape_preserves_vrf_and_coverage_boundaries
    current = Elements::Route.new(subnet: "192.0.2.0/24", zone: "inside", vrf: "tenant")
    external = Elements::Route.new(subnet: "192.0.2.0/25", zone: "exrouter", vrf: "external")
    unrelated = Elements::Route.new(subnet: "192.0.2.1/32", zone: "other", vrf: "other")
    table = Elements::RoutingTable.new([ unrelated, external, current ])

    assert_same external, table.lookup_static(destination: "192.0.2.1", vrf: "tenant", external_zone: "exrouter")
    assert_same current, table.lookup_static(destination: "192.0.2.129", vrf: "tenant", external_zone: "exrouter")
    assert_same current, table.lookup_static(destination: "192.0.2.1", vrf: "tenant")
    assert_raises(Elements::RoutingTable::ConditionalRoute) do
      table.lookup_static(destination: "192.0.2.0/24", vrf: "tenant", external_zone: "exrouter")
    end
    assert_raises(Elements::RoutingTable::ConditionalRoute) do
      table.lookup_static(destination: "192.0.2.1", external_zone: "exrouter")
    end
  end

  private

  def lookup(table, destination)
    table.lookup(source: "10.1.1.1", destination: destination)
  end
end
