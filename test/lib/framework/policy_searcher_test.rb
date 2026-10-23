# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "support/policy_factory"

class PolicySearcherTest < Minitest::Test
  include PolicyFactory

  def test_search_uses_injected_snapshots_and_no_cache_survives_the_request
    VENDORS.each do |vendor|
      loads = []
      config = snapshot(vendor, [ rule(vendor) ])
      searcher = P::Searcher.new(networks: networks(vendor), snapshots: ->(id) {
        loads << id
        config
      })
      input = { sources: [ "10.0.0.1" ], destinations: [ "192.0.2.1" ], services: [ "tcp/443" ] }
      2.times do
        report = searcher.perform(input)
        assert report.success?, "#{vendor}: #{report.comment}"
        assert_equal [ :ignore ], report.results.map(&:type)
      end
      assert_equal [ 1, 1 ], loads
    end
  end

  def test_asa_expands_each_address_and_service_combination
    searcher = P::Searcher.new(networks: networks(:asa), snapshots: { 1 => snapshot(:asa) })
    report = searcher.perform(sources: [ "10.0.0.1", "10.0.0.2" ], destinations: [ "192.0.2.1", "192.0.2.2" ], services: [ "tcp/80", "tcp/443" ])
    assert report.success?, report.comment
    assert_equal 8, report.results.size
    report.results.each do |result|
      assert_equal [ 1, 1, 1 ], [ result.sources.size, result.destinations.size, result.services.size ]
    end
  end

  def test_search_failure_discards_all_results_and_next_call_can_succeed
    calls = 0
    searcher = P::Searcher.new(networks: networks(:hillstone), snapshots: ->(_id) do
      calls += 1
      raise P::Error.new("配置加载失败", code: :snapshot_missing) if calls == 1
      snapshot(:hillstone)
    end)
    input = { sources: [ "10.0.0.1" ], destinations: [ "192.0.2.1" ], services: [ "tcp/443" ] }
    failure = searcher.perform(input)
    refute failure.success?
    assert_equal :snapshot_missing, failure.error_code
    assert_empty failure.results
    assert searcher.perform(input).success?
  end

  def test_perform_and_perform_bang_keep_their_error_contracts
    searcher = P::Searcher.new(networks: [], snapshots: {})
    request = { sources: [ "10.0.0.1" ], destinations: [ "192.0.2.1" ], services: [ "tcp/443" ] }

    report = searcher.perform(request)
    error = assert_raises(P::Error) { searcher.perform!(request) }
    refute report.success?
    assert_empty report.results
    assert_equal :no_firewall, report.error_code
    assert_equal report.error_code, error.code
  end

  def test_missing_or_ambiguous_network_is_not_treated_as_a_match
    rows = networks(:hillstone)
    searcher = P::Searcher.new(networks: rows, snapshots: { 1 => snapshot(:hillstone) })
    report = searcher.perform(sources: [ "198.51.100.1" ], destinations: [ "192.0.2.1" ], services: [ "tcp/443" ])
    assert_equal :no_firewall, report.error_code
    rows << rows.first.merge(zone: "overlap")
    report = searcher.perform(sources: [ "10.0.0.1" ], destinations: [ "192.0.2.1" ], services: [ "tcp/443" ])
    assert_equal :ambiguous_zone, report.error_code
    rows.pop
    rows.pop
    report = searcher.perform(sources: [ "10.0.0.1" ], destinations: [ "192.0.2.1" ], services: [ "tcp/443" ])
    assert_equal :unreachable, report.error_code
  end

  def test_longest_prefix_distance_priority_and_source_routes
    static = [
      E::Route.new(**context(:hillstone), subnet: "0.0.0.0/0", zone: "default"),
      E::Route.new(**context(:hillstone), subnet: "192.0.2.0/24", zone: "outside", distance: 10),
      E::Route.new(**context(:hillstone), subnet: "192.0.2.0/25", zone: "narrow", distance: 100)
    ]
    # 路由身份相同的记录由 Catalog 替换；不同前缀保持独立。
    policy = E::Route.new(**context(:hillstone), kind: :policy, name: "policy", subnet: "192.0.2.0/24", source: "10.0.0.0/24", zone: "policy")
    index = P::NetworkLocator.new([])
    config = snapshot(:hillstone, static + [ policy ])
    zones = %w[default outside narrow policy]
    assert_equal "narrow", index.route_zone("192.0.2.1/32", snapshot: config, zones: zones)
    assert_equal "outside", index.route_zone("192.0.2.129/32", snapshot: config, zones: zones)
    assert_equal "policy", index.route_zone("192.0.2.1/32", snapshot: config, zones: zones, source: "10.0.0.1")
    assert_nil index.route_zone("192.0.2.1/32", snapshot: config, zones: [ "missing" ])
  end

  def test_same_firewall_and_same_zone_are_each_processed_once
    rows = networks(:hillstone)
    rows.last.merge!(protected: true, address: "192.0.2.0/24")
    searcher = P::Searcher.new(networks: rows, snapshots: { 1 => snapshot(:hillstone) })
    report = searcher.perform(sources: [ "10.0.0.1" ], destinations: [ "192.0.2.1" ], services: [ "tcp/443" ])
    assert report.success?, report.comment
    assert_equal 1, report.results.size
    assert_equal :source, report.results.first.hit
    report = searcher.perform(sources: [ "10.0.0.1" ], destinations: [ "10.0.0.2" ], services: [ "tcp/443" ])
    assert report.success?, report.comment
    assert_equal 1, report.results.size
    assert_equal :new, report.results.first.type
  end

  def test_external_routes_are_skipped_without_loading_a_nat_mapping
    rows = networks(:hillstone)
    rows.last[:address_type] = :extra
    searcher = P::Searcher.new(networks: rows, snapshots: { 1 => snapshot(:hillstone) })
    report = searcher.perform(sources: [ "10.0.0.1" ], destinations: [ "192.0.2.1" ], services: [ "tcp/443" ])
    assert report.success?, report.comment
    assert_empty report.results
  end

  def test_report_distinguishes_same_zone_plans_from_external_omissions
    rows = networks(:hillstone)
    searcher = P::Searcher.new(networks: rows, snapshots: { 1 => snapshot(:hillstone) })
    report = searcher.perform(sources: [ "10.0.0.1" ], destinations: [ "10.0.0.2" ], services: [ "tcp/443" ])
    assert report.success?, report.comment
    assert report.complete?
    assert_equal :new, report.results.sole.type
    assert_empty report.skipped
    rows.last[:address_type] = :extra
    report = searcher.perform(sources: [ "10.0.0.1" ], destinations: [ "192.0.2.1" ], services: [ "tcp/443" ])
    assert report.success?, report.comment
    refute report.complete?
    assert_equal :outside, report.skipped.sole[:reason]
  end

  def test_partial_cartesian_coverage_keeps_original_unmatched_combinations
    searcher = P::Searcher.new(networks: networks(:hillstone), snapshots: { 1 => snapshot(:hillstone) })
    report = searcher.perform(sources: [ "10.0.0.1", "198.51.100.1" ], destinations: [ "192.0.2.1" ], services: [ "tcp/443", "udp/53" ])
    assert report.success?, report.comment
    refute report.complete?
    assert_equal 1, report.results.size
    assert_equal [
      { device_id: nil, source: "198.51.100.1/32", destination: "192.0.2.1/32", service: "tcp/443", reason: :unmatched },
      { device_id: nil, source: "198.51.100.1/32", destination: "192.0.2.1/32", service: "udp/53", reason: :unmatched }
    ], report.skipped
  end

  def test_external_skip_on_another_device_does_not_invalidate_a_fully_evaluated_path
    first = networks(:hillstone)
    first.last[:address_type] = :extra
    rows = first + networks(:hillstone, device_id: 2)
    report = P::Searcher.new(networks: rows, snapshots: { 1 => snapshot(:hillstone), 2 => snapshot(:hillstone, device_id: 2) })
      .perform(sources: [ "10.0.0.1" ], destinations: [ "192.0.2.1" ], services: [ "tcp/443" ])
    assert report.success?, report.comment
    assert report.complete?
    assert_equal [ 2 ], report.results.map(&:device_id)
    assert_equal :outside, report.skipped.sole[:reason]
  end

  def test_later_rule_matching_failure_discards_previously_matched_results
    rows = networks(:hillstone) + networks(:hillstone, device_id: 2)
    ambiguous = %w[r1 r2].map do |name|
      E::SecurityRule.new(**context(:hillstone, device_id: 2), name: name, native_rule_id: name,
        from_zones: "inside", to_zones: "outside", action: "permit", rule_number: 1)
    end
    configs = { 1 => snapshot(:hillstone), 2 => snapshot(:hillstone, ambiguous, device_id: 2) }
    report = P::Searcher.new(networks: rows, snapshots: configs)
      .perform(sources: [ "10.0.0.1" ], destinations: [ "192.0.2.1" ], services: [ "tcp/443" ])
    refute report.success?
    assert_equal :unknown_order, report.error_code
    refute report.complete?
    assert_empty report.results
    assert_empty report.skipped
  end

  def test_report_requires_original_combination_on_every_traversed_device
    result = P::RuleMatcher.new(snapshot(:hillstone)).match(group(:hillstone))
    expected = { [ "10.0.0.1/32", "192.0.2.1/32", "tcp/443" ] => [ 1, 2 ] }
    report = P::Report.new(results: [ result ], expected: expected)
    assert report.success?
    refute report.complete?
    assert_equal [ { device_id: 2, source: "10.0.0.1/32", destination: "192.0.2.1/32", service: "tcp/443", reason: :unmatched } ], report.skipped
  end

  def test_original_address_combination_remains_complete_after_nat_translation
    searcher = P::Searcher.new(networks: networks(:hillstone, nat_mode: 1, address_type: :private), snapshots: { 1 => snapshot(:hillstone) })
    report = searcher.perform(sources: [ "192.0.2.1" ], destinations: [ { addresses: [ "10.0.0.9" ], nat: { type: :static, address: "203.0.113.9" } } ], services: [ "tcp/443" ])
    assert report.success?, report.comment
    assert report.complete?
    assert_empty report.skipped
    result = report.results.sole
    assert_equal [ "203.0.113.9/32" ], result.destinations.keys
    assert_equal [ "10.0.0.9/32" ], result.destinations.values.map { |entry| entry[:origin] }
  end

  def test_device_info_preserves_unmatched_addresses_without_loading_snapshots
    searcher = P::Searcher.new(networks: networks(:hillstone), snapshots: ->(_id) { flunk "不应加载配置" })
    info = searcher.device_info([ "10.0.0.1", "192.0.2.1" ])
    assert_equal [ 1, nil ], info.map { |row| row[:device_id] }
    assert_equal [ "inside", nil ], info.map { |row| row[:zone] }
  end
  def test_same_zone_explicit_denial_is_retained_as_a_planning_conflict
    denied = rule(:hillstone, destination: "10.0.0.2", to_zones: "inside", action: "deny", rule_number: 1)
    report = P::Searcher.new(networks: networks(:hillstone), snapshots: { 1 => snapshot(:hillstone, [ denied ]) })
      .perform(sources: [ "10.0.0.1" ], destinations: [ "10.0.0.2" ], services: [ "tcp/443" ])
    assert report.success?, report.comment
    assert_equal 1, report.results.size
    assert_equal [ denied ], report.results.first.conflicting_rules
    assert_empty report.skipped
  end

  def test_proven_pan_same_zone_default_needs_no_policy_change
    report = P::Searcher.new(networks: networks(:palo_alto), snapshots: { 1 => snapshot(:palo_alto) })
      .perform(sources: [ "10.0.0.1" ], destinations: [ "10.0.0.2" ], services: [ "tcp/443" ])
    assert report.success?, report.comment
    assert_equal 1, report.results.size
    assert_equal :ignore, report.results.first.type
    assert_nil report.results.first.rule
    assert_nil report.results.first.actions
    assert report.complete?
  end
end
