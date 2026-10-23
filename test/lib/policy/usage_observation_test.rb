# frozen_string_literal: true

require "bundler/setup"
require "minitest/autorun"
require "json"
require "active_support"
require "active_support/time"
require "algosec/policy/usage_observation"

class UsageObservationTest < Minitest::Test
  def setup
    @scope = Algosec::Elements::Scope.new(device_id: 7, virtual_system: "vsys1", rulebase: "security")
    @identity = [ :security_rule, :palo_alto, @scope, +"vsys1/rulebase", +"allow-web" ]
    @start = Time.utc(2026, 9, 1)
    @end = Time.utc(2026, 10, 1)
  end

  def observation(**changes)
    Algosec::Policy::UsageObservation.new(**{
      rule_identity: @identity, window_start: @start, window_end: @end,
      hits: 0, counter_reset: false, complete: true
    }.merge(changes))
  end

  def unused?(value, **changes)
    value.unused_for?(**{ rule_identity: @identity, window_start: @start, window_end: @end }.merge(changes))
  end

  def test_complete_zero_hit_evidence_covers_the_entire_required_window
    value = observation
    assert unused?(value)
    assert unused?(value, window_start: @start + 1, window_end: @end - 1)
    refute unused?(value, window_start: @start - 1)
    refute unused?(value, window_end: @end + 1)
    refute unused?(observation(window_start: @start + 1))
    refute unused?(observation(window_end: @end - 1))
  end

  def test_incomplete_reset_and_used_records_never_prove_unused
    [ { complete: false }, { counter_reset: true }, { hits: 1 }, { hits: 2**80 } ].each do |changes|
      refute unused?(observation(**changes)), changes.inspect
    end
  end

  def test_identity_comparison_keeps_vendor_device_scope_and_all_stable_fields
    alternatives = [
      [ :security_rule, :fortinet, @scope, "vsys1/rulebase", "allow-web" ],
      [ :security_rule, :palo_alto, @scope.with(device_id: 8), "vsys1/rulebase", "allow-web" ],
      [ :security_rule, :palo_alto, @scope.with(virtual_system: "vsys2"), "vsys1/rulebase", "allow-web" ],
      [ :security_rule, :palo_alto, @scope.with(rulebase: "pre-rulebase"), "vsys1/rulebase", "allow-web" ],
      [ :security_rule, :palo_alto, @scope.with(address_book: "global"), "vsys1/rulebase", "allow-web" ],
      [ :security_rule, :palo_alto, @scope.with(zone: "inside"), "vsys1/rulebase", "allow-web" ],
      [ :security_rule, :palo_alto, @scope, "other-rulebase", "allow-web" ],
      [ :security_rule, :palo_alto, @scope, "vsys1/rulebase", "different-rule" ],
      "allow-web"
    ]
    alternatives.each { |identity| refute unused?(observation, rule_identity: identity), identity.inspect }
    assert unused?(observation, rule_identity: [ :security_rule, :palo_alto, @scope.with, "vsys1/rulebase", "allow-web" ])
  end

  def test_invalid_observation_evidence_is_rejected_without_coercion
    [ nil, "allow-web", [], [ :security_rule, :palo_alto, @scope ],
      [ :nat_rule, :palo_alto, @scope, "allow-web" ],
      [ "security_rule", :palo_alto, @scope, "allow-web" ],
      [ :security_rule, "palo_alto", @scope, "allow-web" ],
      [ :security_rule, :palo_alto, @scope.to_h, "allow-web" ],
      [ :security_rule, :palo_alto, @scope, 1 ],
      [ :security_rule, :palo_alto, @scope, [ "allow-web" ] ] ].each do |rule_identity|
      assert_raises(ArgumentError) { observation(rule_identity:) }
    end
    [ nil, -1, 0.0, "0", false ].each { |hits| assert_raises(ArgumentError) { observation(hits:) } }
    [ nil, 0, 1, "false", :true ].each do |value|
      assert_raises(ArgumentError) { observation(counter_reset: value) }
      assert_raises(ArgumentError) { observation(complete: value) }
    end
  end

  def test_all_constructor_evidence_keywords_are_required
    attributes = { rule_identity: @identity, window_start: @start, window_end: @end, hits: 0, counter_reset: false, complete: true }
    attributes.each_key do |omitted|
      assert_raises(ArgumentError) { Algosec::Policy::UsageObservation.new(**attributes.except(omitted)) }
    end
  end

  def test_invalid_observation_and_requested_windows_raise_even_for_incomplete_evidence
    [ { window_start: nil }, { window_start: "2026-09-01" }, { window_end: 123 },
      { window_start: Date.new(2026, 9, 1) }, { window_start: @end },
      { window_end: @start - 1 }, { window_end: @start } ].each do |changes|
      assert_raises(ArgumentError) { observation(**changes) }
      assert_raises(ArgumentError) { unused?(observation(complete: false), **changes) }
    end
  end

  def test_mutating_input_arrays_strings_and_times_cannot_change_owned_evidence
    value = observation
    @identity.last.replace("other-rule")
    @identity[3].replace("other-rulebase")
    @identity.clear
    @start.localtime("+08:00")
    @end.localtime("-05:00")
    expected = [ :security_rule, :palo_alto, @scope, "vsys1/rulebase", "allow-web" ]
    assert value.unused_for?(rule_identity: expected, window_start: Time.utc(2026, 9, 1), window_end: Time.utc(2026, 10, 1))
    assert_equal 0, value.window_start.utc_offset
    assert_equal 0, value.window_end.utc_offset
    assert value.frozen?
    assert value.rule_identity.frozen?
    assert value.rule_identity[3].frozen?
    assert value.rule_identity[4].frozen?
    assert_same @scope, value.rule_identity[2]
    refute_same @start, value.window_start
    refute_same @end, value.window_end
    assert value.window_start.frozen?
    assert value.window_end.frozen?
    assert_raises(FrozenError) { value.rule_identity << "extra" }
    assert_raises(FrozenError) { value.window_start.localtime("+02:00") }
  end

  def test_timezone_equivalent_instants_cover_the_same_window
    zone = ActiveSupport::TimeZone["Asia/Hong_Kong"]
    zone_start, zone_end = zone.local(2026, 9, 1, 8), zone.local(2026, 10, 1, 8)
    value = observation(window_start: zone_start, window_end: zone_end)
    assert unused?(value)
    assert unused?(observation, window_start: zone_start, window_end: zone_end)
    assert unused?(observation, window_start: Time.new(2026, 9, 1, 8, 0, 0, "+08:00"))
    refute_same zone_start, value.window_start
    assert value.window_start.frozen?
    assert value.window_end.frozen?
    refute zone_start.frozen?
    refute zone_end.frozen?
  end

  def test_metadata_serializes_the_full_identity_and_exact_evidence_without_source_objects
    value = observation(window_start: @start + Rational(123_456_789, 1_000_000_000))
    expected = {
      "rule_identity" => [ "security_rule", "palo_alto", {
        "device_id" => 7, "virtual_system" => "vsys1", "rulebase" => "security", "address_book" => nil, "zone" => nil
      }, "vsys1/rulebase", "allow-web" ],
      "window_start" => "2026-09-01T00:00:00.123456789Z", "window_end" => "2026-10-01T00:00:00.000000000Z",
      "hits" => 0, "counter_reset" => false, "complete" => true
    }
    assert_equal expected, JSON.parse(JSON.generate(value.as_json))
    assert_equal expected, JSON.parse(JSON.generate(value.to_h))
    metadata = value.to_h
    begin
      metadata[:rule_identity].clear
    rescue FrozenError
      # 调用者可以得到冻结元数据，或可独立修改的副本。
    end
    assert_equal "allow-web", value.rule_identity.last
    flags = JSON.parse(JSON.generate(observation(complete: false, counter_reset: true, hits: 3).as_json))
    assert_equal false, flags["complete"]
    assert_equal true, flags["counter_reset"]
    assert_equal 3, flags["hits"]
  end
end
