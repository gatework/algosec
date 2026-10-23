# frozen_string_literal: true

require "minitest/autorun"
require "algosec"

class ParserRoutingTest < Minitest::Test
  def test_vip_uses_distance_then_priority_for_equal_prefix_routes
    result = parse(routes: <<~CONFIG)
      config router static
        edit 1
          set dst 10.0.0.0 255.255.255.0
          set device worse
          set distance 30
        next
        edit 2
          set dst 10.0.0.0 255.255.255.0
          set device worse
          set distance 10
          set priority 20
        next
        edit 3
          set dst 10.0.0.0 255.255.255.0
          set device inside
          set distance 10
          set priority 5
        next
      end
    CONFIG

    assert result.complete?, result.diagnostics.inspect
    assert_equal "inside", result.elements(Algosec::Elements::StaticNat).sole.real_zone
  end

  def test_vip_range_crossing_a_more_specific_route_keeps_zone_unknown
    result = parse(mapped: "10.0.0.1-10.0.0.200", routes: <<~CONFIG)
      config router static
        edit 1
          set dst 10.0.0.0 255.255.255.0
          set device inside
        next
        edit 2
          set dst 10.0.0.0 255.255.255.128
          set device worse
        next
      end
    CONFIG

    assert_nil result.elements(Algosec::Elements::StaticNat).sole.real_zone
    refute result.complete?
    diagnostic = result.diagnostics.find { |item| item.code == :ambiguous_route }
    refute_nil diagnostic
    assert_operator diagnostic.line_number, :>, 0
  end

  def test_policy_routes_do_not_participate_in_vip_zone_inference
    result = parse(routes: <<~CONFIG)
      config router policy
        edit 1
          set dst 10.0.0.0 255.255.255.0
          set input-device outside
          set output-device worse
        next
      end
      config router static
        edit 1
          set dst 10.0.0.0 255.255.255.0
          set device inside
        next
      end
    CONFIG

    assert result.complete?, result.diagnostics.inspect
    assert_equal "inside", result.elements(Algosec::Elements::StaticNat).sole.real_zone
  end

  def test_missing_route_keeps_zone_unknown_without_an_ambiguity_diagnostic
    result = parse(routes: "")

    assert_nil result.elements(Algosec::Elements::StaticNat).sole.real_zone
    assert result.complete?, result.diagnostics.inspect
    refute result.diagnostics.any? { |item| item.code == :ambiguous_route }
  end

  private

  def parse(routes:, mapped: "10.0.0.1")
    Algosec::Config::Parser.perform(<<~CONFIG, vendor: :fortinet)
      config system interface
        edit outside
        next
        edit inside
        next
        edit worse
        next
      end
      #{routes}
      config firewall vip
        edit web
          set extip 198.51.100.1
          set extintf outside
          set mappedip #{mapped}
        next
      end
    CONFIG
  end
end
