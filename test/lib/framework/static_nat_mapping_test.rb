# frozen_string_literal: true

require "minitest/autorun"
require "algosec"

class StaticNatMappingTest < Minitest::Test
  E = Algosec::Elements

  def test_conflicting_real_ranges_cannot_produce_multiple_translations
    pairs = [ [ "10.0.0.0/24", "203.0.113.0/24" ], [ "10.0.0.128/25", "198.51.100.0/25" ] ]
    [ pairs, pairs.reverse ].each do |mappings|
      assert_raises(E::StaticNat::InvalidMapping) { nat(mappings).translate("10.0.0.129") }
      assert_raises(E::StaticNat::InvalidMapping) { nat(mappings).reverse_translate("203.0.113.129") }
    end
  end

  def test_nested_compatible_ranges_do_not_hide_a_later_conflict_with_the_parent
    mappings = [ [ "10.0.0.0/24", "203.0.113.0/24" ], [ "10.0.0.32/27", "203.0.113.32/27" ],
                 [ "10.0.0.128/25", "198.51.100.0/25" ] ]
    assert_raises(E::StaticNat::InvalidMapping) { nat(mappings).translate("10.0.0.129") }
  end

  def test_constant_and_offset_mappings_must_agree_on_the_entire_overlap
    assert_raises(E::StaticNat::InvalidMapping) do
      nat([ [ "10.0.0.0/24", "203.0.113.0/24" ], [ "10.0.0.128/25", "203.0.113.128" ] ]).translate("10.0.0.129")
    end
    assert_raises(E::StaticNat::InvalidMapping) do
      nat([ [ "10.0.0.0/24", "203.0.113.1" ], [ "10.0.0.128/25", "203.0.113.2" ] ]).translate("10.0.0.129")
    end
  end

  def test_identical_offsets_allow_duplicates_and_nested_overlaps
    mapping = nat([ [ "10.0.0.128/25", "203.0.113.128/25" ], [ "10.0.0.0/24", "203.0.113.0/24" ],
                    [ "10.0.0.0/24", "203.0.113.0/24" ] ])
    assert_equal ip("203.0.113.0/24"), mapping.translate("10.0.0.0/24")
    assert_equal ip("10.0.0.0/24"), mapping.reverse_translate("203.0.113.0/24")
  end

  def test_constant_mappings_allow_compatible_overlaps_and_reverse_expansion
    mapping = nat([ [ "10.0.0.0/24", "203.0.113.1" ], [ "10.0.0.128/25", "203.0.113.1" ],
                    [ "10.0.1.0/24", "203.0.113.1" ] ])
    assert_equal ip("203.0.113.1"), mapping.translate("10.0.0.0/23")
    assert_equal ip("10.0.0.0/23"), mapping.reverse_translate("203.0.113.1")
  end

  def test_constant_and_offset_mappings_can_agree_at_a_single_endpoint
    mapping = nat([ [ "10.0.0.0-10.0.0.128", "203.0.113.128" ],
                    [ "10.0.0.128/25", "203.0.113.128/25" ] ])
    assert_equal ip("203.0.113.128/25"), mapping.translate("10.0.0.0/24")
    assert_equal ip("10.0.0.0-10.0.0.128"), mapping.reverse_translate("203.0.113.128")
  end

  def test_disjoint_swapped_segments_and_overlapping_mapped_ranges_keep_their_pairing
    swapped = nat([ [ "10.0.0.128/25", "203.0.113.0/25" ], [ "10.0.0.0/25", "203.0.113.128/25" ] ])
    assert_equal ip("203.0.113.1"), swapped.translate("10.0.0.129")
    assert_equal ip("10.0.0.129"), swapped.reverse_translate("203.0.113.1")

    shared = nat([ [ "10.0.0.0/25", "203.0.113.0/25" ], [ "10.0.0.128/25", "203.0.113.0/25" ] ])
    assert_equal ip("203.0.113.0/25"), shared.translate("10.0.0.0/24")
    assert_equal ip("10.0.0.0/24"), shared.reverse_translate("203.0.113.0/25")
  end

  private

  def nat(mappings)
    E::StaticNat.new(real_ip: "real", mapped_ip: "mapped", mappings: mappings)
  end

  def ip(value) = Algosec::IPAddr.parse(value)
end
