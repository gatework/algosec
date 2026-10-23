# frozen_string_literal: true

require "test_helper"
require "algosec/policy/traffic_set"

class TrafficSetTest < ActiveSupport::TestCase
  TrafficSet = Algosec::Policy::TrafficSet
  Packet = Algosec::Policy::Packet
  DIMENSIONS = %i[source_addresses destination_addresses protocols source_ports destination_ports].freeze

  def numbers(*ranges) = Algosec::Set.new(*ranges)

  def region(family: :ipv4, source_addresses: numbers(0..2), destination_addresses: numbers(0..2),
             protocols: numbers(0..2), source_ports: numbers(0..2), destination_ports: numbers(0..2))
    TrafficSet::Region.new(family:, source_addresses:, destination_addresses:, protocols:, source_ports:, destination_ports:)
  end

  def packet(source: "0.0.0.1", destination: "0.0.0.1", protocol: 0, source_port: 1, destination_port: 1, **context)
    Packet.new(source:, destination:, protocol:, source_port:, destination_port:, **context)
  end

  def points(traffic)
    traffic.flat_map do |part|
      values = DIMENSIONS.map { |name| part.public_send(name).flat_map(&:to_a) }
      values.first.product(*values.drop(1)).map { |point| [ part.family, *point ] }
    end.sort
  end

  test "packet singleton preserves protocol zero and provides a concrete witness" do
    value = packet
    traffic = TrafficSet.from_packet(value)
    assert traffic.include?(value)
    refute traffic.include?(packet(protocol: 1))
    assert_equal value, traffic.witness
    assert_nil TrafficSet.new.witness
    assert TrafficSet.new.empty?
  end

  test "context cannot silently disappear into numeric sets" do
    [ packet(application: "ssl"), packet(source_user: "alice") ].each do |value|
      assert_raises(ArgumentError) { TrafficSet.from_packet(value) }
      assert_raises(ArgumentError) { TrafficSet.new.include?(value) }
    end
  end

  test "accepts field hashes and stores disjoint frozen regions without mutating input" do
    original = region
    fields = { family: :ipv4, **DIMENSIONS.to_h { |name| [ name, original.public_send(name) ] } }
    input = [ fields, original, original ]
    traffic = TrafficSet.new(input)
    assert_equal 1, traffic.regions.size
    assert_equal 3, input.size
    assert_equal fields, input.first
    assert traffic.frozen?
    assert traffic.regions.frozen?
    assert traffic.first.frozen?
    assert_kind_of Enumerator, traffic.each
    assert_same traffic, traffic.each { |_part| }
    assert_equal 4096, traffic.limit
  end

  test "union preserves paired rectangles instead of broadening independent dimensions" do
    first = region(source_addresses: numbers(0..0), destination_addresses: numbers(0..0))
    second = region(source_addresses: numbers(1..1), destination_addresses: numbers(1..1))
    traffic = TrafficSet.new([ first ]) | TrafficSet.new([ second ])
    refute traffic.include?(packet(source: "0.0.0.0", destination: "0.0.0.1"))
    assert_equal 54, points(traffic).size
    assert_equal 2, traffic.regions.size
  end

  test "initialization removes overlaps and difference cuts across all five dimensions" do
    outer = region
    inner = region(**DIMENSIONS.to_h { |name| [ name, numbers(1..1) ] })
    traffic = TrafficSet.new([ inner, outer, inner ])
    assert_equal 243, points(traffic).size
    assert_equal points(traffic).uniq, points(traffic)
    difference = TrafficSet.new([ outer ]) - TrafficSet.new([ inner ])
    assert_equal 242, points(difference).size
    assert_equal 5, difference.regions.size
    refute difference.include?(packet(protocol: 1))
  end

  test "joint regions cover a larger rectangle and empty sets have normal set identities" do
    first = region(source_addresses: numbers(0..0))
    second = region(source_addresses: numbers(1..2))
    whole = TrafficSet.new([ region ])
    halves = TrafficSet.new([ first, second ])
    assert halves.cover?(whole)
    assert whole.cover?(halves)
    assert whole.cover?(TrafficSet.new)
    refute TrafficSet.new.cover?(whole)
    assert_equal points(whole), points(whole | TrafficSet.new)
    assert (whole & TrafficSet.new).empty?
    assert (whole - whole).empty?
  end

  test "families stay separate even when numeric endpoints coincide" do
    v4 = TrafficSet.new([ region ])
    v6 = TrafficSet.new([ region(family: :ipv6) ])
    assert (v4 & v6).empty?
    assert_equal points(v4), points(v4 - v6)
    assert_equal 486, points(v4 | v6).size
    refute v4.cover?(v6)
    value = packet(source: "::1", destination: "::1")
    assert v6.include?(value)
    assert_equal :ipv6, v6.witness.family
    assert v6.include?(v6.witness)
  end

  test "validates dimensions family universes and operand types" do
    assert_raises(ArgumentError) { region(family: :other) }
    assert_raises(ArgumentError) { region(protocols: numbers(256..256)) }
    assert_raises(ArgumentError) { region(source_ports: numbers(65_536..65_536)) }
    assert_raises(ArgumentError) { region(destination_addresses: numbers((1 << 32)..(1 << 32))) }
    assert_raises(ArgumentError) { region(source_addresses: [ 0..1 ]) }
    assert_raises(ArgumentError) { TrafficSet.new([ {} ]) }
    assert_raises(ArgumentError) { TrafficSet.new([ "region" ]) }
    assert_raises(ArgumentError) { TrafficSet.new | [] }
    assert_raises(ArgumentError) { TrafficSet.new.include?(nil) }
    assert TrafficSet.new([ region(protocols: numbers) ]).empty?
  end

  test "rejects invalid budgets and enforces region count incrementally after deduplication" do
    [ 0, -1, 1.5, nil ].each { |limit| assert_raises(ArgumentError) { TrafficSet.new(limit:) } }
    assert_equal 1, TrafficSet.new(Array.new(20, region), limit: 1).regions.size
    first = region(source_addresses: numbers(0..0))
    second = region(source_addresses: numbers(1..1))
    assert_equal 2, TrafficSet.new([ first, second ], limit: 2).regions.size
    assert_equal 2, TrafficSet.new([ first, second, second ], limit: 2).regions.size
    contained = region(source_addresses: numbers(1..1), protocols: numbers(1..1))
    assert_equal 2, TrafficSet.new([ first, second, contained ], limit: 2).regions.size
    assert_raises(TrafficSet::LimitExceeded) { TrafficSet.new([ first, second ], limit: 1) }
  end

  test "bounds single dimension fragments in inputs and intermediate subtraction" do
    fragmented = region(source_addresses: numbers(1..1, 3..3, 5..5, 7..7))
    assert_raises(TrafficSet::LimitExceeded) { TrafficSet.new([ fragmented ], limit: 3) }
    left = TrafficSet.new([ region(source_addresses: numbers(0..8)) ], limit: 4)
    right = TrafficSet.new([ fragmented ], limit: 4)
    before = points(left)
    assert_raises(TrafficSet::LimitExceeded) { left - right }
    assert_equal before, points(left)
    assert_equal 4, right.first.source_addresses.size
  end

  test "bounds fragmented intersections before accepting oversized dimension results" do
    left = TrafficSet.new([ region(source_addresses: numbers(0..2, 4..6)) ], limit: 2)
    right = TrafficSet.new([ region(source_addresses: numbers(1..4, 6..8)) ], limit: 2)
    assert_raises(TrafficSet::LimitExceeded) { left & right }
    assert_equal 2, left.first.source_addresses.size
    assert_equal 2, right.first.source_addresses.size
  end

  test "default interval budget accepts 4096 segments and rejects the next one" do
    intervals = Array.new(4096) { |index| (index * 2)..(index * 2) }
    boundary = region(source_addresses: numbers(*intervals))
    assert_equal 4096, TrafficSet.new([ boundary ]).first.source_addresses.size
    oversized = region(source_addresses: numbers(*intervals, 8192..8192))
    assert_raises(TrafficSet::LimitExceeded) { TrafficSet.new([ oversized ]) }
  end

  test "operation budget uses the stricter operand and never mutates either input" do
    left = TrafficSet.new([ region(source_addresses: numbers(0..0)) ], limit: 1)
    right = TrafficSet.new([ region(source_addresses: numbers(1..1)) ], limit: 2)
    before = [ points(left), points(right) ]
    assert_raises(TrafficSet::LimitExceeded) { left | right }
    assert_raises(TrafficSet::LimitExceeded) { right | left }
    assert_equal before, [ points(left), points(right) ]
  end

  test "seeded exhaustive small-space oracle proves union intersection difference and coverage" do
    random = Random.new(20_261_022)
    universe = [ 0, 1, 2 ].repeated_permutation(5).to_a
    40.times do
      inputs = Array.new(2) do
        Array.new(random.rand(0..4)) do
          dimensions = DIMENSIONS.to_h do |name|
            endpoints = [ random.rand(0..2), random.rand(0..2) ].minmax
            [ name, random.rand(3).zero? ? numbers(0..0, 2..2) : numbers(endpoints.first..endpoints.last) ]
          end
          region(**dimensions)
        end
      end
      expected = inputs.map do |regions|
        universe.select do |point|
          regions.any? { |part| DIMENSIONS.each_with_index.all? { |name, index| part.public_send(name).include?(point[index]) } }
        end.map { |point| [ :ipv4, *point ] }.sort
      end
      left, right = inputs.map { |regions| TrafficSet.new(regions) }
      assert_equal (expected[0] | expected[1]).sort, points(left | right)
      assert_equal (expected[0] & expected[1]).sort, points(left & right)
      assert_equal (expected[0] - expected[1]).sort, points(left - right)
      assert_equal (expected[1] - expected[0]).empty?, left.cover?(right)
      assert_equal expected[0], points(left)
      assert_equal points(left).uniq, points(left)
    end
  end
end
