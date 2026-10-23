# frozen_string_literal: true

require "test_helper"
require_relative "../framework/support/policy_factory"

class RequestServiceTest < ActiveSupport::TestCase
  include PolicyFactory

  def request(service)
    P::Request.new(sources: [ "10.0.0.1" ], destinations: [ "192.0.2.1" ], services: [ service ])
  end

  test "unsupported non TCP UDP restrictions are rejected before losing intent" do
    %w[any/443 0/443 icmp/8 icmpv6/128 1/0 58/0 47/80 132/443].each do |service|
      assert_raises(ArgumentError, service) { request(service) }
    end
  end

  test "protocol-only requests validate the complete service expression" do
    %w[any/ icmp/ 47/ any/not-a-port icmp/type=8 47/70000 any/0-65535/extra icmp/8/0].each do |service|
      assert_raises(ArgumentError, service) { request(service) }
    end
  end

  test "explicit unrestricted suffixes and legacy protocol aliases retain their meaning" do
    { "any" => "any", "0" => "any", "ANY/any" => "any", "any/0-65535" => "any",
      "icmp" => "1", "icmp/any" => "1", "1/0-65535" => "1", "icmp/1 65535" => "1",
      "icmpv6/65535-1" => "58", "47" => "47", "47/any" => "47", "47/65535 0" => "47",
      "6/00443" => "tcp/443", "17/53" => "udp/53" }.each do |service, canonical|
      assert_equal [ canonical ], request(service).services.keys, service
    end
  end

  test "a restricted any request cannot become an executable full service allow plan" do
    loaded = []
    searcher = P::Searcher.new(networks: networks(:palo_alto), snapshots: ->(id) { loaded << id; snapshot(:palo_alto) })
    report = searcher.perform(sources: [ "10.0.0.1" ], destinations: [ "192.0.2.1" ], services: [ "any/443" ])

    refute report.success?
    assert_kind_of ArgumentError, report.error
    assert_empty loaded
    assert_empty report.results
    assert_raises(P::Error) { P::Planner.new(report).plans }
  end

  test "direct result maps and traffic conversion cannot bypass request restrictions" do
    current = snapshot(:palo_alto)
    %w[any/443 icmp/8 47/80].each do |service|
      attributes = group(:palo_alto).merge(services: { service => { origin: service } })
      assert_raises(ArgumentError, service) { P::Result.new(**attributes, snapshot: current, type: :ignore) }
      assert_raises(ArgumentError, service) { P::Request::Traffic.from_maps(attributes) }
    end
  end

  test "direct result metadata cannot hide restricted original service behind a normalized key" do
    attributes = group(:palo_alto).merge(services: { "any" => { origin: "any/443" } })

    assert_raises(ArgumentError) { P::Result.new(**attributes, snapshot: snapshot(:palo_alto), type: :ignore) }
  end

  test "legacy NAT queries cannot discard restrictions from names original services or translated ports" do
    [ { "any/443" => {} }, { "icmp/8" => {} }, { "any" => { origin: "any/443" } },
      { "icmp" => { translated_port: "8" } } ].each do |services|
      assert_raises(ArgumentError) { P::Nat::ServiceQuery.coerce(services) }
    end
  end
end
