# frozen_string_literal: true

require "test_helper"
require "algosec/policy/packet"

class PacketTest < ActiveSupport::TestCase
  def packet(**changes)
    Algosec::Policy::Packet.new(**{
      source: "192.0.2.1", destination: "198.51.100.2", protocol: 6,
      source_port: 12_345, destination_port: 443
    }.merge(changes))
  end

  test "represents a concrete frozen IPv4 packet including actual protocol zero" do
    value = packet(protocol: 0)
    assert_equal :ipv4, value.family
    assert_equal 0, value.protocol
    assert_equal "192.0.2.1", value.source
    assert value.frozen?
    assert value.source.frozen?
    assert_equal value, packet(protocol: 0)
    assert_equal value.hash, packet(protocol: 0).hash
  end

  test "canonicalizes IPv6 hosts and preserves frozen context" do
    application = +"ssl"
    value = packet(source: "2001:0db8::1", destination: "2001:db8::2", application:, source_user: "alice")
    application.replace("other")
    assert_equal :ipv6, value.family
    assert_equal "2001:db8::1", value.source
    assert_equal "ssl", value.application
    assert_equal "alice", value.source_user
    assert value.contextual?
    assert value.application.frozen?
  end

  test "rejects address ranges prefixes scopes mixed families and nonaddresses" do
    [ "192.0.2.1/32", "192.0.2.0/24", "192.0.2.1-192.0.2.2", "any", "::1%eth0", 1, nil ].each do |source|
      assert_raises(ArgumentError) { packet(source:) }
    end
    assert_raises(ArgumentError) { packet(destination: "::1") }
  end

  test "requires integer protocol and scalar ports within their universes" do
    [ -1, 256, "any", "tcp", "0", nil, 1.5 ].each do |protocol|
      assert_raises(ArgumentError) { packet(protocol:) }
    end
    [ -1, 65_536, 1..2, "443", nil, 1.5 ].each do |port|
      assert_raises(ArgumentError) { packet(source_port: port) }
      assert_raises(ArgumentError) { packet(destination_port: port) }
    end
    assert_equal 65_535, packet(source_port: 0, destination_port: 65_535, protocol: 255).destination_port
  end
end
