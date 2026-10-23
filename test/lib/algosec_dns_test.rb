# frozen_string_literal: true

require "test_helper"
require "algosec/dns_resolver"

class AlgosecDnsTest < ActiveSupport::TestCase
  test "cname TTL limits A records and cycles or missing answers stay unknown" do
    cname = Struct.new(:name, :ttl)
    address = Struct.new(:address, :ttl)
    records = {
      [ "alias.test.", Resolv::DNS::Resource::IN::CNAME ] => [ cname.new("target.test", 20) ],
      [ "target.test.", Resolv::DNS::Resource::IN::A ] => [ address.new("192.0.2.2", 60), address.new("192.0.2.1", 120) ],
      [ "cycle.test.", Resolv::DNS::Resource::IN::CNAME ] => [ cname.new("cycle.test", 60) ]
    }
    fake = Object.new
    fake.define_singleton_method(:timeouts=) { |_value| }
    fake.define_singleton_method(:getresources) { |name, type| records.fetch([ name, type ], []) }
    now = Time.utc(2026, 9, 16, 12)
    client = Object.new
    client.define_singleton_method(:open) { |**_options, &block| block.call(fake) }
    resolver = Algosec::DnsResolver.new(device_id: 1, servers: [ "192.0.2.53" ], clock: -> { now }, dns_class: client)
    answer = resolver.resolve("ALIAS.test.")
    assert_equal [ "192.0.2.1", "192.0.2.2" ], answer.fetch("addresses")
    assert_equal now + 20, Time.iso8601(answer.fetch("expires_at"))
    assert_equal "unresolved", resolver.resolve("cycle.test").fetch("status")
    assert_equal "unresolved", resolver.resolve("missing.test").fetch("status")
    assert_equal "unsupported", resolver.resolve("*.example.test").fetch("status")
  end

  test "cache partitions devices and resolver views and failures are retried after a short TTL" do
    now = Time.utc(2026, 9, 16, 12)
    store = ActiveSupport::Cache::MemoryStore.new
    calls = 0
    transport = ->(_name, _servers) { calls += 1; raise Resolv::ResolvTimeout, "timeout" }
    options = { store: store, clock: -> { now }, transport: transport }
    make = ->(id, servers) { Algosec::DnsResolver.new(device_id: id, servers: servers, **options) }
    first = make.call(1, [ "192.0.2.53" ])
    first.resolve("example.test")
    first.resolve("EXAMPLE.test.")
    make.call(1, [ "192.0.2.53" ]).resolve("example.test")
    assert_equal 1, calls
    make.call(2, [ "192.0.2.53" ]).resolve("example.test")
    make.call(1, [ "198.51.100.53" ]).resolve("example.test")
    assert_equal 3, calls
    now += 16
    make.call(1, [ "192.0.2.53" ]).resolve("example.test")
    assert_equal 4, calls
    system = make.call(1, [])
    assert_equal "system", system.context.fetch("source")
  end

  test "repeated normalization never promotes empty terminal labels to an exact domain" do
    calls = []
    resolver = Algosec::DnsResolver.new(device_id: 1, servers: [ "192.0.2.53" ],
      transport: ->(name, _servers) { calls << name; [ [ "192.0.2.1" ], 60 ] })

    [ "example.test..", "example.test..." ].each do |name|
      assert_equal "unsupported", resolver.resolve(name).fetch("status")
      refute Algosec::DomainName.matches?("example.test", name)
      refute Algosec::DomainName.matches?("*.example.test..", "www.example.test")
    end
    assert_empty calls
    assert_equal "resolved", resolver.resolve("EXAMPLE.test.").fetch("status")
    assert_equal [ "example.test" ], calls
  end
end
