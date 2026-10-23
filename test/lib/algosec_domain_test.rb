# frozen_string_literal: true

require "test_helper"

class AlgosecDomainTest < ActiveSupport::TestCase
  test "loads vendor elements through the gem entrypoint" do
    address = Algosec::Elements::AddressObject.new(
      name: "web",
      member: [ { type: "host", value: "192.0.2.10" } ],
      zone: "global",
      vendor: :srx,
      device_id: 1
    )

    assert_equal :srx, address.vendor
    assert_equal Algosec::IPAddr.parse("192.0.2.10"), address.set
    assert_includes Algosec::Vendors.names(:parser), :srx
  end

  test "parses configuration with ActiveSupport time defaults" do
    result = Algosec::Config::Parser.perform(
      "set security address-book global address web 192.0.2.10/32\n",
      vendor: :srx,
      device_id: 1
    )

    assert result.complete?, result.diagnostics.inspect
    assert_equal "web", result.find(Algosec::Elements::AddressObject, name: "web").name
  end

  test "uses an injected cache store for configuration results" do
    store = ActiveSupport::Cache::MemoryStore.new
    cache = Algosec::Config::Cache.new(store: store)
    result = Algosec::Config::Parser.perform("", vendor: :srx, device_id: 1)

    assert_nil cache.directory
    assert_same store, cache.store
    assert_nil cache.save(result)
    assert_equal :srx, cache.load(1).reader.vendor
  end

  test "parses Hillstone absolute schedules with seconds" do
    result = Algosec::Config::Parser.perform(
      "schedule \"maintenance\"\n" \
        "  absolute start 10/11/2021 02:45:00 end 01/25/2023 08:15:00\n" \
        "exit\n",
      vendor: :hillstone,
      device_id: 1
    )

    assert result.complete?, result.diagnostics.inspect
    schedule = result.find(Algosec::Elements::Schedule, name: "maintenance")
    assert_equal 45, schedule.start_at.min
    assert_equal 15, schedule.end_at.min
  end

  test "keeps Hillstone multi-member addresses, transparent zones and inline services" do
    result = Algosec::Config::Parser.perform(
      "zone \"transparent\" l2\n" \
        "exit\n" \
        "address \"private\"\n" \
        "  ip 10.0.0.0/8\n" \
        "  ip 192.168.0.0/16\n" \
        "exit\n" \
        "rule id 1\n" \
        "  action permit\n" \
        "  src-addr \"private\"\n" \
        "  dst-addr \"Any\"\n" \
        "  service-rule tcp dst-port 8443\n" \
        "exit\n",
      vendor: :hillstone,
      device_id: 1,
      builtin_services: {
        "Any" => Algosec::Elements::ServiceObject.new(
          name: "Any", vendor: :hillstone, device_id: 1,
          protocol: "any", destination_port: "0-65535"
        )
      }
    )

    assert_empty result.diagnostics
    assert_equal :transparent, result.find(Algosec::Elements::Zone, name: "transparent").mode
    address = result.find(Algosec::Elements::AddressObject, name: "private")
    assert_equal [ "10.0.0.0/8", "192.168.0.0/16" ], address.member.map { |member| member["value"] }
    rule = result.rules.first
    assert_includes rule.services.members.keys, "tcp/8443"
  end

  test "parses Hillstone address-book source NAT" do
    result = Algosec::Config::Parser.perform(
      "address \"source\"\n" \
        "  ip 10.0.0.0/8\n" \
        "exit\n" \
        "ip vrouter \"trust-vr\"\n" \
        "  snatrule id 1 from address-book \"source\" to ip 192.0.2.0/24 service \"Any\" trans-to eif-ip mode dynamicport\n" \
        "exit\n",
      vendor: :hillstone,
      device_id: 1,
      builtin_services: {
        "Any" => Algosec::Elements::ServiceObject.new(
          name: "Any", vendor: :hillstone, device_id: 1,
          protocol: "any", destination_port: "0-65535"
        )
      }
    )

    nat = result.find(Algosec::Elements::DynamicNat, name: "1")
    assert nat
    assert_equal :source, nat.direction
    assert_equal "192.0.2.0/24", nat.destination_ip
    assert_equal "dynamicport", nat.nat_type
    assert_equal "any", nat.protocol
  end
end
