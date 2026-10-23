# frozen_string_literal: true

require_relative "../../test_helper"
require "algosec/policy"

class NatConditionsTest < Minitest::Test
  def test_neteye_static_nat_respects_its_service_condition
    parsed = Algosec::Config::Parser.perform("policy mip 9 10.0.0.1 203.0.113.9\npolicy mip 9 matching protocol tcp port 443\n", vendor: :neteye, device_id: 1)
    assert parsed.complete?, parsed.diagnostics.inspect
    resolver = Algosec::Policy::Nat::Resolver.new(Algosec::Policy::Snapshot.from_config(parsed))
    nat = parsed.elements(Algosec::Elements::StaticNat).sole
    options = { zone: nat.mapped_zone, direction: :source, peers: { "192.0.2.1" => {} } }

    assert resolver.find("10.0.0.1", **options, services: { "tcp/443" => {} })
    assert_nil resolver.find("10.0.0.1", **options, services: { "udp/53" => {} })
  end

  def test_fortinet_scheduled_source_nat_cannot_prove_unconditional_translation
    content = File.read(TestPaths.root.join("test/fixtures/config/fortinet.cfg"))
    content = content.sub("set action accept", "set action accept\n        set nat enable")
    content = content.sub('set schedule "always"', 'set schedule "office"')
    content = <<~CONFIG + content
      config firewall schedule onetime
        edit office
          set start 09:00 2030/01/01
          set end 18:00 2030/01/01
        next
      end
    CONFIG
    parsed = Algosec::Config::Parser.perform(content, vendor: :fortinet, device_id: 1)
    assert parsed.complete?, parsed.diagnostics.inspect
    resolver = Algosec::Policy::Nat::Resolver.new(Algosec::Policy::Snapshot.from_config(parsed))

    error = assert_raises(Algosec::Policy::Error) do
      resolver.find("10.0.0.10", zone: "outside", direction: :source,
                    peers: { "198.51.100.20" => {} }, services: { "tcp/443" => {} })
    end
    assert_equal :conditional_nat, error.code
  end
end
