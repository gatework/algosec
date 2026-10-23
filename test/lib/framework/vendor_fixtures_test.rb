# frozen_string_literal: true

require_relative "../../test_helper"

class VendorFixturesTest < Minitest::Test
  E = Algosec::Elements

  # 这些样例来自迁移源中的人工配置，期望范围由配置内容明确给出。
  def test_address_service_and_nat_semantics_from_saved_configurations
    expectations = {
      asa: [ "server", "192.0.2.10", "web", "tcp/443" ],
      huawei: [ "clients", "192.0.2.10", "web", "tcp/443" ],
      hillstone: [ "client", "192.0.2.10", "http", "tcp/80" ],
      neteye: [ "clients", "192.0.2.10 192.0.2.20-192.0.2.30", "web", "tcp/443" ],
      topsec: [ "clients", "192.0.2.10 192.0.2.20", "https", "tcp/443" ]
    }
    expectations.each do |vendor, (name, addresses, service, protocol)|
      result = Algosec::Config::Parser.perform(File.read(TestPaths.root.join("test/fixtures/config/#{vendor}.cfg")),
                                               vendor: vendor, device_id: 1, reference_time: Time.utc(2026, 9, 14, 12))
      if vendor == :huawei
        refute result.complete?
        assert_equal %i[unsupported_nat_action unsupported_nat_server_reverse], result.diagnostics.map(&:code)
        error = assert_raises(Algosec::Policy::Error) { Algosec::Policy::Snapshot.from_config(result) }
        assert_equal :incomplete_configuration, error.code
      else
        assert result.complete?, "#{vendor}: #{result.diagnostics.inspect}"
      end
      object = result.find(E::AddressObject, name: name) || result.find(E::AddressGroup, name: name)
      assert_equal addresses.split.map { |value| Algosec::IPAddr.parse(value) }.reduce(:|), object.set, vendor.to_s
      service_object = result.find(E::ServiceObject, name: service) || result.find(E::ServiceGroup, name: service)
      assert service_object.set.cover?(Algosec::IPAddr.service(protocol)), vendor.to_s
      assert result.rules.any?, vendor.to_s
      assert result.elements(E::DynamicNat).any?, vendor.to_s
      assert result.elements(E::DynamicNat).any? { |nat| nat.source_targets&.include?(Algosec::IPAddr.to_i("198.51.100.100")) }, vendor.to_s
    end
  end

  def test_all_parser_instances_can_be_reused_after_a_partial_document
    Algosec::Vendors.names(:parser).each do |vendor|
      parser = Algosec::Vendors.fetch(vendor, :parser).new(device_id: 1)
      input = vendor == :hillstone ? "rule id 1\n unknown-match value\nexit\n" : "unsupported-platform-command\n"
      partial = parser.perform(input)
      refute partial.complete?, vendor.to_s
      clean = parser.perform("")
      assert clean.complete?, vendor.to_s
      assert_empty clean.catalog.to_a, vendor.to_s
    end
  end
end
