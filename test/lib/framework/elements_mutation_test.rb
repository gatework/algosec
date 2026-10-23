# frozen_string_literal: true

require_relative "../../test_helper"

class ElementsMutationTest < Minitest::Test
  E = Algosec::Elements

  def test_invalid_configuration_replacement_preserves_text_and_presence
    [ {}, { config: "original" }, { config_present: true } ].each do |attributes|
      address = E::AddressObject.new(name: "host", **attributes)
      present, available = address.config_present?, address.config_available?
      original = address.config if available

      assert_raises(ArgumentError) { address.replace_config("valid line", nil) }

      assert_equal present, address.config_present?
      assert_equal available, address.config_available?
      if available
        original.nil? ? assert_nil(address.config) : assert_same(original, address.config)
      else
        assert_raises(Algosec::Config::SourceUnavailable) { address.config }
      end
    end
  end

  def test_successful_configuration_replacement_publishes_normalized_owned_text
    address = E::AddressObject.new(name: "host", config_present: true)
    line = +"address host\r\n"

    assert_equal "address host\n ip 192.0.2.1", address.replace_config(line, " ip 192.0.2.1\n")
    line.clear

    assert address.config_present?
    assert address.config_available?
    assert_equal "address host\n ip 192.0.2.1", address.config
    assert address.config.frozen?
  end

  def test_failed_dns_refresh_preserves_all_answers_and_redacted_error_evidence
    address = address_with_redacted_dns_errors
    original = address.dns_answers
    resolver = Object.new
    resolver.define_singleton_method(:resolve) do |domain|
      raise IOError, "resolver unavailable" if domain == "second.example.test"
      { "status" => "resolved", "addresses" => [ "192.0.2.1" ], "expires_at" => "2030-01-01T00:00:00Z" }
    end

    assert_raises(IOError) { address.resolve_domains!(resolver) }

    assert_same original, address.dns_answers
    original.each_key do |domain|
      assert address.dns_error_key?(domain)
      assert address.dns_error_present?(domain)
      assert_raises(Algosec::Config::SourceUnavailable) { address.dns_error(domain) }
    end
  end

  def test_successful_dns_refresh_replaces_answers_and_clears_prior_error_evidence
    address = address_with_redacted_dns_errors
    answer = { "status" => "resolved", "addresses" => [ "192.0.2.1" ], "expires_at" => "2030-01-01T00:00:00Z" }
    resolver = Object.new
    resolver.define_singleton_method(:resolve) { |_| answer }

    assert_same address, address.resolve_domains!(resolver)

    assert_equal 2, address.dns_answers.size
    address.dns_answers.each do |domain, actual|
      assert_equal answer, actual
      refute address.dns_error_key?(domain)
      refute address.dns_error_present?(domain)
      assert_nil address.dns_error(domain)
      assert actual.fetch("addresses").frozen?
    end
    answer.fetch("addresses").clear
    assert_equal [ "192.0.2.1" ], address.dns_answers.fetch("first.example.test").fetch("addresses")
  end

  private

  def address_with_redacted_dns_errors
    domains = %w[first.example.test second.example.test]
    address = E::AddressObject.new(name: "domains", member: domains.map { |domain| { type: "domain", value: domain } })
    address.restore_dns_answers!(domains.to_h do |domain|
      [ domain, { "error_key" => true, "error_present" => true,
                  "evidence" => { "status" => "unresolved", "addresses" => [], "expires_at" => "2030-01-01T00:00:00Z" } } ]
    end)
  end
end
