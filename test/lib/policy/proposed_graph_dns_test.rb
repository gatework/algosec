# frozen_string_literal: true

require "test_helper"
require "algosec/policy/plan_document"

class ProposedGraphDnsTest < ActiveSupport::TestCase
  test "approved graph retains the DNS observation and validates its resolver context" do
    at = Time.utc(2030, 1, 1)
    context = { "device_id" => 1, "source" => "device", "servers" => [ "192.0.2.53" ] }
    evidence = { "status" => "resolved", "addresses" => [ "192.0.2.1" ], "source" => context,
      "resolved_at" => at.iso8601(6), "expires_at" => (at + 600).iso8601(6) }
    resolver = Object.new
    resolver.define_singleton_method(:resolve) { |_name| evidence }
    address = Algosec::Elements::AddressObject.new(vendor: :hillstone, device_id: 1, name: "domain",
      member: [ { type: "domain", value: "example.test" } ])
    address.resolve_domains!(resolver)
    catalog = Algosec::Elements::Catalog.new([ address ], vendor: :hillstone, device_id: 1).seal!
    snapshot = Algosec::Policy::Snapshot.new(vendor: :hillstone, device_id: 1, catalog: catalog)
    codec = Algosec::Policy::PlanDocument::ProposedGraph
    document = JSON.parse(JSON.generate(codec.dump(catalog.to_a, snapshot: snapshot, at: at)))
    assert_equal context, document.fetch("context").fetch("dns_context")
    restored = codec.load(document, snapshot: snapshot).sole
    assert_equal address.dns_answers, restored.dns_answers
    assert_equal address.address_projection(at: at), restored.address_projection(at: at)
    assert restored.sealed?
    document.fetch("context")["dns_context"] = context.merge("servers" => [ "192.0.2.54" ])
    assert_raises(Algosec::Config::Document::InvalidDocument) { codec.load(document, snapshot: snapshot) }
  end
end
