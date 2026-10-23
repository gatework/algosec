# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "../framework/support/policy_factory"
require "algosec/config/document"

class NatDestinationPortRelationTest < Minitest::Test
  include PolicyFactory

  def configuration(external: "443-444", internal: "8443-8444", mapping: nil)
    <<~CONFIG
      config firewall vip
       edit "publication"
        set extip 203.0.113.9
        set extintf "any"
        set mappedip "10.0.0.9"
        set portforward enable
        set protocol tcp
        set extport #{external}
        set mappedport #{internal}
        #{"set portmapping-type #{mapping}" if mapping}
       next
      end
    CONFIG
  end

  def parse(text = configuration)
    parsed = Algosec::Config::Parser.perform(text, vendor: :fortinet, device_id: 1)
    assert parsed.complete?, parsed.diagnostics.inspect
    parsed
  end

  def expectation(original: "443", translated: "8443")
    P::Nat::Verification::Expectation.new(address: "10.0.0.9", direction: :destination, zone: "outside",
      peers: { "192.0.2.1" => {} }, allocation: { type: :static, address: "203.0.113.9" },
      services: { "tcp/#{original}" => { origin: "tcp/#{original}", translated_port: translated } },
      flow: { from_zone: "outside", to_zone: "inside", original_dst: "203.0.113.9" })
  end

  def prove(config, **ports)
    baseline = P::Snapshot.from_config(config)
    change = P::ChangeSet.new(snapshot: baseline, intents: [], targets: [])
    proof = P::Nat::Verification.new(snapshot: baseline, candidate: change.apply, expectations: [ expectation(**ports) ], change_set: change)
    plan = P::Plan.new(operation: :configure, snapshot: baseline, changes: [], change_set: change,
      commands: "", required_effects: [ :nat ], effect_proofs: { nat: proof })
    [ proof, plan ]
  end

  def test_wrong_offset_cannot_reuse_existing_vip
    baseline = P::Snapshot.from_config(parse)
    expected = expectation(translated: "8444")
    error = assert_raises(P::Error) { P::Nat::Resolver.new(baseline).find(expected.address, **expected.options) }
    assert_equal :conditional_nat, error.code
  end

  def test_wrong_offset_cannot_pass_effect_proof_or_readback
    parsed = parse
    proof, plan = prove(parsed, translated: "8444")
    refute proof.verified?
    refute plan.ready?
    refute proof.verify_readback(P::Snapshot.from_config(parse)).verified?
  end

  def test_correct_offset_subsets_and_complete_range_pass_readback
    [ [ "443", "8443" ], [ "444", "8444" ], [ "443-444", "8443-8444" ] ].each do |before, after|
      [ nil, "1-to-1" ].each do |mapping|
        text = configuration(mapping: mapping)
        proof, plan = prove(parse(text), original: before, translated: after)
        assert proof.verified?, proof.to_h.inspect
        assert plan.ready?, plan.issues.inspect
        assert plan.verify_readback(P::Snapshot.from_config(parse(text))).verified?
      end
    end
  end

  def test_identity_range_does_not_allow_crossed_ports
    config = parse(configuration(internal: "443-444"))
    assert prove(config, original: "443", translated: "443").first.verified?
    refute prove(config, original: "443", translated: "444").first.verified?
  end

  def test_one_to_one_mapped_start_expands_to_the_external_span
    config = parse(configuration(internal: "8443"))
    assert prove(config, original: "444", translated: "8444").first.verified?
    refute prove(config, original: "444", translated: "8443").first.verified?
  end

  def test_many_to_one_rewrite_preserves_constant_target
    config = parse(configuration(internal: "8443", mapping: "m-to-n"))
    [ "443", "444", "443-444" ].each do |before|
      assert prove(config, original: before, translated: "8443").first.verified?
    end
    refute prove(config, translated: "8444").first.verified?
  end

  def test_many_to_many_allocation_does_not_prove_a_fixed_port_pair
    config = parse(configuration(mapping: "m-to-n"))
    [ "8443", "8444", "8443-8444" ].each do |target|
      refute prove(config, translated: target).first.verified?
    end
  end

  def test_config_document_and_cache_preserve_the_port_mapping_mode
    [ nil, "1-to-1", "m-to-n" ].each do |mode|
      config = parse(configuration(mapping: mode))
      restored = Algosec::Config::Document.load(Algosec::Config::Document.dump(config))
      cache = Algosec::Config::Cache.new
      cache.save(config)
      [ restored, cache.load(1) ].each do |copy|
        assert_equal mode == "m-to-n" ? :pool : :offset, copy.elements(E::DynamicNat).sole.destination_translation.port_mapping
        refute prove(copy, translated: "8444").first.verified?
        assert prove(copy).first.verified? unless mode == "m-to-n"
      end
    end
  end

  def test_invalid_one_to_one_ranges_remain_incomplete
    [ { internal: "8443-8445" }, { external: "443-445", internal: "65535" }, { mapping: "invalid" } ].each do |options|
      parsed = Algosec::Config::Parser.perform(configuration(**options), vendor: :fortinet, device_id: 1)
      refute parsed.complete?, options.inspect
      restored = Algosec::Config::Document.load(Algosec::Config::Document.dump(parsed))
      refute restored.complete?
    end
  end

  def test_unhandled_port_mapping_does_not_make_non_forwarding_vip_complete
    text = configuration(mapping: "invalid").lines.reject { |line| line.include?("portforward") }.join
    parsed = Algosec::Config::Parser.perform(text, vendor: :fortinet, device_id: 1)

    refute parsed.complete?
  end

  def test_readback_detects_mapping_mode_changes_even_when_port_sets_are_identical
    proof, plan = prove(parse)
    assert proof.verified?
    changed = P::Snapshot.from_config(parse(configuration(mapping: "m-to-n")))

    readback = plan.verify_readback(changed)
    refute readback.verified?
    assert_includes proof.verify_readback(changed).issues.map { |issue| issue.evidence[:code] }, :nat_readback_mismatch
  end

  def test_policy_lookup_cannot_skip_a_wrong_first_port_relation
    common = { **context(:palo_alto), direction: :destination, from_zone: "outside", to_zone: "inside",
      source_set: "0.0.0.0/0", destination_set: "203.0.113.9", translated_destination_set: "10.0.0.9", protocol: "tcp" }
    first = E::DynamicNat.new(**common, name: "first", nat_order: [ 1 ], destination_port: "443-444",
      translated_destination_port: "8443-8444", destination_port_mapping: :offset)
    later = E::DynamicNat.new(**common, name: "later", nat_order: [ 2 ], destination_port: "443", translated_destination_port: "8444")
    baseline = snapshot(:palo_alto, [ first, later ])
    wanted = expectation(translated: "8444")

    error = assert_raises(P::Error) { P::Nat::Resolver.new(baseline).find(wanted.address, **wanted.options) }
    assert_equal :conditional_nat, error.code
  end

  def test_equal_port_spans_without_declared_offset_do_not_prove_a_pair
    nat = E::DynamicNat.new(**context(:palo_alto), name: "unknown-range", direction: :destination,
      from_zone: "outside", to_zone: "inside", source_set: "0.0.0.0/0", destination_set: "203.0.113.9",
      translated_destination_set: "10.0.0.9", protocol: "tcp", destination_port: "443-444", translated_destination_port: "8443-8444")
    wanted = expectation
    error = assert_raises(P::Error) { P::Nat::Resolver.new(snapshot(:palo_alto, [ nat ])).find(wanted.address, **wanted.options) }
    assert_equal :conditional_nat, error.code
  end

  def test_discovery_cannot_discard_an_unknown_port_relation
    common = { **context(:palo_alto), direction: :destination, from_zone: "outside", to_zone: "inside",
      source_set: "0.0.0.0/0", translated_destination_set: "10.0.0.9", protocol: "tcp", destination_port: "443" }
    unknown = E::DynamicNat.new(**common, name: "unknown", nat_order: [ 1 ], destination_set: "203.0.113.9",
      translated_destination_port: "8443-8444")
    fixed = E::DynamicNat.new(**common, name: "fixed", nat_order: [ 2 ], destination_set: "203.0.113.10",
      translated_destination_port: "8443")
    wanted = expectation
    options = wanted.options.merge(allocation: nil, flow: { from_zone: "outside", to_zone: "inside" })

    error = assert_raises(P::Error) { P::Nat::Resolver.new(snapshot(:palo_alto, [ unknown, fixed ])).find(wanted.address, **options) }
    assert_equal :conditional_nat, error.code
  end

  def test_load_balancing_preserves_unknown_backend_port_semantics
    %w[0 8443].each do |port|
      text = <<~CONFIG
        config firewall vip
         edit "load-balanced"
          set type server-load-balance
          set extip 203.0.113.9
          set extintf "any"
          set extport 443
          config realservers
           edit 1
            set ip 10.0.0.9
            set port #{port}
           next
          end
         next
        end
      CONFIG
      parsed = Algosec::Config::Parser.perform(text, vendor: :fortinet, device_id: 1)
      refute parsed.complete?
      assert_includes parsed.diagnostics.map(&:code), :unsupported_vip_load_balance
      assert_equal :unknown, parsed.elements(E::DynamicNat).sole.destination_port_mapping
      restored = Algosec::Config::Document.load(Algosec::Config::Document.dump(parsed))
      refute restored.complete?
      error = assert_raises(P::Error) { P::Snapshot.from_config(restored) }
      assert_equal :incomplete_configuration, error.code
      baseline = P::Snapshot.from_config(restored, allow_incomplete: true)
      proof = P::Nat::Verification.new(snapshot: baseline, candidate: baseline, expectations: [ expectation(translated: port) ])
      refute proof.verified?
      refute proof.verify_readback(baseline).verified?
    end
  end

  def test_policy_segmentation_keeps_each_requested_port_translation
    pool = E::NatPool.new(**context(:huawei), name: "pool", ip: "10.0.0.9", direction: :destination)
    rows = [ [ "443", "8443" ], [ "444", "8444" ] ].each_with_index.map do |(before, after), index|
      E::DynamicNat.new(**context(:huawei), name: "rule#{index}", direction: :destination, nat_order: [ 0, index + 1 ],
        from_zone: "outside", source_set: "0.0.0.0/0", destination_set: "203.0.113.9", protocol: "tcp",
        destination_port: before, translated_destination_port: after, translated_destination_set: "10.0.0.9", destination_pool: pool,
        extra_conf: { "match" => { "to_zone" => nil, "interface" => nil } })
    end
    baseline = snapshot(:huawei, [ pool, *rows ])
    fields = expectation(original: "443-444", translated: "8443-8444").to_h
    wanted = P::Nat::Verification::Expectation.new(**fields.merge(allocation: { type: :dynamic, address: "203.0.113.9" }))
    proof = P::Nat::Verification.new(snapshot: baseline, candidate: baseline, expectations: [ wanted ])

    assert proof.verified?, proof.to_h.inspect
    assert_equal 2, proof.observations.size
    assert proof.verify_readback(baseline).verified?
  end

  def test_server_map_cannot_bypass_destination_port_relation
    [ [ "443", "8444", :unknown ], [ "443-444", "8443-8444", :offset ] ].each do |before, after, mode|
      nat = E::DynamicNat.new(**context(:huawei), name: "server", rule_set: "nat-server", direction: :destination,
        from_zone: "outside", source_set: "0.0.0.0/0", destination_set: "203.0.113.9", translated_destination_set: "10.0.0.9",
        protocol: "tcp", destination_port: before, translated_destination_port: after, destination_port_mapping: mode)
      baseline = snapshot(:huawei, [ nat ])
      wanted = expectation(translated: "8444")

      error = assert_raises(P::Error) { P::Nat::Resolver.new(baseline).find(wanted.address, **wanted.options) }
      assert_equal :conditional_nat, error.code
      consumed = { address: "203.0.113.9/32", type: :dynamic, rule: nat, acl_name: nil }
      error = assert_raises(P::Error) do
        P::Nat::Resolver.new(baseline).guard_unchanged!(source: "192.0.2.1", destination: "203.0.113.9",
          directions: [ :source ], services: wanted.options[:services], flow: wanted.options[:flow], mappings: { destination: consumed })
      end
      assert_equal :conditional_nat, error.code
      proof = P::Nat::Verification.new(snapshot: baseline, candidate: baseline, expectations: [ wanted ])
      refute proof.verified?
      refute proof.verify_readback(snapshot(:huawei, [ nat ])).verified?
    end
  end

  def test_native_server_map_preserves_protocol_only_identity
    [ [ "tcp", "tcp/443" ], [ "udp", "udp/53" ], [ "icmp", "icmp" ] ].each do |protocol, service|
      text = "nat server web zone outside protocol #{protocol} global 203.0.113.9 inside 10.0.0.9 no-reverse\n"
      parsed = Algosec::Config::Parser.perform(text, vendor: :huawei, device_id: 1)
      assert parsed.complete?, parsed.diagnostics.inspect
      restored = Algosec::Config::Document.load(Algosec::Config::Document.dump(parsed))
      baseline = P::Snapshot.from_config(restored)
      wanted = P::Nat::Verification::Expectation.new(**expectation.to_h.merge(services: { service => { origin: service } }))
      proof = P::Nat::Verification.new(snapshot: baseline, candidate: baseline, expectations: [ wanted ])

      assert proof.verified?, proof.to_h.inspect
      assert proof.verify_readback(P::Snapshot.from_config(parsed)).verified?
    end
  end

  def test_native_server_map_keeps_inherited_and_explicit_target_ports
    [ [ "", "443" ], [ " 8443", "8443" ] ].each do |private_port, expected|
      text = "nat server web zone outside protocol tcp global 203.0.113.9 443 inside 10.0.0.9#{private_port} no-reverse\n"
      parsed = Algosec::Config::Parser.perform(text, vendor: :huawei, device_id: 1)
      assert parsed.complete?, parsed.diagnostics.inspect
      proof, plan = prove(parsed, translated: expected)

      assert proof.verified?, proof.to_h.inspect
      assert plan.ready?, plan.issues.inspect
      assert proof.verify_readback(P::Snapshot.from_config(parsed)).verified?
    end
  end
end
