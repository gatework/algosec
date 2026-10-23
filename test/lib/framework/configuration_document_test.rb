# frozen_string_literal: true

require_relative "../../test_helper"
require "json"
require "open3"
require "tempfile"
require_relative "support/configuration_document_probe"

class ConfigurationDocumentTest < Minitest::Test
  E = Algosec::Elements
  C = Algosec::Config
  AT = Time.iso8601("2026-10-22T10:11:12.123456789+08:00").freeze

  def setup
    assert C.const_defined?(:Document), "Config::Document must expose the versioned semantic document boundary"
  end

  def parse(content = configuration, vendor: :hillstone, **options)
    C::Parser.perform(content, vendor: vendor, device_id: 7, device_name: "edge", reference_time: AT, **options)
  end

  def configuration
    "address host\n ip 192.0.2.1/32\nexit\nrule id 1\n action permit\n src-addr host\nexit\n"
  end

  def json(value) = JSON.parse(JSON.generate(value))

  def test_detached_round_trip_retains_shared_references_identity_and_sealing
    original = parse
    document = json(C::Document.dump(original))
    restored = C::Document.load(document, expected_source_sha256: original.reader.source_sha256)
    address = restored.find(E::AddressObject, name: "host")

    assert_equal 1, document.fetch("schema_version")
    assert_kind_of String, document.fetch("semantic_version")
    assert_nil document.fetch("raw_details")
    refute_includes JSON.generate(document), "src-addr host"
    refute restored.reader.source_attached?
    assert_raises(C::SourceUnavailable) { restored.reader.content }
    assert_same address, restored.rules.first.sources.members.fetch("host")
    assert_equal original.catalog.map(&:identity), restored.catalog.map(&:identity)
    assert_equal original.reference_counts, restored.reference_counts
    assert_equal AT, restored.reference_time
    assert_equal original.reader.source_metadata, restored.reader.source_metadata
    assert_equal document, json(C::Document.dump(restored))
    assert_raises(FrozenError) { address.add(type: "host", value: "192.0.2.2") }
    assert_raises(C::SourceUnavailable) { restored.rules.first.config }
  end

  def test_raw_details_and_source_attachment_are_explicit_and_exact
    original = parse(configuration + "private-unsupported-command\n", source_complete: false)
    document = json(C::Document.dump(original, raw: true))
    restored = C::Document.load(document, source_content: original.reader.content)

    assert_equal original.reader.content, restored.reader.content
    assert_equal original.reader.unparsed_lines, restored.reader.unparsed_lines
    assert_equal original.catalog.map(&:config), restored.catalog.map(&:config)
    assert_equal original.diagnostics.map(&:to_h), restored.diagnostics.map(&:to_h)
    refute restored.complete?
    assert_equal document, json(C::Document.dump(restored, raw: true))
    assert_raises(C::Document::InvalidDocument) { C::Document.load(document, source_content: "different") }
    document.fetch("raw_details")["source_sha256"] = "0" * 64
    assert_raises(C::Document::InvalidDocument) { C::Document.load(document) }
  end

  def test_context_tracks_actual_parse_time_effective_settings_and_rejects_mismatch
    reader = C::Reader.new(configuration, vendor: :hillstone, device_id: 7, created_at: AT - 60)
    original = parse(reader, time_zone: "Asia/Hong_Kong")
    document = json(C::Document.dump(original))
    context = document.fetch("context")

    assert_equal AT.iso8601(9), context.fetch("reference_time")
    assert_equal "Asia/Hong_Kong", context.fetch("time_zone")
    assert_equal({}, context.fetch("settings"))
    assert_equal original.reader.created_at.iso8601(9), document.fetch("source").fetch("created_at")
    assert C::Document.load(document, expected_context: context).complete?
    assert_raises(C::Document::InvalidDocument) { C::Document.load(document, expected_context: context.merge("device_id" => 8)) }
    assert_raises(C::Document::InvalidDocument) { C::Document.load(document, expected_source_sha256: "f" * 64) }
    fortinet = Algosec::Vendors::Fortinet::Parser.new(vdom: "tenant", device_id: 7, reference_time: AT).perform("")
    assert_equal({ "vdom" => "tenant" }, C::Document.dump(fortinet).fetch("context").fetch("settings"))
  end

  def test_structural_corruption_is_rejected_before_publication
    document = json(C::Document.dump(parse))
    mutations = [
      ->(data) { data["schema_version"] = 99 },
      ->(data) { data["semantic_version"] = "unknown" },
      ->(data) { data["extra"] = true },
      ->(data) { data.fetch("source")["content"] = "secret" },
      ->(data) { data.fetch("nodes").first["kind"] = "Object" },
      ->(data) { data.fetch("nodes").first.fetch("attributes")["extra"] = true },
      ->(data) { data.fetch("nodes").first["identity_fields"] = [ "wrong" ] },
      ->(data) { data.fetch("catalog") << "missing" },
      ->(data) { data.fetch("catalog") << data.fetch("catalog").first },
      ->(data) { data.fetch("nodes") << data.fetch("nodes").first.dup }
    ]
    mutations.each do |mutation|
      damaged = json(document)
      mutation.call(damaged)
      assert_raises(C::Document::InvalidDocument) { C::Document.load(damaged) }
    end
  end

  def test_previous_semantic_revision_cannot_restore_as_current_configuration
    %w[firewall-domain-v1 firewall-domain-v2 firewall-domain-v3 firewall-domain-v4 firewall-domain-v5].each do |version|
      document = json(C::Document.dump(parse))
      document["semantic_version"] = version

      assert_raises(C::Document::InvalidDocument) { C::Document.load(document) }
    end
  end

  def test_every_vendor_full_and_partial_graph_round_trips_through_json
    inputs = {
      srx: "set security address-book global address host 192.0.2.1/32\nset applications application web protocol tcp\nset applications application web destination-port 443\n",
      h3c: "acl advanced 3000\n rule 10 permit tcp source any destination any destination-port eq 443\n#\n",
      netscreen: "set address Trust host 192.0.2.1 255.255.255.255\nset service web protocol tcp src-port 0-65535 dst-port 443-443\n"
    }
    %i[asa fortinet hillstone huawei neteye palo_alto topsec].each do |vendor|
      inputs[vendor] = File.read(TestPaths.root.join("test/fixtures/config/#{vendor}.cfg"))
    end
    assert_equal 10, inputs.size
    process_cases = []
    inputs.each do |vendor, content|
      [ true, false ].each do |source_complete|
        original = parse(content, vendor: vendor, source_complete: source_complete)
        document = json(C::Document.dump(original, raw: true))
        restored = C::Document.load(document, source_content: content)
        assert_equal original.complete?, restored.complete?, vendor.to_s
        assert_equal original.catalog.map(&:identity), restored.catalog.map(&:identity), vendor.to_s
        assert_equal original.rules.map(&:locator), restored.rules.map(&:locator), vendor.to_s
        assert_equal original.rules.map { |rule| [ rule.action, rule.native_action, rule.status, rule.conditions ] },
          restored.rules.map { |rule| [ rule.action, rule.native_action, rule.status, rule.conditions ] }, vendor.to_s
        assert_equal original.reference_counts, restored.reference_counts, vendor.to_s
        assert_equal original.catalog.map(&:config), restored.catalog.map(&:config), vendor.to_s
        assert_equal document, json(C::Document.dump(restored, raw: true)), vendor.to_s
        process_cases << { "document" => document, "expected" => json(ConfigurationDocumentProbe.call(original, at: AT)) }
      end
    end
    Tempfile.create([ "algosec-vendor-documents", ".json" ]) do |file|
      file.write(JSON.generate(process_cases))
      file.flush
      script = <<~'CODE'
        require "algosec"
        require "json"
        require_relative "test/lib/framework/support/configuration_document_probe"
        Algosec::Config::Parser.define_singleton_method(:perform) { |*| raise "Unexpected parse" }
        Algosec::Vendors.names(:parser).each do |vendor|
          Algosec::Vendors.fetch(vendor, :parser).define_method(:perform) { |*| raise "Unexpected parse" }
        end
        results = JSON.parse(File.read(ARGV.fetch(0))).map do |entry|
          result = Algosec::Config::Document.load(entry.fetch("document"))
          ConfigurationDocumentProbe.call(result, at: Time.iso8601(ARGV.fetch(1)))
        end
        puts JSON.generate(results)
      CODE
      output, error, status = Open3.capture3(RbConfig.ruby, "-Ilib", "-e", script, file.path, AT.iso8601(9), chdir: TestPaths.root.to_s)
      assert status.success?, error
      assert_equal process_cases.map { |entry| entry.fetch("expected") }, JSON.parse(output)
    end
  end

  def test_fresh_process_loads_json_and_queries_without_invoking_any_parser
    original = parse
    Tempfile.create([ "algosec-document", ".json" ]) do |file|
      file.write(JSON.generate(C::Document.dump(original)))
      file.flush
      script = <<~'CODE'
        require "algosec"
        require "json"
        Algosec::Config::Parser.define_singleton_method(:perform) { |*| raise "Document must not parse" }
        Algosec::Vendors.names(:parser).each do |vendor|
          Algosec::Vendors.fetch(vendor, :parser).define_method(:perform) { |*| raise "Document must not parse" }
        end
        result = Algosec::Config::Document.load(JSON.parse(File.read(ARGV.fetch(0))))
        address = result.find(Algosec::Elements::AddressObject, name: "host")
        puts JSON.generate({ address: address.set.include?(Algosec::IPAddr.to_i("192.0.2.1")),
          alias: result.rules.first.sources.members.fetch("host").equal?(address),
          action: result.rules.first.action, detached: !result.reader.source_attached?, sealed: address.sealed? })
      CODE
      output, error, status = Open3.capture3(RbConfig.ruby, "-Ilib", "-e", script, file.path, chdir: TestPaths.root.to_s)
      assert status.success?, error
      assert_equal({ "address" => true, "alias" => true, "action" => "allow", "detached" => true, "sealed" => true }, JSON.parse(output))
    end
  end

  def context = { vendor: :hillstone, device_id: 7 }

  def result_for(*objects, diagnostics: [], builtins: {}, dns_context: nil)
    C::Result.new(reader: C::Reader.new("manual-source\n", **context, created_at: AT),
      catalog: E::Catalog.new(objects, **context), diagnostics: diagnostics, at: AT,
      builtin_services: builtins, dns_context: dns_context, time_zone: "Asia/Hong_Kong")
  end

  def test_full_declarations_and_network_seeds_survive_rebuilding
    scope = E::Scope.new(device_id: 7, virtual_system: "tenant", rulebase: "security", address_book: "book", zone: "inside")
    address = E::AddressObject.new(**context, scope: scope, name: "host", description: "owned", ref_count: 9,
      member: [ { type: "host", value: "192.0.2.1" }, { type: "ipv6", value: "2001:db8::/64" } ], excluded_member: [ { type: "host", value: "192.0.2.2" } ])
    shared = E::AddressGroup.new(**context, name: "shared", members: { "first" => address })
    service = E::ServiceObject.new(**context, name: "web", terms: [
      { protocol: "tcp", source_port: "1024-2048", destination_port: "443", term: "one", uuid: "app", timeout: "60" },
      { protocol: "udp", source_port: "53", destination_port: "53", term: "two" }
    ])
    services = E::ServiceGroup.new(**context, name: "services", protocol: "tcp", members: { "web" => service })
    schedule = E::Schedule.new(**context, name: "hours", kind: :mixed, time_zone: "Asia/Hong_Kong", reference_time: AT - 1,
      start_at: AT - 60, end_at: AT + 3600, periods: { "thu" => [ [ "00:00", "23:59" ], [ "20:00", "10:00" ] ] },
      monthly_periods: [ { "start_day" => 1, "end_day" => 2, "start_time" => "08:00:00", "end_time" => "17:00:00" } ])
    rule = E::SecurityRule.new(**context, scope: scope, name: "policy", native_rule_id: "42", rule_number: 3,
      rule_type: :interzone, native_rule_type: :acl, sources: shared, destinations: shared, services: services,
      from_zones: [ "inside" ], to_zones: [ "outside" ], from_interface: "eth0", dst_interfaces: [ "eth1" ],
      action: "reset-client", native_action: "reset-client", status: "mystery", log: "all", log_enabled: false,
      schedule_name: "hours", schedule: schedule, service_selection: :application_default, applications: [ "ssl" ], source_users: [ "alice" ], nat: true,
      conditions: { "application_check" => "required", "security_profiles" => { "av" => "scan" }, "starts_at" => AT.iso8601,
        "expires_at" => (AT + 3600).iso8601, "unparsed_commands" => [ "unsupported semantics" ], "from_vlans" => { "eth0" => "1" }, "to_vlans" => { "eth1" => "2" } },
      vendor_data: { "aggregate_type" => "member", "aggregate_rule_id" => "parent", "aggregate_status" => "enable" })
    route = E::Route.new(**context, name: "route", subnet: "198.51.100.0/24", source_set: Algosec::IPAddr.parse("10.0.0.0/8"),
      source_interface: "eth0", destination_interface: "vlan1", next_hop: "192.0.2.254", zone: "inside", distance: 30, priority: 2,
      vrf: "tenant", destination_vrf: "destination", extra_conf: { "tag" => [ 1, true, nil ] })
    child = E::Interface.new(**context, name: "vlan1", ipaddr: "192.0.2.1/24", mode: :layer3, zone: "inside", vrf: "tenant",
      routes: [ route ], reachable: Algosec::IPAddr.parse("10.0.0.0/8"), aggregate: "bond0", ipv6_addresses: [ "2001:db8::1/64" ])
    parent = E::Interface.new(**context, name: "parent", vlans: [ "unresolved-vlan" ], reachable: Algosec::IPAddr.parse("172.16.0.0/16"))
    parent.add_vlan(child)
    zone = E::Zone.new(**context, name: "inside", acl_name: "acl", vrf: "tenant", interfaces: [ parent ], reachable: Algosec::IPAddr.parse("203.0.113.0/24"))
    original = result_for(address, service, schedule, rule, zone)
    restored = C::Document.load(json(C::Document.dump(original)))
    loaded_rule = restored.rules.first
    loaded_zone = restored.find(E::Zone, name: "inside")
    loaded_parent = loaded_zone.interfaces.values.first
    loaded_child = loaded_parent.vlan_interfaces.values.first

    assert_same loaded_rule.sources, loaded_rule.destinations
    assert_same restored.find(E::AddressObject, name: "host"), loaded_rule.sources.members.fetch("first")
    assert_equal scope, loaded_rule.scope
    assert_equal service.terms, restored.find(E::ServiceObject, name: "web").terms
    assert_equal rule.semantic_conditions, loaded_rule.semantic_conditions
    assert_equal rule.unparsed_commands_metadata, loaded_rule.unparsed_commands_metadata
    assert_raises(C::SourceUnavailable) { loaded_rule.conditions }
    assert_equal rule.vendor_data, loaded_rule.vendor_data
    assert_equal :application_default, loaded_rule.service_selection
    assert_equal rule.applications, loaded_rule.applications
    assert_equal rule.source_users, loaded_rule.source_users
    assert_equal "mystery", loaded_rule.status
    refute loaded_rule.status_known?
    assert_equal schedule.weekly_windows, loaded_rule.schedule.weekly_windows
    assert_equal schedule.monthly_periods, loaded_rule.schedule.monthly_periods
    assert_equal schedule.reference_time, loaded_rule.schedule.reference_time
    assert_equal schedule.active?(at: AT), loaded_rule.schedule.active?(at: AT)
    assert_equal parent.seed_reachable, loaded_parent.seed_reachable
    assert_equal child.seed_reachable, loaded_child.seed_reachable
    assert_equal zone.seed_reachable, loaded_zone.seed_reachable
    assert_equal zone.set, loaded_zone.set
    assert_equal route.source_set, loaded_child.routes.values.first.source_set
    assert_equal parent.vlans, loaded_parent.vlans
    assert loaded_child.sealed?
    assert_equal json(C::Document.dump(original)), json(C::Document.dump(restored))
  end

  def test_builtin_roots_and_null_references_preserve_distinct_aliases
    explicit = E::ServiceObject.new(**context, name: "web", protocol: "tcp", destination_port: "443")
    builtin = E::ServiceObject.new(**context, name: "web", protocol: "tcp", destination_port: "80")
    unused = E::ServiceObject.new(**context, name: "unused", protocol: "udp", destination_port: "53")
    rule = E::SecurityRule.new(**context, native_rule_id: "1")
    rule.services.add("web", explicit)
    rule.services.add("missing", nil)
    original = result_for(explicit, rule, builtins: { "external-name" => builtin, "unused-key" => unused },
      diagnostics: [ C::Diagnostic.new(:missing_reference, "missing", 1) ])
    restored = C::Document.load(json(C::Document.dump(original)))
    assert_same restored.find(E::ServiceObject, name: "web"), restored.rules.first.services.members.fetch("web")
    refute_same restored.find(E::ServiceObject, name: "web"), restored.builtin_services.fetch("external-name")
    assert_nil restored.rules.first.services.members.fetch("missing")
    assert_equal %w[external-name unused-key], restored.builtin_services.keys
    assert_equal builtin.terms, restored.builtin_services.fetch("external-name").terms
    assert_raises(C::SourceUnavailable) { restored.diagnostics.first.message }
    attached = restored.with_source(original.reader.content)
    assert_same restored.catalog, attached.catalog
    assert_same restored.rules.first, attached.rules.first
  end

  def test_dns_evidence_and_expiry_survive_without_resolution_or_error_text
    address = E::AddressObject.new(**context, name: "domain", member: [ { type: "domain", value: "example.test" } ])
    dns_context = { "device_id" => 7, "source" => "device", "servers" => [ "192.0.2.53" ] }
    answer = { "status" => "unresolved", "addresses" => [], "resolved_at" => AT.iso8601(6),
      "expires_at" => (AT + 15).iso8601(6), "source" => dns_context, "error" => "private DNS error" }
    resolver = Object.new
    resolver.define_singleton_method(:resolve) { |_name| answer }
    address.resolve_domains!(resolver)
    original = result_for(address, dns_context: dns_context)
    document = json(C::Document.dump(original))
    refute_includes JSON.generate(document), "private DNS error"
    restored = C::Document.load(document)
    loaded = restored.find(E::AddressObject, name: "domain")
    assert_equal [], loaded.dns_answers.fetch("example.test").fetch("addresses")
    assert_raises(C::SourceUnavailable) { loaded.dns_error("example.test") }
    refute restored.dns_refresh_required?(dns_context, at: AT + 1)
    assert restored.dns_refresh_required?(dns_context, at: AT + 16)
    assert_equal document, json(C::Document.dump(restored))
    raw = C::Document.load(json(C::Document.dump(original, raw: true)))
    assert_equal address.dns_answers, raw.find(E::AddressObject, name: "domain").dns_answers
    broken = json(document)
    evidence = broken.fetch("nodes").first.fetch("attributes").fetch("dns_answers").fetch("example.test").fetch("evidence")
    evidence.delete("expires_at")
    assert_raises(C::Document::InvalidDocument) { C::Document.load(broken) }
  end

  def test_nat_constructor_values_pair_order_and_shared_references
    address = E::AddressObject.new(**context, name: "host", member: [ { type: "host", value: "192.0.2.1" } ])
    service = E::ServiceObject.new(**context, name: "web", protocol: "tcp", source_port: "1024", destination_port: "443")
    services = E::ServiceGroup.new(**context, name: "services", members: { "web" => service })
    rule = E::SecurityRule.new(**context, native_rule_id: "12", disabled: true, services: services)
    pool = E::NatPool.new(**context, name: "pool", ip: [ "203.0.113.2", "203.0.113.8-203.0.113.9" ], zone: "outside",
      interface: "eth1", direction: :source, port: 10443, mode: "pat", id: "pool-id", alias_name: "alias", arp_reply: false)
    mappings = [ [ "192.0.2.8-192.0.2.9", "198.51.100.8-198.51.100.9" ], [ "192.0.2.1", "198.51.100.1" ] ]
    static = E::StaticNat.new(**context, name: "static", id: "static-id", mapped_ip: "198.51.100.1", real_ip: "192.0.2.1", mappings: mappings,
      destination_set: Algosec::IPAddr.parse("10.0.0.0/8"), real_zone: "inside", mapped_zone: "outside", interface: "eth1", interfaces: [ "eth1", "eth2" ],
      rule_set: "rules", acl_name: "acl", acl_number: 9, mask: "255.255.255.255", nat_order: [ 2, 4 ],
      disabled: false, log_enabled: false, source_nat_enabled: true, match_rule: rule)
    dynamic = E::DynamicNat.new(**context, name: "dynamic", id: "dynamic-id", policy_id: "policy", direction: :bidirectional,
      rule_set: "rules", acl_name: "acl", nat_type: "dynamicport", pool_name: "pool", from_zone: "inside", to_zone: "outside", interface: "eth1",
      protocol: "tcp", source_port: "1024-2048", translated_source_port: "3000-4000", destination_ip: "192.0.2.1", destination_port: "443",
      translated_destination_ip: "198.51.100.1", translated_destination_port: "8443", source_set: Algosec::IPAddr.parse("10.0.0.0/8"),
      destination_set: Algosec::IPAddr.parse("192.0.2.1"), service_set: Algosec::IPAddr.service("tcp/443"),
      translated_source_set: Algosec::IPAddr.parse("203.0.113.2"), translated_destination_set: Algosec::IPAddr.parse("198.51.100.1"),
      translated_service_set: Algosec::IPAddr.service("tcp/8443"), source_pool: pool, destination_pool: pool, service: services,
      translated_service: service, match_rule: rule, references: [ address, services ], vrf: "tenant", nat_order: [ 3, 2 ], log_enabled: true,
      extra_conf: { "src_zones" => [ "inside", "other" ], "dst_zones" => [ "outside" ], "custom" => { "values" => [ 1, true, nil ] } })
    original = result_for(address, service, pool, rule, static, dynamic)
    restored = C::Document.load(json(C::Document.dump(original)))
    loaded_static, loaded_dynamic = restored.elements(E::StaticNat).first, restored.elements(E::DynamicNat).first
    loaded_pool = restored.find(E::NatPool, name: "pool")
    assert_equal static.mappings, loaded_static.mappings
    assert_equal static.translate(Algosec::IPAddr.parse("192.0.2.8")), loaded_static.translate(Algosec::IPAddr.parse("192.0.2.8"))
    assert loaded_static.disabled?
    refute loaded_static.declared_disabled
    assert_same restored.rules.first, loaded_static.match_rule
    assert_same restored.rules.first, loaded_dynamic.match_rule
    assert_same loaded_pool, loaded_dynamic.source_pool
    assert_same loaded_pool, loaded_dynamic.destination_pool
    assert_same restored.find(E::ServiceObject, name: "web"), loaded_dynamic.translated_service
    assert_same restored.rules.first.services, loaded_dynamic.service
    assert_same restored.find(E::AddressObject, name: "host"), loaded_dynamic.references.first
    assert_equal dynamic.original_packet.to_h.reject { |key, _| key == :match_rule }, loaded_dynamic.original_packet.to_h.reject { |key, _| key == :match_rule }
    assert_equal dynamic.source_translation.to_h.reject { |key, _| key == :pool }, loaded_dynamic.source_translation.to_h.reject { |key, _| key == :pool }
    assert_equal dynamic.destination_translation.to_h.reject { |key, _| %i[pool service].include?(key) },
      loaded_dynamic.destination_translation.to_h.reject { |key, _| %i[pool service].include?(key) }
    assert_equal static.original_packet.to_h.reject { |key, _| key == :match_rule }, loaded_static.original_packet.to_h.reject { |key, _| key == :match_rule }
    assert_equal static.source_translation.to_h, loaded_static.source_translation.to_h
    assert_equal static.destination_translation.to_h, loaded_static.destination_translation.to_h
    assert_equal pool.ip, loaded_pool.ip
    assert_equal false, loaded_pool.arp_reply
    assert_equal json(C::Document.dump(original)), json(C::Document.dump(restored))
  end

  def test_negated_address_groups_keep_domain_semantics_independent_of_vendor
    %i[palo_alto hillstone].each do |vendor|
      device = { vendor: vendor, device_id: 7 }
      address = E::AddressObject.new(**device, name: "host", member: [ { type: "host", value: "192.0.2.1" } ])
      negated = E::AddressGroup::Negated.new(**device, name: "negated", members: { "host" => address })
      rule = E::SecurityRule.new(**device, name: "rule", native_rule_id: "1", sources: negated, applications: [ "ssl" ], source_users: [ "alice" ])
      original = C::Result.new(reader: C::Reader.new("manual\n", **device), catalog: E::Catalog.new([ address, rule ], **device), diagnostics: [], at: AT)
      restored = C::Document.load(json(C::Document.dump(original)))
      assert_instance_of E::AddressGroup::Negated, restored.rules.first.sources
      assert_equal negated.set, restored.rules.first.sources.set
      assert_equal negated.set, restored.rule_projection.sources.fetch(restored.rules.first.identity)
      refute restored.rules.first.sources.set.include?(Algosec::IPAddr.to_i("192.0.2.1"))
    end
  end

  def test_dangling_wrong_kind_cycles_surplus_nodes_and_raw_binding_are_rejected
    original = parse
    document = json(C::Document.dump(original))
    rule = document.fetch("nodes").find { |node| node["kind"] == "security_rule" }
    group = document.fetch("nodes").find { |node| node["id"] == rule.fetch("edges").fetch("sources") }
    mutations = [
      ->(data) { data.fetch("nodes").find { |node| node["id"] == rule["id"] }.fetch("edges")["sources"] = "n999999" },
      ->(data) { data.fetch("nodes").find { |node| node["id"] == rule["id"] }.fetch("edges")["sources"] = data.fetch("nodes").first.fetch("id") },
      ->(data) { data.fetch("nodes").find { |node| node["id"] == group["id"] }.fetch("edges")["members"] = [ { "name" => "cycle", "node" => group["id"] } ] },
      ->(data) { data.fetch("nodes") << data.fetch("nodes").first.merge("id" => "n999999") },
      ->(data) { data.fetch("nodes").first.fetch("attributes")["scope"]["device_id"] = 8 },
      ->(data) { data.fetch("nodes").first.fetch("attributes")["direct_member"] = [ false ] }
    ]
    mutations.each do |mutation|
      damaged = json(document)
      mutation.call(damaged)
      assert_raises(C::Document::InvalidDocument) { C::Document.load(damaged) }
    end
    raw = json(C::Document.dump(original, raw: true))
    raw.fetch("nodes").first.fetch("attributes")["description"] = "altered"
    assert_raises(C::Document::InvalidDocument) { C::Document.load(raw) }
    assert_raises(C::Document::InvalidDocument) { C::Document.load(document.merge(schema_version: 1)) }
    assert_raises(C::Document::InvalidDocument) { C::Document.load(document, source_details: { "bad" => true }) }
  end
  def test_version_and_optional_parameters_reject_truthy_or_numeric_aliases
    document = json(C::Document.dump(parse))
    assert_raises(C::Document::InvalidDocument) { C::Document.load(document.merge("schema_version" => 1.0)) }
    assert_raises(C::Document::InvalidDocument) { C::Document.load(document.merge("raw_details" => false)) }
    assert_raises(C::Document::InvalidDocument) { C::Document.load(document, source_details: false) }
    assert_raises(C::Document::InvalidDocument) { C::Document.load(document, expected_context: false) }
    assert_raises(C::Document::InvalidDocument) { C::Document.load(document, expected_source_sha256: false) }
  end

  def test_minimal_injected_dns_evidence_retains_absent_fields_and_projection
    address = E::AddressObject.new(**context, name: "domain", member: [ { type: "domain", value: "example.test" } ])
    answer = { "status" => "resolved", "addresses" => [ "192.0.2.1" ], "expires_at" => (AT + 30).iso8601 }
    resolver = Object.new
    resolver.define_singleton_method(:resolve) { |_| answer }
    address.resolve_domains!(resolver)
    original = result_for(address, dns_context: { "servers" => [ "192.0.2.53" ] })
    restored = C::Document.load(json(C::Document.dump(original)))
    loaded = restored.find(E::AddressObject, name: "domain")
    assert_equal answer, loaded.dns_answers.fetch("example.test")
    assert_equal address.address_projection(at: AT), loaded.address_projection(at: AT)
    assert_equal Algosec::IPAddr.parse("192.0.2.1"), loaded.address_projection(at: AT).fetch(:set)
    refute restored.dns_refresh_required?(original.dns_context, at: AT)
    assert restored.dns_refresh_required?(original.dns_context, at: AT + 31)
  end

  def test_detached_result_retains_raw_availability_across_existing_cache
    require "active_support/cache"
    original = parse(configuration + "unsupported-private-command\n", source_complete: false)
    restored = C::Document.load(json(C::Document.dump(original))).bind_source!("document-version")
    cache = C::Cache.new(store: ActiveSupport::Cache::MemoryStore.new)
    cache.save(restored, source_key: "document-version")
    cached = cache.load(7, source_key: "document-version")
    assert cached.catalog.sealed?
    refute cached.reader.source_attached?
    assert_raises(C::SourceUnavailable) { cached.rules.first.config }
    assert_raises(C::SourceUnavailable) { cached.diagnostics.first.message }
    assert_equal json(C::Document.dump(restored)), json(C::Document.dump(cached))
  end
  def test_invalid_document_errors_do_not_reveal_rejected_declaration_text
    document = json(C::Document.dump(parse))
    document.fetch("nodes").first.fetch("attributes").fetch("direct_member").first["value"] = "private-rejected-address"
    error = assert_raises(C::Document::InvalidDocument) { C::Document.load(document) }
    refute_includes error.full_message, "private-rejected-address"
    assert_nil error.cause
  end
  def test_protected_details_do_not_bypass_nested_structure_validation
    document = json(C::Document.dump(parse(source_complete: false), raw: true))
    document.fetch("diagnostics")[0] = false
    document.fetch("raw_details")["document_sha256"] = C::Document::Value.digest(document.merge("raw_details" => nil))
    assert_raises(C::Document::InvalidDocument) { C::Document.load(document) }
  end
  def test_document_rejects_impossible_dates_in_rule_declarations
    rule_document = json(C::Document.dump(parse("rule id 1\n action permit\nexit\n")))
    %w[starts_at expires_at].each do |field|
      broken = json(rule_document)
      broken.fetch("nodes").find { |node| node.fetch("kind") == "security_rule" }.fetch("attributes").fetch("conditions")[field] = "2026-02-31T10:11:12Z"
      assert_raises(C::Document::InvalidDocument, "rule #{field}") { C::Document.load(broken) }
    end
  end

  def test_document_rejects_impossible_dates_in_dns_declarations
    address = E::AddressObject.new(**context, name: "domain", member: [ { type: "domain", value: "example.test" } ])
    answer = { "status" => "resolved", "addresses" => [ "192.0.2.1" ], "resolved_at" => "2026-02-01T10:11:12Z", "expires_at" => "2026-04-01T10:11:12Z" }
    resolver = Object.new
    resolver.define_singleton_method(:resolve) { |_name| answer }
    address.resolve_domains!(resolver)
    document = json(C::Document.dump(result_for(address)))
    %w[resolved_at expires_at].each do |field|
      broken = json(document)
      broken.fetch("nodes").first.fetch("attributes").fetch("dns_answers").fetch("example.test").fetch("evidence")[field] = "2026-02-31T10:11:12.123Z"
      assert_raises(C::Document::InvalidDocument, "DNS #{field}") { C::Document.load(broken) }
    end
  end

  def test_document_preserves_valid_declaration_timestamp_precision_and_offsets
    [ "2024-02-29T10:11:12Z", "2024-02-29T10:11:12.1Z", "2024-02-29T10:11:12.123456+08:00", "2024-02-29T10:11:12.123456789123-04:30" ].each do |timestamp|
      rule = E::SecurityRule.new(**context, native_rule_id: "1", conditions: { "starts_at" => timestamp, "expires_at" => timestamp })
      address = E::AddressObject.new(**context, name: "domain", member: [ { type: "domain", value: "example.test" } ])
      answer = { "status" => "resolved", "addresses" => [ "192.0.2.1" ], "resolved_at" => timestamp, "expires_at" => timestamp }
      resolver = Object.new
      resolver.define_singleton_method(:resolve) { |_name| answer }
      address.resolve_domains!(resolver)
      document = json(C::Document.dump(result_for(address, rule)))
      restored = C::Document.load(document)
      assert_equal rule.conditions, restored.rules.first.conditions
      assert_equal answer, restored.find(E::AddressObject, name: "domain").dns_answers.fetch("example.test")
      assert_equal document, json(C::Document.dump(restored))
    end
  end

  def test_document_rejects_impossible_calendar_dates_in_all_timestamp_slots
    schedule = E::Schedule.new(**context, name: "window", kind: :once, start_at: AT - 60, end_at: AT + 60, reference_time: AT)
    document = json(C::Document.dump(result_for(schedule)))
    bad = "2026-02-31T10:11:12.000000000Z"
    paths = [ [ "context", "reference_time" ], [ "source", "created_at" ],
      [ "nodes", 0, "attributes", "reference_time" ], [ "nodes", 0, "attributes", "start_at" ], [ "nodes", 0, "attributes", "end_at" ] ]
    paths.each do |path|
      corrupted = json(document)
      path[0...-1].reduce(corrupted) { |value, key| value.fetch(key) }[path.last] = bad
      assert_raises(C::Document::InvalidDocument, path.join("/")) { C::Document.load(corrupted) }
    end
  end
  def test_default_document_keeps_unknown_command_semantics_without_native_text
    rule_text = "private-rule-setting private-marker-728"
    schedule_text = "private-schedule-setting private-marker-729"
    original = parse("rule id 1\n action permit\n #{rule_text}\nexit\n")
    document = json(C::Document.dump(original))
    refute_includes JSON.generate(document), rule_text
    restored = C::Document.load(document)
    assert restored.rules.first.unparsed_commands?
    assert_raises(C::SourceUnavailable) { restored.rules.first.unparsed_commands }
    assert_raises(C::SourceUnavailable) { restored.rules.first.conditions }
    assert_equal original.rules.first.unparsed_commands_metadata, restored.rules.first.unparsed_commands_metadata
    assert_equal document, json(C::Document.dump(restored))
    raw = C::Document.load(json(C::Document.dump(original, raw: true)))
    assert_equal original.rules.first.conditions, raw.rules.first.conditions

    schedule = E::Schedule.new(**context, name: "unsupported", kind: :weekly, days: "daily", periods: [ [ "00:00", "23:59" ] ],
      unparsed_commands: [ schedule_text ])
    rule = E::SecurityRule.new(**context, native_rule_id: "2", schedule: schedule, schedule_name: schedule.name)
    source = result_for(schedule, rule)
    schedule_document = json(C::Document.dump(source))
    refute_includes JSON.generate(schedule_document), schedule_text
    loaded = C::Document.load(schedule_document)
    refute loaded.rules.first.schedule.resolved?
    assert loaded.rules.first.schedule.unparsed_commands?
    assert_raises(C::SourceUnavailable) { loaded.rules.first.schedule.unparsed_commands }
    assert_raises(ArgumentError) { loaded.rules.first.schedule.active?(at: AT) }
    assert_equal schedule_document, json(C::Document.dump(loaded))
    loaded_raw = C::Document.load(json(C::Document.dump(source, raw: true)))
    assert_equal [ schedule_text ], loaded_raw.rules.first.schedule.unparsed_commands
  end
  def test_detached_unknown_commands_block_ordered_evaluation_before_disabled_filtering
    require "algosec/policy/evaluation"
    rule = E::SecurityRule.new(**context, native_rule_id: "1", rule_number: 1, disabled: true,
      from_zones: [ "inside" ], to_zones: [ "outside" ], conditions: { "unparsed_commands" => [ "private state override" ] })
    source = result_for(rule)
    loaded = C::Document.load(json(C::Document.dump(source)))
    packet = Algosec::Policy::Packet.new(source: "192.0.2.1", destination: "198.51.100.1", protocol: 6, source_port: 1234, destination_port: 443)
    [ source, loaded ].each do |result|
      snapshot = Algosec::Policy::Snapshot.from_config(result)
      assert_equal result.rules, snapshot.rulebase(from_zone: "inside", to_zone: "outside").ordered_rules(at: AT)
      evaluation = Algosec::Policy::Evaluation.new(snapshot, at: AT).perform(packet, from_zone: "inside", to_zone: "outside")
      refute evaluation.complete?
      assert_equal [ :unknown ], evaluation.partitions.map(&:status)
      assert_same result.rules.first, evaluation.partitions.first.rule
      assert_raises(Algosec::Policy::Analysis::Unknown) { Algosec::Policy::Analysis::RuleView.new(snapshot, result.rules.first, at: AT).disabled? }
    end
    assert_empty C::Comparison.new(before: source, after: loaded).perform.fetch(:changes)
  end

  def test_command_provenance_distinguishes_absent_empty_and_order_and_rejects_corrupt_details
    absent = E::SecurityRule.new(**context, native_rule_id: "1")
    empty = E::SecurityRule.new(**context, native_rule_id: "2", conditions: { "unparsed_commands" => [] })
    ordered = E::SecurityRule.new(**context, native_rule_id: "3", conditions: { "unparsed_commands" => [ "second", "first" ] })
    result = result_for(absent, empty, ordered)
    document = json(C::Document.dump(result))
    restored = C::Document.load(document)
    refute restored.rules[0].unparsed_commands_metadata.fetch("declared")
    assert restored.rules[1].unparsed_commands_metadata.fetch("declared")
    refute restored.rules[1].unparsed_commands?
    assert_equal [], restored.rules[1].conditions.fetch("unparsed_commands")
    assert_equal 2, restored.rules[2].unparsed_commands_metadata.fetch("count")
    raw = json(C::Document.dump(result, raw: true))
    assert_equal [ "second", "first" ], C::Document.load(raw).rules[2].unparsed_commands
    altered = json(raw)
    altered.fetch("raw_details").fetch("unparsed_commands").last.fetch("value").reverse!
    assert_raises(C::Document::InvalidDocument) { C::Document.load(altered) }
    altered = json(document)
    metadata = altered.fetch("nodes").find { |node| node["kind"] == "security_rule" && node.fetch("attributes")["native_rule_id"] == "3" }.fetch("attributes").fetch("unparsed_commands_metadata")
    metadata["declared"] = false
    assert_raises(C::Document::InvalidDocument) { C::Document.load(altered) }
    altered = json(raw)
    altered.fetch("raw_details").fetch("unparsed_commands").pop
    assert_raises(C::Document::InvalidDocument) { C::Document.load(altered) }
  end
end
