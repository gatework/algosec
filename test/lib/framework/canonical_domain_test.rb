# frozen_string_literal: true

require_relative "../../test_helper"
require "open3"
require_relative "support/policy_factory"

class CanonicalDomainTest < Minitest::Test
  include PolicyFactory
  E = Algosec::Elements

  def setup
    assert E.const_defined?(:SecurityRule), "canonical SecurityRule is missing"
  end

  def test_domain_components_load_before_the_elements_entrypoint
    %w[address/expansion address/expansion/projection address_group/negated service/expansion catalog/reference_resolver nat/translation
       nat/source_translation nat/destination_translation nat/original_packet
       address_object service_object security_rule static_nat dynamic_nat].each do |file|
      source = <<~RUBY_SOURCE
        require "algosec/elements/#{file}"
        require "algosec/elements"
        elements = Algosec::Elements
        abort if elements.const_defined?(:Rule, false)
        abort if elements::Address.is_a?(Class) || elements::Service.is_a?(Class)
        abort unless elements::AddressObject.ancestors.include?(elements::Address::Expansion)
        abort unless elements::ServiceObject.ancestors.include?(elements::Service::Expansion)
        abort unless elements::SecurityRule.name == "Algosec::Elements::SecurityRule"
      RUBY_SOURCE
      output, error, status = Open3.capture3(RbConfig.ruby, "-Ilib", "-e", source)
      assert status.success?, "#{file}: #{output} #{error}"
    end
  end

  def test_canonical_names_and_groups_preserve_domain_identity
    source = E::AddressGroup.new(name: "src")
    rule = E::SecurityRule.new(name: "web", source_zones: [ "inside" ], destination_zones: [ "outside" ],
      source_addresses: source, applications: [ "web", "web" ], source_users: [ "alice" ])
    assert_equal "Algosec::Elements::AddressObject", E::AddressObject.name
    assert_equal "Algosec::Elements::ServiceObject", E::ServiceObject.name
    assert_same source, rule.sources
    assert_same source, rule.source_addresses
    assert_same rule.to_zones, rule.destination_zones
    assert_equal [ "inside" ], rule.from_zones
    assert_equal [ "web" ], rule.applications
    assert rule.applications.frozen?
    assert rule.source_users.first.frozen?
    assert_equal :security_rule, rule.element_type
    assert_equal :security_rule, rule.type
    assert_equal :address_object, E::AddressObject.new(name: "a").type
    assert_equal :service_object, E::ServiceObject.new(name: "s").type
  end

  def test_alias_parameter_conflicts_are_rejected
    assert_raises(ArgumentError) { E::SecurityRule.new(name: "x", source_zones: [ "a" ], from_zones: [ "b" ]) }
    assert_raises(ArgumentError) { E::SecurityRule.new(name: "x", source_addresses: E::AddressGroup.new(name: "a"), sources: E::AddressGroup.new(name: "b")) }
    assert_raises(ArgumentError) { E::SecurityRule.new(name: "x", disabled: false, status: "disable") }
    assert_raises(ArgumentError) { E::SecurityRule.new(name: "x", native_rule_type: :object, rule_type: :acl) }
    assert_raises(ArgumentError) { E::SecurityRule.new(name: "x", action: "allow", native_action: "deny") }
    assert_raises(ArgumentError) { E::SecurityRule.new(name: "x", disabled: "false") }
  end

  def test_action_normalization_preserves_native_and_reset_semantics
    { "permit" => "allow", "accept" => "allow", "allow" => "allow", "deny" => "deny", "drop" => "drop",
      "reject" => "reject", "reset-client" => "reset-client", "reset-server" => "reset-server", "reset-both" => "reset-both" }.each do |native, canonical|
      rule = E::SecurityRule.new(name: "x", action: native)
      assert_equal canonical, rule.action
      assert_equal native, rule.native_action
    end
    rule = E::SecurityRule.new(name: "x", action: "allow", native_action: "permit")
    assert_equal "allow", rule.action
    rule.action = "deny"
    assert_equal "deny", rule.native_action
    unknown = E::SecurityRule.new(name: "x", action: "tunnel")
    assert_nil unknown.action
    assert_equal "tunnel", unknown.native_action
    assert_nil Algosec::Policy::Behavior.new(nil).rule_decision(unknown)
    reset = E::SecurityRule.new(name: "x", action: "reset-both")
    assert_nil Algosec::Policy::Behavior.new(nil).rule_decision(reset)
  end

  def test_status_mapping_is_boolean_and_unknown_is_not_active
    %w[enable enabled active activate].each do |status|
      rule = E::SecurityRule.new(name: "x", status: status)
      assert_equal false, rule.disabled
      assert rule.active?
    end
    %w[disable disabled inactive deactivate].each do |status|
      rule = E::SecurityRule.new(name: "x", status: status)
      assert_equal true, rule.disabled
      refute rule.active?
    end
    unknown = E::SecurityRule.new(name: "x", status: "surprise")
    assert_equal false, unknown.status_known?
    refute unknown.active?
    assert_includes [ true, false ], unknown.disabled
    rule = E::SecurityRule.new(name: "x", disabled: true)
    assert_equal "disable", rule.status
    rule.disabled = false
    assert rule.active?
    rule.status = "disable"
    assert rule.disabled
  end

  def test_scope_device_ids_use_the_same_decimal_contract_as_elements
    assert_equal 8, E::Scope.new(device_id: "08").device_id
    assert_raises(ArgumentError) { E::Scope.new(device_id: true) }
    assert_raises(ArgumentError) { E::Scope.new(device_id: -1) }
  end

  def test_scope_is_immutable_and_identity_ignores_execution_order
    input = +"vsys-a"
    scope = E::Scope.new(device_id: 7, virtual_system: input, rulebase: "pre-rulebase", address_book: "global", zone: "inside")
    input.replace("changed")
    assert_equal "vsys-a", scope.virtual_system
    assert scope.frozen?
    assert scope.virtual_system.frozen?
    first = E::SecurityRule.new(name: "web", scope: scope, rule_number: 1)
    moved = E::SecurityRule.new(name: "web", scope: scope, rule_number: 90)
    other = E::SecurityRule.new(name: "web", scope: scope.with(virtual_system: "vsys-b"), rule_number: 1)
    assert_equal 7, first.device_id
    assert first.same_identity?(moved)
    refute first.same_identity?(other)
    assert_equal first.rule_id, moved.rule_id
    assert_raises(ArgumentError) { E::SecurityRule.new(name: "web", device_id: 8, scope: scope) }
    catalog = E::Catalog.new([ first, other ])
    assert_same first, catalog.find(E::SecurityRule, name: "web", scope: scope)
    assert_raises(E::Catalog::AmbiguousReference) { catalog.find(E::SecurityRule, name: "web") }
  end

  def test_native_acl_type_is_separate_from_pan_rule_type
    acl = E::SecurityRule.new(name: "x", rule_type: :acl)
    assert_equal :acl, acl.native_rule_type
    assert_nil acl.rule_type
    pan = E::SecurityRule.new(name: "x", rule_type: :interzone, native_rule_type: :object)
    assert_equal :interzone, pan.rule_type
    assert_equal :object, pan.native_rule_type
  end

  def test_ten_vendors_emit_canonical_rules_without_losing_native_actions
    snippets = {
      asa: [ "access-list inbound extended permit ip any any\n", "permit" ],
      h3c: [ "acl advanced 3000\n rule 5 permit ip\n#\n", "permit" ],
      huawei: [ "security-policy\n rule name web\n  action permit\n#\n", "permit" ],
      hillstone: [ "rule id 1\n action permit\nexit\n", "permit" ],
      fortinet: [ "config firewall policy\n edit 1\n set srcintf any\n set dstintf any\n set srcaddr all\n set dstaddr all\n set service ALL\n set action accept\n next\nend\n", "accept" ],
      neteye: [ "rule id 1 any any any any any permit enable 1\n", "permit" ],
      netscreen: [ "set policy id 1 from inside to outside Any Any ANY permit\n", "permit" ],
      srx: [ "set security policies from-zone inside to-zone outside policy web then permit\n", "permit" ],
      topsec: [ "pf policy id 1 action accept\n", "accept" ],
      palo_alto: [ "set rulebase security rules web from any\nset rulebase security rules web to any\nset rulebase security rules web source any\nset rulebase security rules web destination any\nset rulebase security rules web service any\nset rulebase security rules web action allow\n", "allow" ]
    }
    # 已保存的 Neteye/Topsec 样例提供完整厂商语法。
    %i[neteye topsec].each { |vendor| snippets[vendor][0] = File.read(TestPaths.root.join("test/fixtures/config/#{vendor}.cfg")) }
    snippets.each do |vendor, (content, native)|
      result = Algosec::Config::Parser.perform(content, vendor: vendor, device_id: 7)
      rule = result.rules.first
      refute_nil rule, "#{vendor}: #{result.diagnostics.inspect}"
      assert_instance_of E::SecurityRule, rule
      assert_equal "allow", rule.action, vendor.to_s
      assert_equal native, rule.native_action, vendor.to_s
      assert_equal false, rule.disabled, vendor.to_s
      assert_same rule.sources, rule.source_addresses
      assert_same rule.destinations, rule.destination_addresses
      assert_equal 7, rule.scope.device_id
    end
  end

  def test_pan_preserves_applications_users_rule_type_and_known_scope
    result = Algosec::Config::Parser.perform(<<~CONFIG, vendor: :palo_alto)
      set rulebase security rules web application [ ssl web-browsing ]
      set rulebase security rules web source-user alice
      set rulebase security rules web rule-type interzone
      set rulebase security rules web action reset-both
      set rulebase security rules web service application-default
    CONFIG
    rule = result.rules.sole
    assert_equal %w[ssl web-browsing], rule.applications
    assert_equal [ "alice" ], rule.source_users
    assert_equal :interzone, rule.rule_type
    assert_equal "reset-both", rule.action
    assert_equal "vsys1", rule.scope.virtual_system
    assert_equal "rulebase", rule.scope.rulebase
    assert result.complete?, result.diagnostics.inspect
    assert_equal :application_default, rule.service_selection
    assert_empty rule.unparsed_commands
  end

  def test_service_source_port_shortcut_preserves_full_term_semantics
    service = E::ServiceObject.new(name: "web", terms: [
      { protocol: "tcp", source_port: "1024", destination_port: "443" },
      { protocol: "tcp", source_port: "1024", destination_port: "8443" }
    ])
    assert_respond_to service, :source_port
    assert_equal "1024", service.source_port
    assert_nil service.destination_port
    service.add(protocol: "tcp", source_port: "2048", destination_port: "443")
    assert_nil service.source_port
    assert service.matches?(protocol: "tcp", source_port: 2048, destination_port: 443)
    refute service.matches?(protocol: "tcp", source_port: 2048, destination_port: 8443)
  end

  def test_srx_address_book_and_zone_scopes_are_distinct_native_evidence
    result = Algosec::Config::Parser.perform(<<~CONFIG, vendor: :srx, device_id: 7)
      set security address-book global address server 192.0.2.1/32
      set security zones security-zone inside address-book address client 192.0.2.2/32
    CONFIG
    assert result.complete?, result.diagnostics.inspect
    server = result.find(E::AddressObject, name: "server", zone: "global")
    client = result.find(E::AddressObject, name: "client", zone: "inside")
    assert_equal "global", server.scope.address_book
    assert_nil server.scope.zone
    assert_nil client.scope.address_book
    assert_equal "inside", client.scope.zone
  end

  def test_unknown_native_actions_cannot_silently_disagree
    assert_raises(ArgumentError) { E::SecurityRule.new(name: "x", action: "tunnel", native_action: "inspect") }
  end

  def test_unknown_state_is_unknown_to_packet_queries_and_analysis
    entry = rule(:hillstone, status: "surprise", rule_number: 1)
    current = snapshot(:hillstone, [ entry ])
    hit = Algosec::Policy::TrafficMatcher.new(current).perform(source: "10.0.0.1", destination: "192.0.2.1", protocol: "tcp",
      source_port: 1024, destination_port: 443, from_zone: "inside", to_zone: "outside")
    assert_equal :unknown, hit.status
    assert_raises(Algosec::Policy::Analysis::Unknown) { Algosec::Policy::Analysis::RuleView.new(current, entry, at: Time.current).disabled? }
    assert_empty Algosec::Policy::RuleMatcher.new(current).candidates(from_zone: "inside", to_zone: "outside")
  end

  def test_canonical_applications_and_users_do_not_prove_unrestricted_matching
    [ { applications: [ "ssl" ] }, { source_users: [ "alice" ] } ].each do |attributes|
      entry = rule(:hillstone, rule_number: 1, **attributes)
      current = snapshot(:hillstone, [ entry ])
      hit = Algosec::Policy::TrafficMatcher.new(current).perform(source: "10.0.0.1", destination: "192.0.2.1", protocol: "tcp",
        source_port: 1024, destination_port: 443, from_zone: "inside", to_zone: "outside")
      assert_equal :unknown, hit.status
      assert_raises(Algosec::Policy::Analysis::Unknown) { Algosec::Policy::Analysis::RuleView.new(current, entry, at: Time.current).ranges }
      assert_empty Algosec::Policy::RuleMatcher.new(current).candidates(from_zone: "inside", to_zone: "outside")
    end
  end

  def test_native_acl_locator_and_scope_survive_cache_restore
    result = Algosec::Config::Parser.perform("access-list inbound line 10 extended permit ip any any\n", vendor: :asa, device_id: 7)
    rule = result.rules.sole
    assert_equal :acl, rule.native_rule_type
    assert_nil rule.rule_type
    assert_equal "inbound/10", rule.rule_id
    assert_equal "10", rule.native_rule_id
    cache = Algosec::Config::Cache.new(store: ActiveSupport::Cache::MemoryStore.new)
    cache.save(result)
    loaded = cache.load(7).rules.sole
    assert_equal rule.identity, loaded.identity
    assert loaded.scope.frozen?
    assert_equal 7, loaded.scope.device_id
  end

  def test_pan_and_topsec_unknown_disabled_tokens_are_not_enabled
    content = "set rulebase security rules web action allow\nset rulebase security rules web service any\nset rulebase security rules web disabled perhaps\n"
    pan = Algosec::Config::Parser.perform(content, vendor: :palo_alto)
    top = File.read(TestPaths.root.join("test/fixtures/config/topsec.cfg")).sub("enable yes", "enable perhaps")
    topsec = Algosec::Config::Parser.perform(top, vendor: :topsec)
    [ pan, topsec ].each do |result|
      refute result.complete?
      assert_includes result.diagnostics.map(&:code), :unknown_rule_status
      refute result.rules.first.active?
    end
  end

  def test_unknown_parser_action_and_status_are_diagnosed
    result = Algosec::Config::Parser.perform("rule id 1\n action mysterious\nexit\n", vendor: :hillstone)
    refute result.complete?
    assert_includes result.diagnostics.map(&:code), :unknown_rule_action
    assert_nil result.rules.sole.action
    assert_equal "mysterious", result.rules.sole.native_action
  end
end
