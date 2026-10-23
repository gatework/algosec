# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "support/policy_factory"

class CanonicalDomainReviewTest < Minitest::Test
  include PolicyFactory

  # 使用公开解析流程装配带规范条件的 ACL，验证后续 NAT 投影边界。
  class ConditionedH3cParser < Algosec::Vendors::H3c::Parser
    def initialize(rule_attributes:, **options)
      super(**options)
      @rule_attributes = rule_attributes
    end

    private

    def emit(type, attributes, lines = [])
      attributes = attributes.merge(@rule_attributes) if type == :rule
      super(type, attributes, lines)
    end
  end

  def test_h3c_nat_generation_does_not_reuse_acl_with_unknown_state_or_canonical_conditions
    [ { status: "surprise" }, { applications: [ "ssl" ] }, { source_users: [ "alice" ] } ].each do |attributes|
      commands = h3c_nat_commands(attributes)
      assert_includes commands, "acl advanced 3001", attributes.inspect
      assert_includes commands, "nat outbound 3001", attributes.inspect
      refute_includes commands, "nat outbound 3000", attributes.inspect
    end
  end

  def test_h3c_nat_generation_still_reuses_explicitly_unrestricted_active_acl
    commands = h3c_nat_commands(status: "enable", applications: [ "any" ], source_users: [ "any" ])
    refute_includes commands, "acl advanced"
    assert_includes commands, "nat outbound 3000"
  end

  def test_h3c_parser_nat_projection_retains_unknown_canonical_conditions
    [ { status: "surprise" }, { applications: [ "ssl" ] }, { source_users: [ "alice" ] } ].each do |attributes|
      parsed = ConditionedH3cParser.new(rule_attributes: attributes, device_id: 1).perform(h3c_nat_config)
      assert_includes parsed.diagnostics.map(&:code), :conditional_nat_acl, attributes.inspect
      refute parsed.complete?
      assert_equal 1, parsed.elements(E::DynamicNat).size
    end
    parsed = ConditionedH3cParser.new(rule_attributes: { applications: [ "any" ], source_users: [ "any" ] }, device_id: 1).perform(h3c_nat_config)
    assert parsed.complete?, parsed.diagnostics.inspect
  end

  def test_asa_nat_acl_unknown_state_is_not_an_enabled_match
    entry = rule(:asa, status: "surprise", rule_number: 1)
    error = assert_raises(P::Error) { asa_nat_match(entry) }
    assert_equal :conditional_nat, error.code
    assert asa_nat_match(rule(:asa, status: "enable", rule_number: 1))
    refute asa_nat_match(rule(:asa, status: "disable", rule_number: 1))
  end

  def test_srx_same_text_book_and_zone_addresses_remain_distinct
    result = parse_srx(<<~CONFIG)
      set security address-book inside address server 192.0.2.1/32
      set security zones security-zone inside address-book address server 192.0.2.2/32
    CONFIG
    assert result.complete?, result.diagnostics.inspect
    assert_equal 2, result.elements(E::AddressObject).size
    book = E::Scope.new(device_id: 1, address_book: "inside")
    zone = E::Scope.new(device_id: 1, zone: "inside")
    assert_equal Algosec::IPAddr.parse("192.0.2.1"), result.find(E::AddressObject, name: "server", scope: book).set
    assert_equal Algosec::IPAddr.parse("192.0.2.2"), result.find(E::AddressObject, name: "server", scope: zone).set
  end

  def test_srx_same_text_book_and_zone_groups_do_not_merge_members
    result = parse_srx(<<~CONFIG)
      set security address-book inside address first 192.0.2.1/32
      set security address-book inside address-set servers address first
      set security zones security-zone inside address-book address second 192.0.2.2/32
      set security zones security-zone inside address-book address-set servers address second
    CONFIG
    assert result.complete?, result.diagnostics.inspect
    assert_equal 2, result.elements(E::AddressGroup).size
    book = E::Scope.new(device_id: 1, address_book: "inside")
    zone = E::Scope.new(device_id: 1, zone: "inside")
    book_group = result.find(E::AddressGroup, name: "servers", scope: book)
    zone_group = result.find(E::AddressGroup, name: "servers", scope: zone)
    assert_equal [ "first" ], book_group.members.keys
    assert_equal [ "second" ], zone_group.members.keys
    assert_equal Algosec::IPAddr.parse("192.0.2.1"), book_group.set
    assert_equal Algosec::IPAddr.parse("192.0.2.2"), zone_group.set
  end

  def test_srx_ambiguous_cross_namespace_reference_is_diagnosed_without_losing_objects
    result = parse_srx(<<~CONFIG)
      set security address-book inside address server 192.0.2.1/32
      set security address-book inside address-set servers address server
      set security zones security-zone inside address-book address server 192.0.2.2/32
      set security zones security-zone inside address-book address-set servers address server
    CONFIG
    refute result.complete?
    assert_includes result.diagnostics.map(&:code), :ambiguous_reference
    assert_equal 2, result.elements(E::AddressObject).size
    assert_equal 2, result.elements(E::AddressGroup).size
    result.elements(E::AddressGroup).each do |group|
      assert_nil group.members.fetch("server")
      assert_raises(E::Group::UnresolvedReference) { group.resolved_set }
    end
    assert_raises(Algosec::Config::IncompleteConfiguration) do
      Algosec::Config::Parser.perform(result.reader.content, vendor: :srx, device_id: 1, strict: true)
    end
  end

  private

  def h3c_nat_commands(attributes)
    existing = rule(:h3c, source: "10.0.0.1", destination: "192.0.2.1", services: [ "any" ],
      rule_type: :acl, rule_set: "3000", native_rule_id: 1, from_zones: nil, to_zones: nil, **attributes)
    records = { "10.0.0.1" => { origin: "10.0.0.1", real_ip: "10.0.0.1", nat: { type: :dynamic, interface: "outside" } } }
    result = P::Result.new(**group(:h3c), type: :ignore, snapshot: snapshot(:h3c, [ existing ]), actions: { new: { nat_sources: records } })
    Algosec::Vendors::H3c::Generator.new(result).perform
  end

  def h3c_nat_config
    <<~CONFIG
      security-zone name outside
       import interface GigabitEthernet1/0/1
      #
      interface GigabitEthernet1/0/1
       ip address 203.0.113.254 255.255.255.0
       nat outbound 3000
      #
      acl advanced 3000
       rule 1 permit ip source 10.0.0.1 0 destination 192.0.2.1 0
      #
    CONFIG
  end

  def asa_nat_match(entry)
    Algosec::Vendors::Asa::Nat::Acl.new(snapshot(:asa, [ entry ]), "inside_acl").matches?(
      sources: Algosec::IPAddr.parse("10.0.0.1"), destinations: Algosec::IPAddr.parse("192.0.2.1"),
      services: { "tcp/443" => {} }, relation: :cover?)
  end

  def parse_srx(content) = Algosec::Config::Parser.perform(content, vendor: :srx, device_id: 1)
end
