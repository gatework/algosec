# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "support/policy_factory"

class PolicyVendorGeneratorTest < Minitest::Test
  include PolicyFactory

  H3C_SETTINGS = { policy_bindings: [ { name: "objects", from_zone: "inside", to_zone: "outside" } ] }.freeze

  def generate(vendor, objects: [], settings: {}, version: nil, schedule: nil, **options)
    config = snapshot(vendor, objects, settings: settings, version: version)
    result = P::RuleMatcher.new(config).match(group(vendor, **options), schedule: schedule)
    P::Planner.new(P::Report.new(results: [ result ])).perform.first[:policy_contents].first[:new][:content]
  end

  def nat_commands(vendor, records, direction: :nat_sources, objects: [], version: nil, **options)
    data = group(vendor, **options)
    result = P::Result.new(**data, type: :ignore, snapshot: snapshot(vendor, objects, version: version), actions: { new: { direction => records } })
    P::Planner.new(P::Report.new(results: [ result ])).perform.first[:policy_contents].first[:new][:content]
  end

  def nat_record(real, mapped = nil, type: :dynamic, **nat)
    { origin: real, real_ip: real, nat: { type: type, address: mapped, **nat } }
  end

  def request_schedule
    P::Request.new(sources: [ "any" ], destinations: [ "any" ], services: [ "any" ],
                   schedule: { start_at: "2026-09-15T09:00:00+08:00", end_at: "2026-09-16T18:00:00+08:00", time_zone: "Asia/Hong_Kong" }).schedule
  end

  def test_h3c_binding_and_allocated_rule_id_are_explicit
    assert_raises(P::Error) { generate(:h3c) }
    commands = generate(:h3c, settings: H3C_SETTINGS, sources: [ "10.0.0.1", "10.0.0.2" ])
    assert_includes commands, "object-policy ip objects\nrule 0 pass source-ip Host_10.0.0.1 destination-ip Host_192.0.2.1 service TCP_443"
    assert_includes commands, "rule 0 append source-ip Host_10.0.0.2"
    assert_equal 1, commands.scan(/rule \d+ pass/).size
    commands = generate(:h3c, objects: [ rule(:h3c, native_rule_id: "1") ], sources: [ "10.0.0.0/24" ], services: [ "tcp/443", "tcp/8443" ])
    assert_includes commands, "rule 1 append service TCP_8443"
    refute_match(/rule \d+ pass/, commands)
  end

  def test_h3c_nat_allocations_have_separate_exact_acls
    records = { "10.0.0.1-10.0.0.3" => nat_record("10.0.0.1-10.0.0.3", "203.0.113.1", interface: "outside"),
                "10.0.1.1" => nat_record("10.0.1.1", "203.0.113.2", interface: "outside") }
    commands = nat_commands(:h3c, records)
    assert_includes commands, "acl advanced 3000\nrule permit ip source 10.0.0.1 0 destination 192.0.2.1 0\nrule permit ip source 10.0.0.2 0.0.0.1 destination 192.0.2.1 0"
    assert_includes commands, "acl advanced 3001\nrule permit ip source 10.0.1.1 0 destination 192.0.2.1 0"
    assert_includes commands, "nat outbound 3000 address-group name Pool-203.0.113.1/32"
    assert_includes commands, "nat outbound 3001 address-group name Pool-203.0.113.2/32"
  end

  def test_h3c_acl_reuse_checks_joint_coverage_and_rejects_deny
    left = rule(:h3c, source: "10.0.0.1/32", destination: "192.0.2.1/32", services: [ "any" ],
                rule_type: :acl, rule_set: "3000", native_rule_id: 1, from_zones: nil, to_zones: nil)
    right = rule(:h3c, source: "10.0.0.2/32", destination: "192.0.2.2/32", services: [ "any" ],
                 rule_type: :acl, rule_set: "3000", native_rule_id: 2, from_zones: nil, to_zones: nil)
    records = { "10.0.0.1-10.0.0.2" => nat_record("10.0.0.1-10.0.0.2", interface: "outside") }
    options = { objects: [ left, right ], destinations: [ "192.0.2.1", "192.0.2.2" ] }
    assert_includes nat_commands(:h3c, records, **options), "acl advanced 3001"
    commands = nat_commands(:h3c, { "10.0.0.1" => nat_record("10.0.0.1", interface: "outside") }, objects: [ left ])
    refute_includes commands, "acl advanced"
    assert_includes commands, "nat outbound 3000"
    denied = left.with(action: "deny")
    assert_includes nat_commands(:h3c, records, **options.merge(objects: [ denied, right ])), "acl advanced 3001"
  end

  def test_neteye_objects_rules_and_nat_directions
    commands = generate(:neteye, sources: [ "10.0.0.1", "10.0.0.2" ], services: [ "tcp/443", "udp/53" ])
    assert_includes commands, "object service TCP_443 tcp 0-65535 443"
    assert_match(/policy access p_[a-f0-9]+ inside object Host_10.0.0.1 outside object Host_192.0.2.1 protocol-object TCP_443 permit enable/, commands)
    assert_match(/sourceip object Host_10.0.0.2/, commands)
    assert_equal commands, generate(:neteye, sources: [ "10.0.0.1", "10.0.0.2" ], services: [ "tcp/443", "udp/53" ])
    commands = nat_commands(:neteye, { "10.0.0.1" => nat_record("10.0.0.1", interface: "outside") })
    assert_match(/policy snat \S+ iplist 10.0.0.1 interface outside/, commands)
    commands = nat_commands(:neteye, { "10.0.0.1" => nat_record("10.0.0.1", "203.0.113.1") }, direction: :nat_destinations)
    assert_match(/policy dnat \S+ 203.0.113.1 10.0.0.1 enable/, commands)
    error = assert_raises(P::Error) { generate(:neteye, schedule: request_schedule) }
    assert_equal :unsupported_schedule, error.code
  end

  def test_h3c_nat_does_not_reuse_acls_with_unproven_conditions
    restrictions = [
      { conditions: { unparsed_commands: [ "fragment" ] } },
      { conditions: { starts_at: "2030-01-01T00:00:00Z" } },
      { from_interface: "eth0" }
    ]
    restrictions.each do |attributes|
      existing = rule(:h3c, source: "10.0.0.1", destination: "192.0.2.1", services: [ "any" ],
        rule_type: :acl, rule_set: "3000", native_rule_id: 1, from_zones: nil, to_zones: nil, **attributes)
      records = { "10.0.0.1" => nat_record("10.0.0.1", interface: "outside") }

      commands = nat_commands(:h3c, records, objects: [ existing ])

      assert_includes commands, "acl advanced 3001", attributes.inspect
      assert_includes commands, "nat outbound 3001", attributes.inspect
    end
  end

  def test_h3c_nat_reuses_acls_with_explicitly_empty_condition_containers
    existing = rule(:h3c, source: "10.0.0.1", destination: "192.0.2.1", services: [ "any" ],
      rule_type: :acl, rule_set: "3000", native_rule_id: 1, from_zones: nil, to_zones: nil,
      conditions: { unparsed_commands: [], security_profiles: {}, from_vlans: {}, to_vlans: {} })
    records = { "10.0.0.1" => nat_record("10.0.0.1", interface: "outside") }

    commands = nat_commands(:h3c, records, objects: [ existing ])

    refute_includes commands, "acl advanced"
    assert_includes commands, "nat outbound 3000"
  end

  def test_topsec_preserves_members_nat_direction_and_schedule_binding
    existing = rule(:topsec, config: "policy add src 'old-source ' dst 'old-target ' service 'old-service '")
    commands = generate(:topsec, objects: [ existing ], sources: [ "10.0.0.0/24" ], services: [ "tcp/443", "tcp/8443" ])
    assert_includes commands, "policy modify id r1 service 'old-service TCP_8443 '"
    refute_includes commands, "src 'old-source"
    commands = nat_commands(:topsec, { "10.0.0.1" => nat_record("10.0.0.1", "203.0.113.1", type: :static) })
    assert_includes commands, "orig-src 'Host_10.0.0.1 ' trans-src 'Host_203.0.113.1 '"
    commands = nat_commands(:topsec, { "10.0.0.1" => nat_record("10.0.0.1", "203.0.113.1") }, direction: :nat_destinations)
    assert_includes commands, "orig-dst 'Host_203.0.113.1 ' trans-dst 'Host_10.0.0.1 '"
    commands = generate(:topsec, schedule: request_schedule)
    assert_includes commands, "sdate 2026-09-15 stime 09:00:00 edate 2026-09-16 etime 18:00:00"
    assert_includes commands, "schedule sch_202609150900_202609161800"
  end

  def test_all_nine_vendors_run_search_and_design_without_external_state
    request = P::Request.new(sources: [ "10.0.0.1" ], destinations: [ "192.0.2.1" ], services: [ "tcp/443" ])
    VENDORS.each do |vendor|
      settings = (vendor == :h3c) ? H3C_SETTINGS : {}
      config = snapshot(vendor, settings: settings)
      report = P::Searcher.new(networks: networks(vendor), snapshots: { 1 => config }).perform(request)
      assert report.success?, "#{vendor}: #{report.comment}"
      commands = P::Planner.new(report).perform.first[:policy_contents].first[:new][:content]
      assert_includes commands, (vendor == :h3c) ? "object-policy ip objects" : "inside", vendor.to_s
      assert_match(/permit|accept|allow|rule \d+ pass/, commands, vendor.to_s)
      assert_match(/10\.0\.0\.1/, commands, vendor.to_s)
      assert_match(/192\.0\.2\.1/, commands, vendor.to_s)
      assert_match(/443/, commands, vendor.to_s)
    end
  end

  def test_srx_nat_uses_real_pool_endpoints_and_protocol_specific_ports
    records = { "203.0.113.1" => nat_record("10.0.0.1", "203.0.113.1", option: "sp") }
    commands = nat_commands(:srx, records, direction: :nat_destinations,
                            services: [ { services: [ "tcp/443" ], translated_port: 8443 }, { services: [ "udp/443" ], translated_port: 8443 } ])
    assert_match(/destination pool \S+ address 10\.0\.0\.1\/32 to 10\.0\.0\.1\/32/, commands)
    assert_match(/destination pool \S+ address port 8443/, commands)
    assert_match(/rule \S+ match protocol tcp/, commands)
    assert_match(/rule \S+ match protocol udp/, commands)
    assert_equal 2, commands.scan("match destination-port 443").size
    refute_match(/nat destination rule-set \S+ to zone/, commands)
    records = { "10.0.0.1" => nat_record("10.0.0.1", "203.0.113.4/30", option: "d") }
    commands = nat_commands(:srx, records)
    assert_match(/source pool \S+ address 203\.0\.113\.4\/32 to 203\.0\.113\.7\/32/, commands)
    assert_match(/match destination-address 192\.0\.2\.1\/32/, commands)
  end

  def test_huawei_version_and_complete_multi_address_objects
    commands = generate(:huawei, sources: [ "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4" ])
    assert_match(/ip address-set addrgroup_\S+ type object\naddress 0 range 10.0.0.1 10.0.0.4/, commands)
    assert_includes commands, "service 0 protocol tcp source-port 0 to 65535 destination-port 443"
    records = { "10.0.0.1" => nat_record("10.0.0.1", "203.0.113.4/30") }
    error = assert_raises(P::Error) { nat_commands(:huawei, records) }
    assert_equal :unsupported_version, error.code
    commands = nat_commands(:huawei, records, version: "V500R005")
    assert_includes commands, "section 0 203.0.113.4 203.0.113.7"
    assert_includes commands, "source-address 10.0.0.1 32"
    assert_match(/action source-nat address-group \S+\nquit\nquit/, commands)
    commands = generate(:huawei, objects: [ rule(:huawei) ], sources: [ "10.0.0.0/24" ], services: [ "tcp/443", "tcp/8443" ])
    assert_includes commands, "rule name r1"
    refute_includes commands, "source-zone"
  end

  def test_asa_preserves_real_and_mapped_networks_across_version_boundary
    records = { "203.0.113.0/24" => nat_record("10.0.0.0/24", "203.0.113.0/24", type: :static) }
    modern = nat_commands(:asa, records, direction: :nat_destinations, version: "9.12")
    assert_includes modern, "subnet 203.0.113.0 255.255.255.0"
    assert_includes modern, "subnet 10.0.0.0 255.255.255.0"
    assert_match(/nat \(outside,inside\) static obj-203.0.113.0\/24/, modern)
    legacy = nat_commands(:asa, records, direction: :nat_destinations, version: "8.2")
    assert_includes legacy, "static (outside,inside) 203.0.113.0 access-list 100 netmask 255.255.255.0"
    refute_includes legacy, "object network"
    commands = nat_commands(:asa, { "10.0.0.1" => nat_record("10.0.0.1") }, version: "8.3")
    assert_includes commands, "host 10.0.0.1\nnat (inside,outside) dynamic interface\nexit"
    commands = nat_commands(:asa, { "10.0.0.1" => nat_record("10.0.0.1", "203.0.113.1") },
                            direction: :nat_destinations, version: "9.12", services: [ { services: [ "tcp/443" ], translated_port: 8443 } ])
    assert_includes commands, "nat (outside,inside) static 203.0.113.1 service tcp 8443 443"
  end

  def test_fortinet_splits_nat_groups_and_references_each_port_vip
    config = snapshot(:fortinet)
    source_map = { "10.0.0.1/32" => nat_record("10.0.0.1/32", "203.0.113.1").merge(action: :new_nat),
                   "10.0.0.2/32" => nat_record("10.0.0.2/32", "203.0.113.2").merge(action: :new_nat),
                   "10.0.0.3/32" => { origin: "10.0.0.3/32" } }
    result = P::RuleMatcher.new(config).match(group(:fortinet).merge(sources: source_map))
    commands = Algosec::Vendors::Fortinet::Generator.new(result).perform
    assert_equal 3, commands.scan("edit 0").size
    assert_equal 2, commands.scan("set nat enable").size
    plain = commands.split("config firewall policy").last
    assert_includes plain, 'set srcaddr "10.0.0.3/32"'
    refute_includes plain, "set nat enable"
    destination_map = { "203.0.113.1/32" => nat_record("10.0.0.1", "203.0.113.1", interface: "inside").merge(action: :new_nat) }
    result = P::RuleMatcher.new(config).match(group(:fortinet,
                                                    services: [ { services: [ "tcp/443" ], translated_port: 8443 }, { services: [ "udp/53" ], translated_port: 5353 } ]).merge(destinations: destination_map))
    commands = Algosec::Vendors::Fortinet::Generator.new(result).perform
    assert_equal 2, commands.scan("set portforward enable").size
    assert_includes commands, 'set service "ALL"'
    assert_includes commands, "set extport 443\nset mappedport 8443"
    assert_includes commands, 'set dstaddr "vip203.0.113.1_inside_tcp_443" "vip203.0.113.1_inside_udp_53"'
  end

  def test_fortinet_vip_conflict_does_not_replace_a_committed_target
    config = snapshot(:fortinet)
    state = {}
    results = %w[10.0.0.1 10.0.0.2].map do |real|
      record = nat_record(real, "203.0.113.1", type: :static, interface: "inside").merge(action: :new_nat)
      destinations = { "203.0.113.1/32" => record }
      P::RuleMatcher.new(config).match(group(:fortinet).merge(destinations: destinations))
    end
    implementation = Algosec::Vendors::Fortinet::Generator
    implementation.new(results.first, state: state).perform
    committed = P::Value.copy(state)
    failed = implementation.new(results.last, state: state)
    error = assert_raises(P::Error) { failed.perform }
    assert_equal :nat_scope_conflict, error.code
    assert_empty failed.commands
    assert_equal committed, state
    repeated = implementation.new(results.first, state: state).perform
    refute_includes repeated, "config firewall vip"
    assert_includes repeated, 'set dstaddr "vip203.0.113.1_inside"'
  end

  def test_netscreen_range_is_exact_and_dip_ids_do_not_collide_in_one_batch
    commands = generate(:netscreen, sources: [ "10.0.0.1-10.0.0.3" ], destinations: [ "192.0.2.1", "192.0.2.2" ])
    assert_includes commands, 'set address "inside" "10.0.0.1/32" 10.0.0.1 255.255.255.255'
    assert_includes commands, 'set address "inside" "10.0.0.2/31" 10.0.0.2 255.255.255.254'
    assert_match(/set policy id \d+\nset (src-address|dst-address|service)/, commands)
    refute_includes commands, "XXXXXX"
    interface = E::Interface.new(**context(:netscreen), name: "eth0", ipaddr: "203.0.113.254/24", zone: "outside")
    config = snapshot(:netscreen, [ interface ])
    results = %w[203.0.113.1 203.0.113.2].map do |public_ip|
      sources = { "10.0.0.1/32" => nat_record("10.0.0.1", public_ip, interface: "eth0").merge(action: :new_nat) }
      P::RuleMatcher.new(config).match(group(:netscreen).merge(sources: sources))
    end
    contents = P::Planner.new(P::Report.new(results: results)).perform.first[:policy_contents].map { |entry| entry[:new][:content] }.join
    assert_includes contents, "set interface eth0 dip 4 203.0.113.1 203.0.113.1"
    assert_includes contents, "set interface eth0 dip 5 203.0.113.2 203.0.113.2"
    assert_match(/nat src dip-id 4 permit/, contents)
    assert_match(/nat src dip-id 5 permit/, contents)
  end

  def test_new_nat_cannot_expand_an_existing_policy_outside_the_request
    %i[fortinet netscreen].each do |vendor|
      existing = rule(vendor)
      record = nat_record("10.0.0.1").merge(action: :new_nat)
      result = P::Result.new(**group(vendor), type: :ignore, rule: existing, snapshot: snapshot(vendor, [ existing ]),
                             actions: { new: { nat_sources: { "10.0.0.1/32" => record } } })
      generator = Algosec::Vendors.fetch(vendor, :generator).new(result)
      error = assert_raises(P::Error) { generator.perform }
      assert_equal :nat_scope_conflict, error.code
      assert_empty generator.commands
    end
  end

  def test_supported_schedule_generators_bind_the_declared_schedule
    (VENDORS - [ :neteye ]).each do |vendor|
      commands = generate(vendor, settings: (vendor == :h3c) ? H3C_SETTINGS : {}, schedule: request_schedule)
      assert_operator commands.scan("sch_202609150900_202609161800").size, :>=, 2, vendor.to_s
      assert_includes commands, "09:00", vendor.to_s
      assert_includes commands, "18:00", vendor.to_s
    end
  end

  def test_fortinet_keeps_nat_policy_identity_and_reuses_existing_vip
    wrong, correct = [ rule(:fortinet, name: "r0", rule_number: 1), rule(:fortinet, name: "r1", rule_number: 2) ]
    pool = E::NatPool.new(**context(:fortinet), name: "egress_pool", ip: "203.0.113.1", mode: "overload", arp_reply: true)
    nat = E::DynamicNat.new(**context(:fortinet), name: "r1", policy_id: "r1", direction: :source,
                            from_zone: "inside", to_zone: "outside", source_pool: pool)
    source = { "10.0.0.1/32" => { origin: "10.0.0.1/32", nat: { type: :dynamic, address: "203.0.113.1/32", rule: nat } } }
    config = snapshot(:fortinet, [ wrong, correct, nat, pool ])
    result = P::RuleMatcher.new(config).match(group(:fortinet).merge(sources: source))
    assert_equal :new, result.type
    assert_nil result.rule
    assert_equal [ wrong ], result.conflicting_rules
    empty = snapshot(:fortinet, [ nat, pool ])
    result = P::RuleMatcher.new(empty).match(group(:fortinet).merge(sources: source))
    commands = Algosec::Vendors::Fortinet::Generator.new(result).perform
    assert_includes commands, 'set poolname "egress_pool"'
    refute_includes commands, "config firewall ippool"
    vip = E::StaticNat.new(**context(:fortinet), name: "ExistingVIP", real_ip: "10.0.0.9", mapped_ip: "203.0.113.9", interface: "outside")
    ordinary = E::AddressObject.new(**context(:fortinet), name: "A_ordinary_address", member: [ { type: "subnet", value: "203.0.113.9/32" } ])
    destination = { "203.0.113.9/32" => { origin: "10.0.0.9/32", nat: { type: :static, address: "203.0.113.9/32", rule: vip } } }
    result = P::RuleMatcher.new(snapshot(:fortinet, [ vip, ordinary ])).match(group(:fortinet).merge(destinations: destination))
    commands = Algosec::Vendors::Fortinet::Generator.new(result).perform
    assert_includes commands, 'set dstaddr "ExistingVIP"'
    refute_includes commands, "config firewall vip"
    refute_includes commands, 'set dstaddr "A_ordinary_address"'
  end
end
