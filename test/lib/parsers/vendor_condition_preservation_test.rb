# frozen_string_literal: true

require_relative "../../test_helper"
require "algosec/config"
require "algosec/policy"
require "algosec/vendors/palo_alto/set_configuration"

class VendorConditionPreservationTest < Minitest::Test
  E = Algosec::Elements
  P = Algosec::Policy

  def test_neteye_inline_tcp_and_udp_keep_source_port_limits
    %w[tcp udp].each do |protocol|
      result = parse("policy access restricted inside any outside any #{protocol} 1024-2048 443 permit enable 1\n", :neteye)
      assert result.complete?, result.diagnostics.inspect
      snapshot = P::Snapshot.from_config(result)
      assert_equal :permit, match(snapshot, protocol: protocol, source_port: 1500).decision
      refute_equal :permit, match(snapshot, protocol: protocol, source_port: 50000).decision
    end
  end

  def test_neteye_continuation_preserves_source_and_destination_port_pairs
    result = parse(<<~CONFIG, :neteye)
      policy access restricted inside any outside any tcp 1024-2048 443 permit enable 1
      policy access restricted protocol tcp 5000-6000 8443
    CONFIG
    assert result.complete?, result.diagnostics.inspect
    snapshot = P::Snapshot.from_config(result)
    assert_equal :permit, match(snapshot, source_port: 1500).decision
    assert_equal :permit, match(snapshot, source_port: 5500, destination_port: 8443).decision
    refute_equal :permit, match(snapshot, source_port: 5500).decision
    refute_equal :permit, match(snapshot, source_port: 1500, destination_port: 8443).decision
  end

  def test_pan_repeated_non_recurring_members_remain_unknown_in_both_windows
    xml = <<~XML
      <config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">
      <schedule><entry name="maintenance"><schedule-type><non-recurring>
      <member>2027/01/01@10:00-2027/01/01@11:00</member>
      <member>2027/02/01@10:00-2027/02/01@11:00</member>
      </non-recurring></schedule-type></entry></schedule>
      </entry></vsys></entry></devices></config>
    XML
    normalized = Algosec::Vendors::PaloAlto::SetConfiguration.from_xml(xml)
    result = parse(normalized + pan_rules, :palo_alto)
    refute result.complete?
    assert_includes result.diagnostics.map(&:code), :unsupported_schedule
    schedule = result.find(E::Schedule, name: "maintenance")
    refute schedule.resolved?
    normalized.lines.each { |line| assert_includes schedule.unparsed_commands, line.strip }
    assert_equal :incomplete_configuration, assert_raises(P::Error) { P::Snapshot.from_config(result) }.code

    # Even an explicitly assembled catalog must not turn the lost deny window into allow.
    snapshot = P::Snapshot.new(vendor: :palo_alto, device_id: 1, catalog: result.catalog)
    [ Time.utc(2027, 1, 1, 10, 30), Time.utc(2027, 2, 1, 10, 30) ].each do |at|
      assert_equal :unknown, match(snapshot, at: at).status
    end
  end

  def test_pan_duplicate_of_the_same_non_recurring_window_is_still_supported
    line = "set schedule maintenance schedule-type non-recurring 2027/01/01@10:00-2027/01/01@11:00\n"
    result = parse(line * 2 + pan_rules, :palo_alto)
    assert result.complete?, result.diagnostics.inspect
    assert_equal :deny, match(P::Snapshot.from_config(result), at: Time.utc(2027, 1, 1, 10, 30)).decision
  end

  def test_srx_nat_interface_context_is_not_replaced_with_its_zone
    [ [ :source, "from interface ge-0/0/1.0", "to zone outside" ],
      [ :source, "from zone inside", "to interface ge-0/0/3.0" ],
      [ :destination, "from interface ge-0/0/1.0", nil ],
      [ :static, "from interface ge-0/0/1.0", nil ] ].each do |kind, from, to|
      result = parse(srx_network + srx_nat(kind, from: from, to: to), :srx)
      refute result.complete?, "#{kind}: #{from}, #{to}"
      assert_includes result.diagnostics.map(&:code), :unsupported_nat_context
      assert_empty result.elements(E::NatRule)
      assert_equal :incomplete_configuration, assert_raises(P::Error) { P::Snapshot.from_config(result) }.code
    end
  end

  def test_srx_zone_nat_context_keeps_its_supported_mapping
    result = parse(srx_network + srx_nat(:source, from: "from zone inside", to: "to zone outside"), :srx)
    assert result.complete?, result.diagnostics.inspect
    resolver = P::Nat::Resolver.new(P::Snapshot.from_config(result))
    found = resolver.find("10.0.2.10", zone: "outside", direction: :source, peers: { "192.0.2.10" => {} },
      flow: { from_zone: "inside", to_zone: "outside", vrf: "default" })
    assert_equal "203.0.113.10/32", found.fetch(:address)
  end

  def test_h3c_repeated_periodic_statements_keep_each_day_and_clock_pair
    result = parse(<<~CONFIG + h3c_rules, :h3c)
      time-range maintenance 10:00 to 11:00 Mon
      time-range maintenance 13:00 to 14:00 Tue
      time-range maintenance 16:00 to 17:00 Mon
      time-range maintenance 10:00 to 11:00 Mon
    CONFIG
    assert result.complete?, result.diagnostics.inspect
    snapshot = P::Snapshot.from_config(result)
    { [ 4, 10 ] => :deny, [ 4, 13 ] => :permit, [ 4, 16 ] => :deny,
      [ 5, 10 ] => :permit, [ 5, 13 ] => :deny }.each do |(day, hour), decision|
      assert_equal decision, match(snapshot, at: Time.utc(2027, 1, day, hour, 30)).decision
    end
    restored = Algosec::Config::Document.load(JSON.parse(JSON.generate(Algosec::Config::Document.dump(result))))
    assert_equal result.find(E::Schedule, name: "maintenance").weekly_windows,
      restored.find(E::Schedule, name: "maintenance").weekly_windows
  end

  def test_h3c_multiple_absolute_or_mixed_statements_remain_unknown
    periodic = "time-range maintenance 10:00 to 11:00 Mon\n"
    first = "time-range maintenance from 10:00 01/04/2027 to 11:00 01/04/2027\n"
    last = "time-range maintenance from 10:00 02/01/2027 to 11:00 02/01/2027\n"
    compound = "time-range maintenance 10:00 to 11:00 Mon from 00:00 01/01/2027 to 23:59 02/01/2027\n"
    [ first + last, first + periodic, periodic + first, compound ].each do |declarations|
      result = parse(declarations + h3c_rules, :h3c)
      refute result.complete?, declarations
      assert_includes result.diagnostics.map(&:code), :unsupported_schedule
      schedule = result.find(E::Schedule, name: "maintenance")
      refute schedule.resolved?
      declarations.lines.each { |line| assert_includes schedule.unparsed_commands, line.strip }
      assert_equal :incomplete_configuration, assert_raises(P::Error) { P::Snapshot.from_config(result) }.code
      snapshot = P::Snapshot.new(vendor: :h3c, device_id: 1, catalog: result.catalog)
      assert_equal :unknown, match(snapshot, at: Time.utc(2027, 1, 4, 10, 30)).status

      [ false, true ].each do |raw|
        restored = Algosec::Config::Document.load(JSON.parse(JSON.generate(Algosec::Config::Document.dump(result, raw: raw))))
        refute restored.complete?
        refute restored.find(E::Schedule, name: "maintenance").resolved?
        assert_equal :incomplete_configuration, assert_raises(P::Error) { P::Snapshot.from_config(restored) }.code
      end
    end
  end

  def test_h3c_duplicate_absolute_window_remains_supported
    line = "time-range maintenance from 10:00 01/04/2027 to 11:00 01/04/2027\n"
    result = parse(line * 2 + h3c_rules, :h3c)
    assert result.complete?, result.diagnostics.inspect
    assert_equal :deny, match(P::Snapshot.from_config(result), at: Time.utc(2027, 1, 4, 10, 30)).decision
  end

  def test_asa_multiple_periodic_entries_keep_each_day_and_clock_pair
    result = parse(<<~CONFIG + asa_rules, :asa)
      time-range maintenance
       periodic Monday 10:00 to 11:00
       periodic Tuesday 13:00 to 14:00
       periodic Monday 16:00 to 17:00
      !
    CONFIG
    assert result.complete?, result.diagnostics.inspect
    snapshot = P::Snapshot.from_config(result)
    { [ 4, 10 ] => :deny, [ 4, 13 ] => :permit, [ 4, 16 ] => :deny,
      [ 5, 10 ] => :permit, [ 5, 13 ] => :deny }.each do |(day, hour), decision|
      assert_equal decision, match(snapshot, at: Time.utc(2027, 1, day, hour, 30)).decision
    end
    restored = Algosec::Config::Document.load(JSON.parse(JSON.generate(Algosec::Config::Document.dump(result))))
    assert_equal result.find(E::Schedule, name: "maintenance").weekly_windows,
      restored.find(E::Schedule, name: "maintenance").weekly_windows
  end

  def test_asa_absolute_gating_is_not_lost_when_combined_with_periodic_entries
    absolute = "absolute start 10:00 4 January 2027 end 11:00 4 January 2027"
    periodic = "periodic Tuesday 13:00 to 14:00"
    [ [ absolute, periodic ], [ periodic, absolute ] ].each do |statements|
      result = parse("time-range maintenance\n #{statements.join("\n ")}\n!\n" + asa_rules, :asa)
      refute result.complete?
      assert_includes result.diagnostics.map(&:code), :unsupported_schedule
      schedule = result.find(E::Schedule, name: "maintenance")
      refute schedule.resolved?
      statements.each { |line| assert_includes schedule.unparsed_commands, line }
      assert_equal :incomplete_configuration, assert_raises(P::Error) { P::Snapshot.from_config(result) }.code
      snapshot = P::Snapshot.new(vendor: :asa, device_id: 1, catalog: result.catalog)
      assert_equal :unknown, match(snapshot, at: Time.utc(2027, 1, 5, 13, 30)).status
      [ false, true ].each do |raw|
        restored = Algosec::Config::Document.load(JSON.parse(JSON.generate(Algosec::Config::Document.dump(result, raw: raw))))
        refute restored.complete?
        refute restored.find(E::Schedule, name: "maintenance").resolved?
      end
    end
  end

  def test_fortinet_overnight_and_full_day_ranges_cannot_become_empty_windows
    [ [ "23:00", "01:00" ], [ "00:00", "00:00" ] ].each do |first, last|
      result = parse(<<~CONFIG, :fortinet)
        config firewall schedule recurring
         edit maintenance
          set day monday
          set start #{first}
          set end #{last}
         next
        end
      CONFIG
      refute result.complete?
      assert_includes result.diagnostics.map(&:code), :unsupported_schedule
      schedule = result.find(E::Schedule, name: "maintenance")
      refute schedule.resolved?
      assert_raises(ArgumentError) { schedule.active?(at: Time.utc(2027, 1, 4, 23, 30)) }
      assert_equal :incomplete_configuration, assert_raises(P::Error) { P::Snapshot.from_config(result) }.code
      [ false, true ].each do |raw|
        restored = Algosec::Config::Document.load(JSON.parse(JSON.generate(Algosec::Config::Document.dump(result, raw: raw))))
        refute restored.complete?
        refute restored.find(E::Schedule, name: "maintenance").resolved?
      end
    end
  end

  def test_vendor_conditions_survive_detached_and_raw_document_round_trips
    inputs = {
      neteye: "policy access restricted inside any outside any tcp 1024-2048 443 permit enable 1\n",
      palo_alto: "set schedule maintenance schedule-type non-recurring 2027/01/01@10:00-2027/01/01@11:00\n" \
        "set schedule maintenance schedule-type non-recurring 2027/02/01@10:00-2027/02/01@11:00\n" + pan_rules,
      srx: srx_network + srx_nat(:source, from: "from interface ge-0/0/1.0", to: "to zone outside")
    }
    inputs.each do |vendor, content|
      original = parse(content, vendor)
      [ false, true ].each do |raw|
        document = JSON.parse(JSON.generate(Algosec::Config::Document.dump(original, raw: raw)))
        begin
          restored = Algosec::Config::Document.load(document)
        rescue Algosec::Config::Document::InvalidDocument => error
          flunk "#{vendor} condition document failed to restore (raw=#{raw}): #{error.message}"
        end
        assert_equal original.complete?, restored.complete?, vendor.to_s
        assert_equal original.diagnostics.map { |item| [ item.code, item.line_number ] },
          restored.diagnostics.map { |item| [ item.code, item.line_number ] }, vendor.to_s
        if vendor == :neteye
          snapshot = P::Snapshot.from_config(restored)
          assert_equal :permit, match(snapshot, source_port: 1500).decision
          refute_equal :permit, match(snapshot, source_port: 50000).decision
        else
          assert_equal :incomplete_configuration, assert_raises(P::Error) { P::Snapshot.from_config(restored) }.code
          if vendor == :palo_alto
            refute restored.find(E::Schedule, name: "maintenance").resolved?
            snapshot = P::Snapshot.new(vendor: vendor, device_id: 1, catalog: restored.catalog)
            assert_equal :unknown, match(snapshot, at: Time.utc(2027, 1, 1, 10, 30)).status
          else
            assert_empty restored.elements(E::NatRule)
          end
        end
      end
    end
  end

  private

  def parse(content, vendor)
    Algosec::Config::Parser.perform(content, vendor: vendor, device_id: 1)
  end

  def match(snapshot, protocol: "tcp", source_port: 1500, destination_port: 443, at: Time.current)
    P::TrafficMatcher.new(snapshot, at: at).perform(source: "10.0.0.1", destination: "192.0.2.1",
      protocol: protocol, source_port: source_port, destination_port: destination_port, from_zone: "inside", to_zone: "outside")
  end

  def pan_rules
    <<~CONFIG
      set rulebase security rules blocked from inside
      set rulebase security rules blocked to outside
      set rulebase security rules blocked source any
      set rulebase security rules blocked destination any
      set rulebase security rules blocked service any
      set rulebase security rules blocked application any
      set rulebase security rules blocked schedule maintenance
      set rulebase security rules blocked action deny
      set rulebase security rules fallback from inside
      set rulebase security rules fallback to outside
      set rulebase security rules fallback source any
      set rulebase security rules fallback destination any
      set rulebase security rules fallback service any
      set rulebase security rules fallback application any
      set rulebase security rules fallback action allow
    CONFIG
  end

  def h3c_rules
    <<~CONFIG
      #
      object-policy ip outbound
       rule 10 drop time-range maintenance
       rule 20 pass
      #
      zone-pair security source inside destination outside
       object-policy apply ip outbound
      #
    CONFIG
  end

  def asa_rules
    <<~CONFIG
      access-list outbound extended deny ip any any time-range maintenance
      access-list outbound extended permit ip any any
      access-group outbound in interface inside
    CONFIG
  end

  def srx_network
    <<~CONFIG
      set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24
      set interfaces ge-0/0/2 unit 0 family inet address 10.0.2.1/24
      set interfaces ge-0/0/3 unit 0 family inet address 192.0.2.1/24
      set security zones security-zone inside interfaces ge-0/0/1.0
      set security zones security-zone inside interfaces ge-0/0/2.0
      set security zones security-zone outside interfaces ge-0/0/3.0
    CONFIG
  end

  def srx_nat(kind, from:, to:)
    prefix = "set security nat #{kind} rule-set restricted"
    rows = [ "#{prefix} #{from}", ("#{prefix} #{to}" if to) ]
    if kind == :static
      rows.concat([ "#{prefix} rule r match destination-address 203.0.113.10/32", "#{prefix} rule r then static-nat prefix 10.0.2.10/32" ])
    else
      target = kind == :source ? "203.0.113.10/32" : "10.0.2.10/32"
      rows.unshift("set security nat #{kind} pool translated address #{target}")
      field = kind == :source ? "source-address 0.0.0.0/0" : "destination-address 203.0.113.10/32"
      rows.concat([ "#{prefix} rule r match #{field}", "#{prefix} rule r then #{kind}-nat pool translated" ])
    end
    rows.compact.join("\n") + "\n"
  end
end
