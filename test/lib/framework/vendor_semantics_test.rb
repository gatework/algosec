# frozen_string_literal: true

require "test_helper"
require "algosec/config"
require "algosec/policy"

class VendorSemanticsTest < ActiveSupport::TestCase
  def parse(content, vendor)
    Algosec::Config::Parser.perform(content, vendor: vendor, device_id: 1)
  end

  def srx_policy
    <<~CONFIG
      set security policies from-zone inside to-zone outside policy web match source-address any
      set security policies from-zone inside to-zone outside policy web match destination-address any
      set security policies from-zone inside to-zone outside policy web match application any
      set security policies from-zone inside to-zone outside policy web then permit
    CONFIG
  end

  test "ASA retains logging options and explicit disable independently from rule status" do
    { "log" => true, "log disable" => false, "log informational interval 300" => true,
     "log-input warnings" => true }.each do |option, enabled|
      result = parse("access-list inbound extended permit tcp any any eq 443 #{option}\n", :asa)
      assert result.complete?, result.diagnostics.inspect
      rule = result.rules.sole
      assert_equal option, rule.log
      assert_equal enabled, rule.log_enabled
      refute rule.disabled?
    end
    result = parse("access-list inbound extended permit tcp any any eq 443 log interval nope\n", :asa)
    refute result.complete?
    assert result.rules.sole.unparsed_commands.any?
  end

  test "SRX log statements accumulate and deactivating a clause is not disabling the policy" do
    logging = %w[session-close session-init session-close].map do |value|
      "set security policies from-zone inside to-zone outside policy web then log #{value}\n"
    end.join
    result = parse(srx_policy + logging, :srx)
    assert result.complete?, result.diagnostics.inspect
    assert_equal "session-close session-init", result.rules.sole.log
    assert_equal true, result.rules.sole.log_enabled

    whole = parse(srx_policy + "deactivate security policies from-zone inside to-zone outside policy web\n", :srx)
    assert whole.complete?, whole.diagnostics.inspect
    assert whole.rules.sole.disabled?
    partial = parse(srx_policy + "deactivate security policies from-zone inside to-zone outside policy web then log\n", :srx)
    refute partial.complete?
    refute partial.rules.sole.disabled?
    assert_raises(Algosec::Policy::Error) { Algosec::Policy::Snapshot.from_config(partial) }
  end

  test "Huawei unsupported or missing NAT actions cannot produce a usable configuration" do
    [ "action no-nat", "action unsupported", "action source-nat unknown", "action destination-nat easy-ip", "" ].each do |action|
      result = parse("firewall zone trust\n#\nfirewall zone untrust\n#\nnat-policy\n rule name exempt\n  source-zone trust\n  destination-zone untrust\n  #{action}\n#\n", :huawei)
      refute result.complete?
      assert_includes result.diagnostics.map(&:code), :unsupported_nat_action
      assert_empty result.elements(Algosec::Elements::DynamicNat)
    end
  end
  test "Huawei native any service works without an external service catalog" do
    result = parse("security-policy\n rule name allow\n  action permit\n#\n", :huawei)
    assert result.complete?, result.diagnostics.inspect
    assert_equal Algosec::IPAddr.service("any"), result.rules.sole.services.set
  end

  test "SRX application ALG cannot silently become an ordinary port service" do
    content = <<~CONFIG
      set applications application ftp protocol tcp
      set applications application ftp destination-port 21
      set applications application ftp alg ftp
    CONFIG
    result = parse(content, :srx)
    refute result.complete?
    assert_includes result.diagnostics.map(&:code), :unsupported_application_condition
  end
end
