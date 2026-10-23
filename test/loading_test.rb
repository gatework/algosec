# frozen_string_literal: true

require "test_helper"
require "open3"
require "rbconfig"
require "tmpdir"

class LoadingTest < Minitest::Test
  def test_nested_implementations_load_before_and_after_the_public_entrypoint
    entrypoints = %w[
      algosec/device_session/capture algosec/device_session/read_error algosec/device_session/factory
      algosec/offline_check/firewall algosec/offline_check/error algosec/offline_check/output algosec/offline_check/readback
      algosec/elements/address/expansion/projection algosec/elements/address_group/negated
      algosec/policy/finding algosec/policy/assessment algosec/policy/report algosec/policy/analysis/unknown
      algosec/policy/change_set/intent algosec/policy/change_set/target algosec/policy/change_set/verification
      algosec/policy/traffic_set/budget algosec/policy/traffic_set/region
      algosec/policy/evaluation/predicate algosec/policy/evaluation/result algosec/policy/nat/verification/expectation
      algosec/vendors/asa/nat/acl algosec/vendors/huawei/nat/action
      algosec/vendors/huawei/nat/plan algosec/vendors/huawei/nat/server
      algosec/vendors/asa/nat/translator algosec/vendors/palo_alto/nat/translator algosec/vendors/fortinet/generator/vip_binding
      algosec/policy/nat algosec/policy/nat/translator algosec/policy/nat/resolver
      algosec/policy/nat/verification algosec/policy/nat/service_query algosec/policy/nat/embedded_selection
      algosec/policy/nat/generation algosec/vendors/huawei/nat/generation algosec/vendors/palo_alto/nat/generation
      algosec/policy/generator/syntax algosec/policy/generator/state algosec/policy/generator/rule
      algosec/policy/request/traffic algosec/policy/rule_matcher/comparison algosec/policy/analysis/rule_view
      algosec/policy/change_set/declaration_comparison algosec/policy/change_set/proof_contexts
      algosec/config/cache/entry algosec/config/parser/syntax algosec/config/result/rule_projection
      algosec/config/diagnostic algosec/config/parse_error algosec/config/incomplete_configuration
    ]
    Dir.mktmpdir("algosec-nested-loading-") do |directory|
      entrypoints.each do |entrypoint|
        [ [ entrypoint, "algosec" ], [ "algosec", entrypoint ] ].each do |order|
          script = <<~RUBY
            #{order.map { |path| "require #{path.inspect}" }.join("\n")}
            Algosec::Vendors.validate!
            result = Algosec::Config::Parser.perform("", vendor: :srx)
            abort "Parser unavailable" unless result.complete?
            abort "Unexpected Rails dependency" if defined?(Rails) || defined?(ActiveRecord)
            abort "Unexpected file creation" unless Dir.children(".").empty?
          RUBY
          output, error, status = Open3.capture3(RbConfig.ruby, "-I", TestPaths.root.join("lib").to_s,
            "-e", script, chdir: directory)
          assert status.success?, "#{order.join(' -> ')}: #{error}"
          assert_empty output
          assert_empty error
        end
      end
    end
  end

  def test_public_entrypoints_load_outside_the_checkout_without_rails_or_files
    entrypoints = %w[algosec algosec/config algosec/policy algosec/policy/nat algosec/elements algosec/elements/nat algosec/connector
                     algosec/builtin_services algosec/dns_resolver algosec/ipv6 algosec/domain_name
                     algosec/elements/address/expressions algosec/elements/service/expressions algosec/device_session
                     algosec/collector algosec/offline_check]
    Dir.mktmpdir("algosec-loading-") do |directory|
      entrypoints.each do |entrypoint|
        script = <<~RUBY
          require #{entrypoint.inspect}
          require "algosec"
          Algosec::Vendors.validate!
          abort "Unexpected Rails dependency" if defined?(Rails) || defined?(ActiveRecord)
          result = Algosec::Config::Parser.perform("", vendor: :srx)
          abort "Parser unavailable" unless result.complete?
          abort "Unexpected file creation" unless Dir.children(".").empty?
        RUBY
        output, error, status = Open3.capture3(RbConfig.ruby, "-I", TestPaths.root.join("lib").to_s,
          "-e", script, chdir: directory)
        assert status.success?, "#{entrypoint}: #{error}"
        assert_empty output
        assert_empty error
      end
    end
  end
end
