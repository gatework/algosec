# frozen_string_literal: true

require "minitest/autorun"
require "open3"
require "algosec/ipv6"

class AlgosecIpv6Test < Minitest::Test
  def test_range_normalization_does_not_require_rails_extensions
    source = <<~'RUBY'
      require "algosec/ipv6"
      puts Algosec::IPv6.normalize("2001:0db8::0001-2001:0db8::0002")
    RUBY
    output, error, status = Open3.capture3(RbConfig.ruby, "-Ilib", "-e", source,
      chdir: File.expand_path("../..", __dir__))

    assert status.success?, error
    assert_equal "2001:db8::1-2001:db8::2\n", output
  end

  def test_integer_conversion_rejects_values_that_would_be_truncated
    [ 1.5, -0.5, "1", nil, true, -1, 2**128 ].each do |value|
      assert_raises(ArgumentError, value.inspect) { Algosec::IPv6.from_i(value) }
    end
    assert_equal "::", Algosec::IPv6.from_i(0)
    assert_equal "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Algosec::IPv6.from_i(2**128 - 1)
  end

  def test_expression_entrypoints_report_invalid_types_as_argument_errors
    [ :address, :canonical, :parse, :normalize ].each do |method|
      [ nil, true, 1, [], {} ].each do |value|
        assert_raises(ArgumentError, "#{method}(#{value.inspect})") { Algosec::IPv6.public_send(method, value) }
      end
    end
  end
end
