# frozen_string_literal: true

require "minitest/autorun"
require "open3"

class StandaloneParserTest < Minitest::Test
  def test_hillstone_mixed_schedule_parses_without_rails_preloading_extensions
    source = <<~'RUBY'
      require "algosec"
      result = Algosec::Config::Parser.perform(<<~CONFIG, vendor: :hillstone)
        schedule work
          absolute start 01/01/2026 00:00 end 12/31/2026 23:59
          periodic monday 09:00 to 10:00
        exit
      CONFIG
      abort "incomplete" unless result.complete?
      abort "unresolved schedule" unless result.find(Algosec::Elements::Schedule, name: "work").resolved?
    RUBY
    _output, error, status = Open3.capture3(RbConfig.ruby, "-Ilib", "-e", source,
      chdir: File.expand_path("../../..", __dir__))
    assert status.success?, error
  end
end
