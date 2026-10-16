# frozen_string_literal: true

require "minitest/autorun"
require "algosec"

class AlgosecTest < Minitest::Test
  def test_version_matches_gemspec
    spec = Gem::Specification.load(File.expand_path("../algosec.gemspec", __dir__))
    assert_equal Algosec::VERSION, spec.version.to_s
    assert_equal "algosec", spec.name
  end

  def test_errors_can_be_rescued_as_standard_errors
    assert_operator Algosec::Error, :<, StandardError
  end

  def test_package_contains_only_library_and_documentation
    spec = Gem::Specification.load(File.expand_path("../algosec.gemspec", __dir__))
    assert_equal %w[CHANGELOG.md LICENSE README.md lib/algosec.rb lib/algosec/version.rb], spec.files.sort
  end
end
