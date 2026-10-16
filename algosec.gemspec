# frozen_string_literal: true

require_relative "lib/algosec/version"

Gem::Specification.new do |spec|
  spec.name = "algosec"
  spec.version = Algosec::VERSION
  spec.authors = ["gatework"]
  spec.summary = "Ruby library foundation for AlgoSec automation"
  spec.description = "Initial AlgoSec gem scaffold with a versioned namespace and error class. " \
                     "Device connections and operations are not implemented yet."
  spec.homepage = "https://github.com/gatework/algosec"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.3"
  spec.files = Dir["lib/**/*.rb", "README.md", "CHANGELOG.md", "LICENSE"].sort
  spec.require_paths = ["lib"]
  spec.metadata = {
    "source_code_uri" => spec.homepage,
    "bug_tracker_uri" => "#{spec.homepage}/issues",
    "changelog_uri" => "#{spec.homepage}/blob/main/CHANGELOG.md",
    "documentation_uri" => "#{spec.homepage}/blob/main/README.md",
    "allowed_push_host" => "https://rubygems.org",
    "rubygems_mfa_required" => "true"
  }
end
