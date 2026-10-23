# frozen_string_literal: true

require_relative "lib/algosec/version"

Gem::Specification.new do |spec|
  spec.name = "algosec"
  spec.version = Algosec::VERSION
  spec.authors = [ "Gatework contributors" ]
  spec.summary = "Parse firewall configurations and plan multi-vendor policy changes."
  spec.description = "Reusable firewall objects, configuration evidence, policy analysis, command generation and device sessions for Ruby applications."
  spec.homepage = "https://github.com/gatework/algosec"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 4.0.7"
  spec.metadata = {
    "source_code_uri" => spec.homepage,
    "bug_tracker_uri" => "#{spec.homepage}/issues",
    "changelog_uri" => "#{spec.homepage}/blob/main/CHANGELOG.md",
    "documentation_uri" => "#{spec.homepage}/blob/main/README.md",
    "allowed_push_host" => "https://rubygems.org",
    "rubygems_mfa_required" => "true"
  }
  # 仅发布运行时代码与使用文档，现场配置、测试和本地快照不进入安装包。
  spec.files = Dir.chdir(__dir__) do
    Dir["lib/**/*.rb", "examples/**/*.rb", "README*.md", "CHANGELOG.md", "LICENSE",
        "docs/architecture.md", "docs/capabilities.md", "docs/release.md"].sort
  end
  spec.require_paths = [ "lib" ]

  spec.add_dependency "activesupport", ">= 8.1.4", "< 9"
  spec.add_dependency "ctx_parser", ">= 0.2.5", "< 1"
  spec.add_dependency "ctx_driver", ">= 0.2.4", "< 1"
  spec.add_dependency "net-connector", ">= 0.16.0", "< 1"
  spec.add_dependency "nokogiri", ">= 1.19.4", "< 2"
  spec.add_dependency "ipaddr", ">= 1.2.3"
  %w[date digest fileutils json resolv shellwords strscan time tmpdir].each { |name| spec.add_dependency name }
end
