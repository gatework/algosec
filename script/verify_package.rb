# frozen_string_literal: true

require "rubygems/package"
require "tmpdir"
require "rbconfig"
require "fileutils"

abort "Usage: ruby script/verify_package.rb GEM [--source-only]" unless (1..2).cover?(ARGV.size) && (ARGV.size == 1 || ARGV.last == "--source-only")
artifact = File.expand_path(ARGV.first)
root = File.expand_path("..", __dir__)
source = Gem::Specification.load(File.join(root, "algosec.gemspec"))
abort "Cannot load gemspec" unless source
package = Gem::Package.new(artifact)
package.verify
spec = package.spec
abort "Unexpected package identity" unless spec.name == "algosec" && spec.version == source.version
source.date = spec.date
source.rubygems_version = spec.rubygems_version
abort "Package metadata differs from source" unless source.to_ruby == spec.to_ruby
abort "Package file list differs from source" unless package.contents.sort == source.files.sort
abort "Unexpected package contents" if package.contents.any? { |path| path.start_with?("test/", "spec/", "tmp/", "storage/", "vendor/") || path.end_with?(".log", ".gem", ".key", ".pem") }

# 从包中解压并逐字节核对，避免遗漏未跟踪文件或误装旧版本。
Dir.mktmpdir("algosec-source-") do |directory|
  package.extract_files(directory)
  source.files.each do |path|
    original, extracted = File.join(root, path), File.join(directory, path)
    abort "Package source differs: #{path}" unless File.binread(original) == File.binread(extracted)
    abort "Package permissions differ: #{path}" unless File.stat(original).mode & 0o777 == File.stat(extracted).mode & 0o777
  end
end
puts "Verified #{spec.full_name}: #{package.contents.size} packaged files match source"
exit if ARGV.last == "--source-only"

# 子进程仅使用临时 GEM_HOME；清除 Bundler 和 Ruby 预加载环境，不回退系统 gem。
Dir.mktmpdir("algosec-install-") do |home|
  env = ENV.to_h.keys.grep(/\A(?:BUNDLE_|BUNDLER_|RUBY)/).to_h { |key| [ key, nil ] }
  env.merge!("GEM_HOME" => home, "GEM_PATH" => home, "RUBYOPT" => nil, "RUBYLIB" => nil, "ALGOSEC_CACHE_DIR" => nil)
  options = []
  if (cache = ENV["ALGOSEC_GEM_CACHE"])
    files = Dir[File.join(File.expand_path(cache), "*.gem")]
    abort "Dependency cache is empty" if files.empty?
    files.each { |path| FileUtils.cp(path, home) }
    options << "--local"
  end
  ruby = RbConfig.ruby
  system(env, ruby, "-S", "gem", "install", artifact, "--no-document", *options, chdir: home, exception: true)
  check = <<~RUBY
    require "algosec"
    abort "Unexpected Rails dependency" if defined?(Rails) || defined?(ActiveRecord)
    loaded = Gem.loaded_specs.fetch("algosec")
    prefix = File.realpath(ENV.fetch("GEM_HOME")) + "/"
    abort "Loaded checkout instead of installed package" unless File.realpath(loaded.full_gem_path).start_with?(prefix)
    abort "Version mismatch" unless loaded.version.to_s == #{spec.version.to_s.inspect}
    Algosec::Vendors.validate!
    %w[algosec/device_session algosec/deployment algosec/dns_resolver algosec/offline_check].each { |entry| require entry }
    abort "Missing extracted Huawei implementation" unless File.file?(File.join(loaded.full_gem_path, "lib/algosec/vendors/huawei/nat/plan.rb"))
    Dir[File.join(loaded.full_gem_path, "examples/**/*.rb")].sort.each { |path| load path }
    puts "Verified isolated install: " + loaded.full_name
  RUBY
  system(env, ruby, "-e", check, chdir: home, exception: true)

  # 每个公开入口独立启动，避免根入口提前加载依赖而掩盖缺失的 require。
  entrypoint_check = <<~RUBY
    require ARGV.fetch(0)
    require "algosec"
    abort "Unexpected Rails dependency" if defined?(Rails) || defined?(ActiveRecord)
    loaded = Gem.loaded_specs.fetch("algosec")
    prefix = File.realpath(ENV.fetch("GEM_HOME")) + "/"
    abort "Entrypoint loaded outside isolated package" unless File.realpath(loaded.full_gem_path).start_with?(prefix)
    abort "Version mismatch" unless loaded.version.to_s == #{spec.version.to_s.inspect}
    puts "Verified independent entrypoint: " + ARGV.fetch(0)
  RUBY
  %w[algosec algosec/config algosec/config/document algosec/policy algosec/policy/nat algosec/policy/plan_document algosec/elements algosec/elements/nat
     algosec/connector algosec/device_session algosec/deployment algosec/builtin_services
     algosec/dns_resolver algosec/offline_check algosec/vendors/palo_alto/nat/translator
     algosec/vendors/asa/nat/translator algosec/policy/change_set/intent
     algosec/policy/evaluation/predicate algosec/policy/traffic_set/region
     algosec/policy/nat/verification/expectation algosec/policy/analysis/unknown
     algosec/vendors/fortinet/generator/vip_binding algosec/elements/address_group/negated
     algosec/elements/address/expansion/projection].each do |entry|
    system(env, ruby, "-e", entrypoint_check, entry, chdir: home, exception: true)
  end
end
