# frozen_string_literal: true

require "bundler"
require "digest"
require "fileutils"
require "open3"
require "rbconfig"
require "rubygems/package"
require "tmpdir"

Dir.chdir(File.expand_path("..", __dir__))
spec = Gem::Specification.load("algosec.gemspec")
abort "Cannot load gemspec" unless spec
FileUtils.mkdir_p("pkg")
epoch, status = Open3.capture2("git", "log", "-1", "--format=%ct")
ENV["SOURCE_DATE_EPOCH"] = epoch.strip if status.success? && !epoch.strip.empty?
artifact = "pkg/#{spec.full_name}.gem"
Gem::Package.build(spec, false, true, artifact)

Bundler.with_unbundled_env do
  Dir.mktmpdir("algosec-install-") do |dir|
    env = { "GEM_HOME" => dir, "GEM_PATH" => dir, "RUBYOPT" => nil, "RUBYLIB" => nil }
    system(env, RbConfig.ruby, "-S", "gem", "install", File.expand_path(artifact),
           "--local", "--no-document", "--ignore-dependencies", exception: true)
    code = 'require "algosec"; abort "Wrong version" unless Algosec::VERSION == ARGV.fetch(0); '
    code += 'abort "Loaded workspace" unless $LOADED_FEATURES.grep(%r{/algosec\.rb$}).all? { |p| File.realpath(p).start_with?(File.realpath(ENV.fetch("GEM_HOME")) + "/") }'
    system(env, RbConfig.ruby, "-e", code, spec.version.to_s, chdir: dir, exception: true)
  end
end

File.write("pkg/SHA256SUMS", "#{Digest::SHA256.file(artifact).hexdigest}  #{File.basename(artifact)}\n")
system(RbConfig.ruby, "script/release.rb", "--check", exception: true)
