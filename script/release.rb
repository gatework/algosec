# frozen_string_literal: true

require "digest"
require "json"
require "net/http"
require "rbconfig"
require "rubygems/package"
require "tmpdir"

abort "Usage: ruby script/release.rb --check|--push" unless ARGV.length == 1 && %w[--check --push].include?(ARGV.first)
Dir.chdir(File.expand_path("..", __dir__))
spec = Gem::Specification.load("algosec.gemspec")
abort "Cannot load gemspec" unless spec
artifact = "pkg/#{spec.full_name}.gem"
package = Gem::Package.new(artifact)
package.verify
spec.date = package.spec.date
spec.rubygems_version = package.spec.rubygems_version
abort "Gem metadata differs from source" unless package.spec.to_ruby == spec.to_ruby
abort "Gem file list differs from source" unless package.contents.sort == spec.files.sort
Dir.mktmpdir("algosec-verify-") do |dir|
  package.extract_files(dir)
  spec.files.each do |file|
    abort "Gem content differs: #{file}" unless File.binread(File.join(dir, file)) == File.binread(file)
  end
end
sha = Digest::SHA256.file(artifact).hexdigest
abort "Checksum differs" unless File.read("pkg/SHA256SUMS") == "#{sha}  #{File.basename(artifact)}\n"
puts "Verified #{File.basename(artifact)} SHA256 #{sha}"
exit if ARGV.first == "--check"

abort "Release tag differs from version" unless ENV["GITHUB_REF_TYPE"] == "tag" && ENV["GITHUB_REF_NAME"] == "v#{spec.version}"

def get(path)
  uri = URI("https://rubygems.org#{path}")
  # Avoid a cached pre-publication 404 when verifying a new version or retrying.
  uri.query = URI.encode_www_form("release_check" => Time.now.to_i) if uri.path.start_with?("/api/")
  Net::HTTP.start(uri.host, uri.port, use_ssl: true, open_timeout: 15, read_timeout: 30) do |http|
    http.get(uri.request_uri)
  end
end

metadata_path = "/api/v2/rubygems/#{spec.name}/versions/#{spec.version}.json"
response = get(metadata_path)
case response
when Net::HTTPNotFound
  system(RbConfig.ruby, "-S", "gem", "push", artifact, "--host", "https://rubygems.org", exception: true)
when Net::HTTPSuccess
  metadata = JSON.parse(response.body)
  abort "Existing version differs or was yanked" unless metadata["sha"] == sha && metadata["yanked"] == false
  puts "Same artifact already published; verifying download"
else
  abort "RubyGems preflight failed: HTTP #{response.code}"
end

120.times do |attempt|
  response = get(metadata_path)
  if response.is_a?(Net::HTTPSuccess)
    metadata = JSON.parse(response.body)
    abort "Published metadata differs" unless metadata["sha"] == sha && metadata["yanked"] == false
    download = get("/gems/#{spec.full_name}.gem")
    if download.is_a?(Net::HTTPSuccess)
      abort "Published bytes differ" unless Digest::SHA256.hexdigest(download.body) == sha
      puts "Verified RubyGems version and downloaded bytes: #{spec.full_name}"
      exit
    end
    abort "Download failed: HTTP #{download.code}" unless download.is_a?(Net::HTTPNotFound)
  elsif !response.is_a?(Net::HTTPNotFound)
    abort "Read-back failed: HTTP #{response.code}"
  end
  sleep 5 unless attempt == 119
end
abort "RubyGems read-back timed out; rerun this workflow to verify the existing artifact"
