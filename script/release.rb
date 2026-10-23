# frozen_string_literal: true

require "digest"
require "json"
require "net/http"
require "open3"
require "rbconfig"

abort "Usage: ruby script/release.rb --check|--push" unless ARGV.one? && %w[--check --push].include?(ARGV.first)
Dir.chdir(File.expand_path("..", __dir__))
spec = Gem::Specification.load("algosec.gemspec")
abort "Cannot load gemspec" unless spec
artifact = "pkg/#{spec.full_name}.gem"
abort "Expected exactly one release gem" unless Dir["pkg/*.gem"] == [ artifact ]
system(RbConfig.ruby, "script/verify_package.rb", artifact, "--source-only", exception: true)
sha = Digest::SHA256.file(artifact).hexdigest
abort "Checksum differs" unless File.read("pkg/SHA256SUMS") == "#{sha}  #{File.basename(artifact)}\n"
abort "Missing changelog entry" unless File.read("CHANGELOG.md").include?("## #{spec.version} (")
puts "Verified #{File.basename(artifact)} SHA256 #{sha}"
exit if ARGV.first == "--check"

# 首次发布须补齐真实源码元数据，并从已提交的匹配版本标签运行。
abort "Configure the real source repository before publishing" unless spec.homepage && spec.metadata["source_code_uri"]
tag, status = Open3.capture2("git", "describe", "--tags", "--exact-match", "HEAD")
abort "Release requires tag v#{spec.version}" unless status.success? && tag.strip == "v#{spec.version}"
changes, status = Open3.capture2("git", "status", "--porcelain")
abort "Release requires a clean checkout" unless status.success? && changes.empty?

# 网络失败不等同于版本不存在；注册表请求均设置有限超时。
def registry_get(path)
  uri = URI("https://rubygems.org#{path}")
  Net::HTTP.start(uri.host, uri.port, use_ssl: true, open_timeout: 15, read_timeout: 30) { |http| http.get(uri.request_uri) }
end

def verify_metadata(response, sha)
  metadata = JSON.parse(response.body)
  abort "Published version differs or was yanked" unless metadata["sha"] == sha && metadata["yanked"] == false
end

metadata_path = "/api/v2/rubygems/#{spec.name}/versions/#{spec.version}.json"
response = registry_get(metadata_path)
case response
when Net::HTTPNotFound
  system(RbConfig.ruby, "-S", "gem", "push", artifact, "--host", "https://rubygems.org", exception: true)
when Net::HTTPSuccess
  verify_metadata(response, sha)
else
  abort "RubyGems preflight failed: HTTP #{response.code}"
end

# 上传后仅回读，不因可见性延迟重复上传。
24.times do |attempt|
  response = registry_get(metadata_path)
  if response.is_a?(Net::HTTPSuccess)
    verify_metadata(response, sha)
    download = registry_get("/gems/#{spec.full_name}.gem")
    if download.is_a?(Net::HTTPSuccess)
      abort "Published bytes differ" unless Digest::SHA256.hexdigest(download.body) == sha
      puts "Verified RubyGems metadata and downloaded bytes: #{spec.full_name}"
      exit
    end
    abort "Download failed: HTTP #{download.code}" unless download.is_a?(Net::HTTPNotFound)
  elsif !response.is_a?(Net::HTTPNotFound)
    abort "Read-back failed: HTTP #{response.code}"
  end
  sleep 5 unless attempt == 23
end
abort "RubyGems read-back timed out; verify the existing version before retrying"
