# frozen_string_literal: true

require "algosec"

# 合成配置仅演示领域解析和快照，不需要 Rails、数据库或设备连接。
configuration = <<~CONFIG
  set security address-book global address web 192.0.2.10/32
  set applications application HTTPS protocol tcp
  set applications application HTTPS destination-port 443
  set security policies from-zone inside to-zone outside policy web match source-address any
  set security policies from-zone inside to-zone outside policy web match destination-address web
  set security policies from-zone inside to-zone outside policy web match application HTTPS
  set security policies from-zone inside to-zone outside policy web then permit
CONFIG

result = Algosec::Config::Parser.perform(configuration, vendor: :srx, device_id: 1,
  reference_time: Time.utc(2026, 1, 1), time_zone: "UTC")
abort "Configuration is incomplete: #{result.diagnostics.map(&:code).join(', ')}" unless result.complete?
snapshot = Algosec::Policy::Snapshot.from_config(result)
abort "Expected one policy" unless snapshot.rules.one?
cache = Algosec::Config::Cache.new
cache.save(result, source_key: "example-revision")
restored = cache.load(1, source_key: "example-revision")
abort "Cache lost policy evidence" unless restored.rules.one? && restored.reader.content.frozen?

puts "Algosec #{Algosec::VERSION}"
puts "Vendor: #{result.reader.vendor}; complete: #{result.complete?}; policies: #{snapshot.rules.size}"
puts "Cache round trip: verified (memory)"
