# frozen_string_literal: true

require "algosec"
require "algosec/policy/plan_document"
require "digest"
require "json"

# 独立原生配置展示解析、文档恢复、查询、回收规划和读回证明；不连接设备。
retained = <<~CONFIG
  set rulebase security rules established from inside
  set rulebase security rules established to outside
  set rulebase security rules established source any
  set rulebase security rules established destination any
  set rulebase security rules established service any
  set rulebase security rules established application any
  set rulebase security rules established action allow
CONFIG
redundant = <<~CONFIG
  set rulebase security rules redundant from inside
  set rulebase security rules redundant to outside
  set rulebase security rules redundant source any
  set rulebase security rules redundant destination any
  set rulebase security rules redundant service any
  set rulebase security rules redundant application any
  set rulebase security rules redundant action allow
CONFIG

at = Time.utc(2030, 1, 1, 12)
source = retained + redundant
parsed = Algosec::Config::Parser.perform(source, vendor: :palo_alto, device_id: 1, reference_time: at, time_zone: "UTC")
abort "Incomplete source configuration" unless parsed.complete?

# 默认文档省略原文，载入仍恢复同一领域契约；宿主另外保存并验证来源摘要。
configuration_json = JSON.generate(Algosec::Config::Document.dump(parsed))
restored = Algosec::Config::Document.load(JSON.parse(configuration_json), expected_source_sha256: Digest::SHA256.hexdigest(source))
snapshot = Algosec::Policy::Snapshot.from_config(restored, revision: Digest::SHA256.hexdigest(source))
packet = Algosec::Policy::Packet.new(source: "10.0.0.1", destination: "192.0.2.10", protocol: 6, source_port: 12_345, destination_port: 443)
evaluation = Algosec::Policy::Evaluation.new(snapshot, at: at).perform(packet, from_zone: "inside", to_zone: "outside")
abort "Expected proven allow" unless evaluation.complete? && evaluation.partitions.one? && evaluation.partitions.first.action == "allow"

rule = snapshot.rules.find { |entry| entry.name == "redundant" }
plan = Algosec::Policy::Reclaimer.new(snapshot, at: at).plan(rule_ids: [ snapshot.signature(rule) ])
abort "Reclamation is not proven" unless plan.executable?

# 审批输入重建后重新证明，不把审阅 JSON 中的成功标记当作执行授权。
plan_json = JSON.generate(Algosec::Policy::PlanDocument.dump(plan))
fresh = Algosec::Policy::Snapshot.from_config(Algosec::Config::Document.load(JSON.parse(configuration_json)), revision: snapshot.revision)
approved = Algosec::Policy::PlanDocument.load(JSON.parse(plan_json), target: fresh)
approved.validate!(target: fresh)
abort "Restored command changed" unless approved.script == plan.script

# 读回是另一份原生配置，不能用 ChangeSet.apply 作为已经执行的证据。
readback = Algosec::Config::Parser.perform(retained, vendor: :palo_alto, device_id: 1, reference_time: at, time_zone: "UTC")
actual = Algosec::Policy::Snapshot.from_config(readback, revision: Digest::SHA256.hexdigest(retained))
abort "Readback failed" unless approved.verify_readback(actual).verified?
abort "Undeleted rule incorrectly accepted" if approved.verify_readback(fresh).verified?

puts "Configuration document: restored; packet: allow"
puts "Reclamation: generated and proven; approved document: reproven"
puts "Independent readback: verified; undeleted rule: rejected"
puts "Evidence: synthetic offline configuration; no device session"
