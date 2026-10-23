# frozen_string_literal: true

require "json"
require_relative "analysis"
require_relative "change_set"
require_relative "effect_proof"
require_relative "nat/verification"

module Algosec
  module Policy
    # 可审阅的单设备操作计划；存在未解决项时不发布部分脚本。
    class Plan
      attr_reader :operation, :device_id, :vendor, :source_device_id, :source_vendor, :changes, :issues, :target_baseline, :source_baseline, :target_snapshot, :source_snapshot, :change_set, :proof, :required_effects, :effect_proofs

      def initialize(operation:, snapshot:, changes:, issues: [], commands: "", source: snapshot, change_set: nil, proof: nil, required_effects: [], effect_proofs: {})
        [ snapshot, source ].each(&:require_complete!) if issues.empty?
        [ snapshot, source ].each do |item|
          item.catalog.seal!
          item.builtin_services.each(&:seal!)
        end
        @target_snapshot, @source_snapshot = snapshot, source
        @operation, @device_id, @vendor = operation, snapshot.device_id, snapshot.vendor
        @source_device_id, @source_vendor = source.device_id, source.vendor
        @target_baseline, @source_baseline = snapshot.baseline, source.baseline
        @change_set = change_set
        @proof = proof || change_set&.verify
        if @proof && (!@proof.is_a?(ChangeSet::Verification) || !@proof.change_set.equal?(@change_set) || !@change_set.snapshot.equal?(snapshot))
          raise ArgumentError, "Plan proof does not belong to this baseline and change set"
        end
        unless required_effects.is_a?(Array) && required_effects.all? { |effect| effect.is_a?(Symbol) } && effect_proofs.is_a?(Hash)
          raise ArgumentError, "Invalid effect proof requirements"
        end
        @required_effects = (required_effects | (change_set&.required_effects || [])).freeze
        @effect_proofs = effect_proofs.dup.freeze
        effect_proofs.each do |effect, proof|
          unless proof.is_a?(EffectProof) && proof.effect == effect && change_set && proof.change_set.equal?(change_set) && proof.generation? &&
              JSON.parse(JSON.generate(proof.baseline)) == JSON.parse(JSON.generate(@target_baseline))
            raise ArgumentError, "Effect proof does not belong to this baseline and change set"
          end
        end
        @generated = commands.is_a?(String)
        blockers = issues.dup
        if @proof
          blockers.concat(@proof.issues)
          unless @proof.differences.empty?
            blockers << Finding.new(check: :semantic_proof, rule_id: nil, status: :fail, severity: :critical,
              message: "候选未满足目标动作或改变了目标范围外的行为", evidence: { differences: @proof.differences.size })
          end
        else
          blockers << Finding.new(check: :semantic_proof, rule_id: nil, status: :unknown, severity: :critical,
            message: "计划缺少完整的语义验证", evidence: { code: :missing_semantic_proof })
        end
        @required_effects.each do |effect|
          next if effect_proofs[effect]&.verified?
          blockers << Finding.new(check: :effect_proof, rule_id: nil, status: :unknown, severity: :critical,
            message: "#{effect} 生成尚无完整效果证明", evidence: { code: :missing_effect_proof, effect: effect })
        end
        @changes, @issues = Value.immutable(changes), blockers.freeze
        @script = commands&.dup&.freeze
        freeze
      end

      def semantic_version = target_baseline.fetch(:semantic_version)

      def generated? = @generated
      def verified? = !!proof&.verified? && required_effects.all? { |effect| effect_proofs[effect]&.verified? }
      def executable? = generated? && verified? && issues.empty?
      alias ready? executable?

      def verify_readback(snapshot)
        raise Error.new("计划缺少语义验证", code: :missing_semantic_proof) unless executable?
        security = change_set.verify(candidate: snapshot)
        effects = required_effects.to_h { |effect| [ effect, effect_proofs.fetch(effect).verify_readback(snapshot) ] }
        if !required_effects.include?(:nat) && [ change_set.snapshot, snapshot ].any? { |graph| graph.nat_rules.any? || graph.rules.any?(&:nat?) }
          # 安全候选不持有生成器的独立 NAT 图；聚合层用同一拥有者证明未经请求的转换仍未改变。
          effects[:nat] = Nat::Verification.unchanged(change_set: change_set).verify_readback(snapshot)
        end
        Readback.new(security: security, effects: effects.freeze)
      end

      Readback = Data.define(:security, :effects) do
        def verified? = security.verified? && effects.values.all?(&:verified?)
        def issues = security.issues + effects.values.flat_map { |proof| proof.respond_to?(:issues) ? proof.issues : [] }
        def differences = security.differences + effects.values.flat_map { |proof| proof.respond_to?(:differences) ? proof.differences : [] }
        def to_h = { security: security.to_h, effects: effects.transform_values(&:to_h), verified: verified? }
      end

      # 宿主持久化审阅证据，不保存 Ruby 对象身份或把旧回执恢复为执行授权。
      def to_h
        { operation: operation, device_id: device_id, vendor: vendor, source_device_id: source_device_id, source_vendor: source_vendor,
          semantic_version: semantic_version, target_baseline: target_baseline, source_baseline: source_baseline,
          changes: changes, generated: generated?, verified: verified?, executable: executable?, required_effects: required_effects,
          change_set: change_set&.to_h, proof: proof&.to_h, effect_proofs: effect_proofs.transform_values(&:to_h), issues: issues.map(&:to_h) }
      end

      # 发布方在取得最新快照后调用；离线无修订信息的计划仍可审阅，但不能验证发布依据。
      def validate!(target:, source: target)
        script
        [ [ target, target_baseline ], [ source, source_baseline ] ].each do |snapshot, expected|
          self.class.validate_baseline!(snapshot, expected)
        end
        self
      end

      # JSON 持久化会把符号转换为字符串，核验共用同一份规范字段。
      def self.validate_baseline!(snapshot, expected)
        unless snapshot.is_a?(Snapshot) && snapshot.revision
          raise Error.new("计划缺少可核验的配置修订依据", code: :missing_baseline)
        end
        snapshot.require_complete!
        validate_context!(snapshot.baseline, expected)
      end

      # 数据库适配层可提供同一组基线字段，无需为比较修订重建规则目录。
      def self.validate_context!(actual, expected)
        actual, expected = [ actual, expected ].map { |value| JSON.parse(JSON.generate(value)) }
        unless [ actual, expected ].all? { |value| value.is_a?(Hash) && value["revision"].present? }
          raise Error.new("计划缺少可核验的配置修订依据", code: :missing_baseline)
        end
        unless [ actual, expected ].all? { |value| value["semantic_version"] == Algosec::SEMANTIC_VERSION }
          raise Error.new("计划语义版本已变化，请重新设计", code: :semantic_version_mismatch)
        end
        unless actual == expected
          raise Error.new("配置或设备上下文已变化，请重新查询并设计", code: :stale_plan)
        end
        true
      end

      # 生成只返回文本，调用者通过已有发布流程单独执行。
      def script
        raise Error.new("计划存在未解决项：#{issues.map(&:message).uniq.join('；')}", code: :incomplete_plan) unless ready?
        @script
      end
    end
  end
end
