# frozen_string_literal: true

require_relative "value"
require_relative "definition"
require_relative "snapshot"
require_relative "../elements"
require_relative "request/traffic"

module Algosec
  module Policy
    class Result
      DIMENSIONS = %i[sources destinations services].freeze
      MEMBERS = [ *DIMENSIONS, :nat_sources, :nat_destinations ].freeze
      attr_reader :device_id, :device_name, :vendor, :nat_mode, :from_zone, :to_zone,
                  :type, :hit, :actions, :existing, :sources, :destinations, :services,
                  :schedule, :rule, :snapshot, :definition, :decision, :source_rule_id, :conflicting_rules, :uncovered, :evaluated_at

      # 校验查询结果的设备、方向和操作类型，并冻结所有输入投影。
      def initialize(device_id:, device_name:, vendor:, from_zone:, to_zone:, type:, hit:,
                     sources:, destinations:, services:, nat_mode: 0, actions: nil, existing: nil,
                     schedule: nil, rule: nil, snapshot: nil, definition: nil, decision: :permit, source_rule_id: nil,
                     conflicting_rules: [], uncovered: nil, evaluated_at: nil)
        raise ArgumentError, "设备编号必须为正整数" unless device_id.is_a?(Integer) && device_id.positive?
        @device_id, @device_name = device_id, Value.text(device_name, label: "设备名").freeze
        snapshot_definition = snapshot.definition if snapshot.respond_to?(:definition)
        @vendor, @definition = Definition.resolve(vendor, explicit: definition || snapshot_definition)
        @nat_mode = nat_mode
        raise ArgumentError, "NAT 模式必须是 0、1 或 2" unless @nat_mode.is_a?(Integer) && (0..2).cover?(@nat_mode)
        @from_zone, @to_zone = [ from_zone, to_zone ].map { |zone| Value.text(zone, label: "安全域").freeze }
        @type, @hit = Value.symbol(type, label: "查询类型"), Value.symbol(hit, label: "命中方向")
        @decision = Value.symbol(decision, label: "策略动作")
        @source_rule_id = Value.text(source_rule_id, label: "源规则身份").freeze if source_rule_id
        raise ArgumentError, "策略动作必须是 permit 或 deny" unless %i[permit deny].include?(@decision)
        raise ArgumentError, "查询类型必须是 new、modify 或 ignore" unless %i[new modify ignore].include?(@type)
        raise ArgumentError, "命中方向必须是 source 或 destination" unless %i[source destination].include?(@hit)
        raise ArgumentError, "规则必须是 Rule" if rule && !rule.is_a?(Elements::SecurityRule)
        raise ArgumentError, "时间计划必须是 Schedule" if schedule && !schedule.is_a?(Elements::Schedule)
        @sources, @destinations, @services = [ sources, destinations, services ].map do |map|
          raise ArgumentError, "查询维度必须是非空 Hash" unless map.is_a?(Hash) && !map.empty?
          Value.immutable(map)
        end
        @actions, @existing = Value.immutable(actions), Value.immutable(existing)
        @schedule, @rule, @snapshot = schedule, rule, snapshot
        unless conflicting_rules.is_a?(Array) && conflicting_rules.all? { |item| item.is_a?(Elements::SecurityRule) }
          raise ArgumentError, "冲突策略必须是 Rule 数组"
        end
        raise ArgumentError, "Invalid uncovered traffic" unless uncovered.nil? || uncovered.is_a?(TrafficSet)
        @uncovered, @evaluated_at = uncovered, evaluated_at&.dup&.freeze
        @conflicting_rules = conflicting_rules.dup.freeze
        validate!
        freeze
      end

      # 生成入口消费精确缺口；每个矩形独立生成，绝不合并维度投影。
      def generation_results
        return [ self ] unless uncovered && type == :new
        if actions.values.any? { |members| (members.keys & %i[nat_sources nat_destinations]).any? } ||
            DIMENSIONS.any? { |dimension| public_send(dimension).values.any? { |entry| entry[:nat] || entry[:translated_port] } }
          raise Error.new("NAT 缺口需要独立转换声明，不能丢弃分配后拆分", code: :unsupported_nat_gap)
        end
        maps = DIMENSIONS.to_h { |dimension| [ dimension, public_send(dimension) ] }
        Request::Traffic.slices(uncovered, maps).map do |slice|
          names = slice.to_h { |dimension, entries| [ dimension, entries.transform_values { nil } ] }
          self.class.new(device_id: device_id, device_name: device_name, vendor: vendor, definition: definition,
            from_zone: from_zone, to_zone: to_zone, type: type, hit: hit, nat_mode: nat_mode,
            **slice, actions: { new: names }, schedule: schedule, snapshot: snapshot, decision: decision,
            source_rule_id: source_rule_id, conflicting_rules: conflicting_rules, evaluated_at: evaluated_at)
        end
      end

      def traffic_set
        Request::Traffic.from_maps(DIMENSIONS.to_h { |dimension| [ dimension, public_send(dimension) ] })
      end

      private

      # 按结果类型校验操作、已有规则、维度成员及设备厂商一致性。
      def validate!
        services.each do |service, metadata|
          Ranges.normalize_service(service)
          Ranges.normalize_service(metadata[:origin]) if metadata.is_a?(Hash) && metadata.key?(:origin)
        end
        if snapshot && (!snapshot.is_a?(Snapshot) || snapshot.device_id != device_id || snapshot.vendor != vendor)
          raise ArgumentError, "查询结果与配置快照的设备不一致"
        end
        raise ArgumentError, "策略操作必须是 Hash" unless actions.nil? || actions.is_a?(Hash)
        raise ArgumentError, "拒绝规则只能作为新增策略生成" if decision == :deny && type != :new
        if type == :new
          raise ArgumentError, "新增策略只能包含 new 操作" unless actions.is_a?(Hash) && actions.keys == [ :new ]
          raise ArgumentError, "新增策略不能关联已有规则" if existing || rule
        elsif type == :modify
          raise ArgumentError, "修改策略必须提供操作和规则" unless actions.is_a?(Hash) && rule.is_a?(Elements::SecurityRule)
        end
        if existing && (!rule.is_a?(Elements::SecurityRule) || !DIMENSIONS.all? { |key| existing[key].is_a?(String) })
          raise ArgumentError, "已有结果必须包含三个维度及规则对象"
        end
        if rule
          other_vendor = rule.vendor != vendor
          other_device = ![ nil, device_id ].include?(rule.device_id)
          raise ArgumentError, "查询结果与已有规则的设备不一致" if other_vendor || other_device
        end
        (actions || {}).each do |action, members|
          unless %i[new add].include?(action) && members.is_a?(Hash) && (members.keys - MEMBERS).empty?
            raise ArgumentError, "不支持的策略操作或成员"
          end
          members.each do |dimension, map|
            raise ArgumentError, "操作成员必须是 Hash" unless map.is_a?(Hash)
            next unless DIMENSIONS.include?(dimension)
            unless (map.keys - public_send(dimension).keys).empty?
              raise ArgumentError, "新增成员不在 #{dimension} 请求中"
            end
          end
        end
      end
    end
  end
end
