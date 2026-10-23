# frozen_string_literal: true

require "active_support/core_ext/hash/slice"
require_relative "result"
require_relative "ranges"
require_relative "snapshot"
require_relative "rule_matcher/comparison"
require_relative "rule_order"
require_relative "evaluation"
require_relative "request/traffic"

module Algosec
  module Policy
    # 比较允许规则的范围，产生新增／修改／复用计划；不执行设备策略。
    class RuleMatcher
      # 保存配置快照和查询时刻，确保候选判断使用同一个时间点。
      def initialize(snapshot, at: Time.current)
        snapshot.require_complete!
        @snapshot, @at = snapshot, at
      end

      # 筛选动作、区域、状态和时间都符合请求的候选规则。
      def candidates(from_zone:, to_zone:)
        @snapshot.rules.select do |rule|
          next false if !rule.status_known? || rule.application_or_user_restricted? || rule.ignored?(at: @at)
          raise Error, "规则 #{rule.name} 的时间计划未解析" if rule.schedule_name && !rule.schedule
          @snapshot.behavior.candidate?(rule, from_zone: from_zone, to_zone: to_zone)
        end
      end

      # 先尝试复用，再选择可扩展规则，最后生成新规则或仅 NAT 操作。
      def match(group, schedule: nil)
        request_maps = Result::DIMENSIONS.to_h { |dimension| [ dimension, Value.copy(group.fetch(dimension)) ] }
        ranges = {
          sources: Ranges.addresses(request_maps[:sources].keys),
          destinations: Ranges.addresses(request_maps[:destinations].keys),
          services: Ranges.services(request_maps[:services].keys)
        }
        actions = nat_actions(request_maps)
        rules = candidates(**group.slice(:from_zone, :to_zone))
        if @snapshot.behavior.policy_embeds_nat?
          # 内嵌 NAT 属于规则自身；完整规则链仍须检查不同 NAT 语义的前置规则。
          rules = actions.empty? ? rules.select { |rule| policy_nat_matches?(rule, request_maps) } : []
        end
        conflicts = []
        evaluation = Evaluation.new(@snapshot, at: @at).perform(Request::Traffic.from_maps(request_maps), **group.slice(:from_zone, :to_zone))
        uncertain = evaluation.partitions.select { |part| %i[unknown conditional].include?(part.status) }
        unless uncertain.empty?
          code = uncertain.any? { |part| part.reason&.include?("顺序") || part.reason&.include?("规则链") } ? :unknown_order : :conditional_policy
          raise Error.new(uncertain.map(&:reason).uniq.join("；"), code: code)
        end
        conflicts = evaluation.partitions.filter_map { |part| part.rule if part.status == :matched && part.action != "allow" }.uniq
        safe_coverage = !@snapshot.behavior.policy_embeds_nat? && actions.empty? && schedule.nil? &&
          request_maps.values.none? { |map| map.values.any? { |entry| entry[:nat] } }
        covered_traffic = evaluation.partitions.reduce(TrafficSet.new) do |set, part|
          stable = !part.rule || (!part.rule.schedule && !part.rule.schedule_name && !part.rule.starts_at && !part.rule.expires_at)
          part.status == :matched && part.action == "allow" && stable ? set | part.traffic_set : set
        end
        uncovered = safe_coverage ? Request::Traffic.from_maps(request_maps) - covered_traffic : nil
        if uncovered&.empty?
          selected = evaluation.partitions.map(&:rule).compact.uniq
          selected = selected.one? ? selected.first : nil
          existing = selected && request_maps.transform_values { |map| map.keys.sort.join(",") }
          return Result.new(**group.slice(:device_id, :device_name, :vendor, :nat_mode, :from_zone, :to_zone, :hit).merge(request_maps),
            type: :ignore, rule: selected, existing: existing, snapshot: @snapshot, evaluated_at: @at)
        end
        # 已覆盖区域不再提交修改；部分命中的精确差集由生成入口逐矩形消费。
        exact_gap = uncovered && !covered_traffic.empty?
        if @snapshot.behavior.policy_embeds_nat?
          hits = evaluation.partitions.filter_map(&:rule).uniq
          conflicts |= hits - rules
          rules &= hits unless hits.empty?
        end
        if conflicts.any?
          hit_rules = evaluation.partitions.filter_map { |part| part.rule if part.status == :matched && part.action == "allow" }
          rules &= hit_rules
        end
        rules.each do |rule|
          next unless rule.sources.conditional? || rule.destinations.conditional?
          projections = { sources: potential_addresses(rule.sources), destinations: potential_addresses(rule.destinations), services: rule.services.set }
          next if projections.any? { |dimension, set| set && !set.overlap?(ranges.fetch(dimension)) }
          raise Error.new("规则 #{rule.rule_id || rule.name} 依赖 DNS 解析结果", code: :conditional_policy)
        end
        rules = rules.reject { |rule| rule.sources.conditional? || rule.destinations.conditional? }
        compared = rules.map do |rule|
          Comparison.new(rule, snapshot: @snapshot, maps: request_maps, ranges: ranges)
        end
        covered = compared.find { |comparison| comparison.covers?(schedule: schedule) }
        existing, selected = nil, nil
        to_zone = group.fetch(:to_zone)
        if covered
          type, selected = :ignore, covered.rule
          existing = request_maps.transform_values { |map| map.keys.sort.join(",") }
        else
          choices = schedule.nil? ? compared.select do |comparison|
            comparison.extendable? && @snapshot.behavior.editable_rule?(comparison.rule, **group.slice(:from_zone, :to_zone)) &&
              (!exact_gap || (evaluation.partitions.filter_map { |part| part.rule if part.action == "allow" }.uniq.one? && exact_additions?(comparison)))
          end : []
          if choices.empty?
            type = :new
            names = Result::DIMENSIONS.to_h do |dimension|
              zone = (dimension == :sources) ? group.fetch(:from_zone) : to_zone
              [ dimension, names_for(dimension, request_maps.fetch(dimension), zone) ]
            end
            to_zone = @snapshot.behavior.refine_new_rule_names(group, request_maps, names, to_zone) do |zone|
              names_for(:destinations, request_maps[:destinations], zone)
            end
            actions[:new] = actions.fetch(:new, {}).merge(names)
            retain_policy_nat(actions[:new], request_maps) if @snapshot.behavior.policy_embeds_nat?
          else
            type = :modify
            selected, additions, existing = choose(choices)
            to_zone = @snapshot.behavior.modified_to_zone(selected, to_zone)
            actions[:add] = additions.to_h do |dimension, map|
              zone = (dimension == :sources) ? group.fetch(:from_zone) : to_zone
              [ dimension, names_for(dimension, map, zone) ]
            end
          end
        end
        attributes = group.slice(:device_id, :device_name, :vendor, :nat_mode, :from_zone, :hit).merge(request_maps)
        Result.new(**attributes,
                   to_zone: to_zone, type: type, actions: actions.empty? ? nil : actions,
                   existing: existing, rule: selected, snapshot: @snapshot, schedule: schedule,
                   conflicting_rules: conflicts, uncovered: exact_gap ? uncovered : nil, evaluated_at: @at)
      end

      # 可复用名称必须覆盖完整定义，混合协议或有限源端口不能冒充单一服务。
      def names_for(dimension, map, zone)
        return map.transform_values { nil } if map.empty? || !@snapshot.behavior.reusable_names?

        targets = map.keys.to_h { |value| [ value, (dimension == :services) ? Ranges.service(value) : IPAddr.parse(value) ] }
        index = targets.values.to_h { |set| [ set, [] ] }
        objects = (dimension == :services) ? @snapshot.services : @snapshot.addresses
        objects.each do |object|
          set = if dimension == :services
                  next unless @snapshot.behavior.reusable_service?(object)
                  projection = object.service_projection
                  next unless projection.dig(:resolution, "complete") && projection[:member].all? { |term| Ranges.unrestricted_term?(term) }
                  Ranges.services(projection[:member].map { |term| "#{term[:protocol]}/#{term[:destination_port]}" })
          else
                  next unless @snapshot.behavior.address_in_zone?(object, zone) && object.resolved? && !object.conditional?
                  next unless object.address_projection(at: @at, family: :ipv6)[:set].empty?
                  object.resolved_set
          end
          index[set] << object.name if index.key?(set) && object.name
        end
        targets.transform_values do |target|
          names = index.fetch(target).uniq.sort
          names unless names.empty?
        end
      end

      private

      # 已覆盖对象只追加不重叠的新成员；部分 CIDR 缺口交给独立规则精确表达。
      def exact_additions?(comparison)
        return false unless comparison.changes.additions.size == 1
        projection = Ranges.projection(comparison.rule)
        comparison.changes.additions.all? do |dimension, entries|
          entries.keys.all? do |value|
            set = dimension == :services ? Ranges.service(value) : IPAddr.parse(value)
            !projection.fetch(dimension).overlap?(set)
          end
        end
      end

      def potential_addresses(group)
        Ranges.rule_addresses(group)
      rescue Elements::Group::UnresolvedReference, ArgumentError, Error
        nil
      end

      # 从地址维度收集新增 NAT 操作。
      def nat_actions(request_maps)
        records = { nat_sources: :sources, nat_destinations: :destinations }.each_with_object({}) do |(key, dimension), actions|
          entries = request_maps.fetch(dimension).select { |_address, entry| entry[:action] == :new_nat }
          actions[key] = entries unless entries.empty?
        end
        records.empty? ? {} : { new: records }
      end

      # 判断已有内嵌 NAT 是否属于当前候选规则。
      def policy_nat_matches?(rule, request_maps)
        request_maps[:sources].values.all? do |address_entry|
          nat_rule = address_entry.dig(:nat, :rule)
          next true unless nat_rule.is_a?(Elements::DynamicNat)
          policy_id = @snapshot.behavior.nat_policy_id(nat_rule)
          policy_id.nil? || policy_id == rule.native_rule_id
        end
      end

      # 将仍需保留的源 NAT 信息复制到新策略操作中。
      def retain_policy_nat(action, request_maps)
        records = request_maps[:sources].select { |_, address_entry| address_entry.dig(:nat, :rule) }
        records.each do |value, existing_entry|
          next unless @snapshot.behavior.retain_source_nat?(existing_entry[:nat])
          address_entry = Value.copy(existing_entry)
          address_entry[:real_ip] ||= address_entry[:private] || value
          (action[:nat_sources] ||= {})[value] ||= address_entry
        end
      end

      # 按新增数量和稳定签名选择唯一最佳候选。
      def choose(choices)
        winner = choices.min_by(&:rank)
        [ winner.rule, winner.changes.additions, winner.changes.existing ]
      end
    end
  end
end
