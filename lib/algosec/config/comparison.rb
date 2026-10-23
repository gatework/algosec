# frozen_string_literal: true

require "json"
require_relative "document"

module Algosec
  module Config
    # 比较规则声明及其引用图；不把配置相同等同于当前设备流量行为等价。
    class Comparison
      def initialize(before:, after:)
        unless [ before, after ].all? { |result| result.is_a?(Result) } &&
               before.reader.device_id == after.reader.device_id && before.reader.vendor == after.reader.vendor
          raise ArgumentError, "Comparison requires parsing results from the same device and vendor"
        end
        @before, @after = before, after
      end

      # 保留完整的左右证据；未解析引用使结果不完整，但不丢弃已知差异。
      def perform
        @unresolved = false
        before, after = [ @before, @after ].map { |result| result.rules.reject(&:container?).to_h { |rule| [ rule.rule_id, evidence(rule) ] } }
        changes = (before.keys | after.keys).sort.filter_map do |id|
          left, right = before[id], after[id]
          next if left == right
          { rule_id: id, status: left.nil? ? "added" : right.nil? ? "removed" : "modified", before: left, after: right }
        end
        { complete: @before.complete? && @after.complete? && !@unresolved,
          summary: changes.map { |change| change[:status] }.tally, changes: changes }
      end

      private

      # 每条规则用平铺对象清单表达引用，共享子组只登记一次，避免嵌套输出指数膨胀。
      def evidence(rule)
        pending, objects, visited = [], [], {}.compare_by_identity
        references = %i[sources destinations services].to_h do |dimension|
          [ dimension, group_evidence(rule.public_send(dimension), pending) ]
        end
        if rule.schedule || rule.schedule_name
          references[:schedule] = links({ rule.schedule_name || rule.schedule.name => rule.schedule }, pending)
        end
        until pending.empty?
          object = pending.pop
          next if visited[object]
          visited[object] = true
          objects << object_evidence(object, pending)
        end
        { name: rule.name, action: rule.action, native_action: rule.native_action, scope: rule.scope.to_h,
          rule_type: rule.rule_type, native_rule_type: rule.native_rule_type, applications: rule.applications, source_users: rule.source_users, from_zones: rule.from_zones, to_zones: rule.to_zones,
          configuration: rule.config, sequence: rule.rule_number, rule_set: rule.rule_set,
          status: rule.status, log: rule.log, log_enabled: rule.log_enabled,
          from_interface: rule.from_interface, dst_interfaces: rule.dst_interfaces,
          conditions: rule.semantic_conditions, unparsed_commands: rule.unparsed_commands_metadata, vendor_data: rule.vendor_data, nat: rule.nat?,
          references: references, objects: objects.sort_by { |object| object.fetch(:identity) } }
      end

      # 名称指向结构化身份；nil 是缺失引用，不是空集合或任意条件。
      def links(members, pending)
        members.sort.to_h.transform_values do |object|
          if object
            pending << object
            identity(object)
          else
            @unresolved = true
            nil
          end
        end
      end

      def identity(object) = JSON.generate([ object.element_type, object.scope.to_h, object.identity_fields ])

      # 匹配维度的临时组名不是设备声明；保留组的类型、作用域和完整成员。
      def group_evidence(group, pending)
        data = { kind: Document.codec_for(group).first, scope: group.scope.to_h }
        data[:zone] = group.zone if group.is_a?(Elements::AddressGroup)
        data[:protocol] = group.protocol if group.is_a?(Elements::ServiceGroup)
        data.merge(members: links(group.members, pending))
      end

      # 使用声明数据而不是运行时 DNS、引用计数或当前时间计算出的生效状态。
      def object_evidence(object, pending)
        data = { kind: Document.codec_for(object).first, identity: identity(object), name: object.name, configuration: object.config }
        case object
        when Elements::Group
          data.merge(group_evidence(object, pending))
        when Elements::AddressObject
          data.merge(zone: object.zone, member: object.direct_member, excluded_member: object.excluded_member, unresolved: object.unresolved,
                     references: links(object.references, pending))
        when Elements::ServiceObject
          data.merge(terms: object.terms)
        when Elements::Schedule
          @unresolved = true unless object.resolved?
          data.merge(kind: object.kind, time_zone: object.time_zone.name,
                     start_at: object.start_at&.iso8601, end_at: object.end_at&.iso8601,
                     weekly_windows: object.weekly_windows.transform_values { |ranges| ranges.map { |range| [ range.begin, range.end, range.exclude_end? ] } },
                     monthly_periods: object.monthly_periods, unparsed_commands: object.unparsed_commands_metadata)
        else
          raise ArgumentError, "Unsupported rule dependency: #{object.class}"
        end
      end
    end
  end
end
