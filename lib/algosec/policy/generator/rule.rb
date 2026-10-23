# frozen_string_literal: true

require_relative "../change_set"

module Algosec
  module Policy
    class Generator
      # 把生成器实际使用的成员声明装配为同一 SecurityRule 图，不读取或重写完整配置。
      class Rule
        def initialize(snapshot, result)
          @snapshot, @result = snapshot, result
        end

        def create(members:, schedule: nil, **attributes)
          if @result.schedule && !schedule
            raise Error.new("生成规则缺少实际时间计划声明", code: :missing_time_generation_evidence)
          end
          groups = groups(members)
          Elements::SecurityRule.new(vendor: @snapshot.vendor, device_id: @snapshot.device_id,
            from_zones: [ @result.from_zone ], to_zones: [ @result.to_zone ], schedule: schedule,
            schedule_name: schedule&.name, **groups, **attributes).seal!
        end

        def modify
          additions = @result.actions.fetch(:add, {})
          updated = groups(additions, original: @result.rule)
          @result.rule.with(**updated).seal!
        end

        private

        def groups(action, original: nil)
          Result::DIMENSIONS.to_h do |dimension|
            old = original&.public_send(dimension)
            values = action.fetch(dimension, {})
            if old && values.empty?
              next [ dimension, old ]
            end
            type = dimension == :services ? Elements::ServiceGroup : Elements::AddressGroup
            options = dimension == :services ? {} : { zone: dimension == :sources ? @result.from_zone : @result.to_zone }
            group = old ? old.dup : type.new(name: dimension.to_s, vendor: @snapshot.vendor, device_id: @snapshot.device_id, **options)
            values.each do |value, names|
              object = names ? existing(dimension, names.first) : literal(dimension, value)
              group.add("generated:#{value}", object)
            end
            [ dimension, group.seal! ]
          end
        end

        def existing(dimension, name)
          if dimension == :services
            objects = @snapshot.services
          else
            zone = dimension == :sources ? @result.from_zone : @result.to_zone
            objects = @snapshot.addresses + @snapshot.elements(Elements::AddressGroup)
            objects = objects.select { |object| @snapshot.behavior.address_in_zone?(object, zone) }
          end
          matches = objects.select { |object| object.name == name }.uniq(&:identity)
          raise Error.new("生成引用 #{name} 没有唯一完整定义", code: :unproven_reference) unless matches.one?
          matches.first
        end

        def literal(dimension, value)
          context = { name: value, vendor: @snapshot.vendor, device_id: @snapshot.device_id }
          if dimension == :services
            protocol, ports = value.split("/", 2)
            Elements::ServiceObject.new(**context, protocol: protocol, source_port: "0-65535", destination_port: ports || "0-65535")
          else
            zone = dimension == :sources ? @result.from_zone : @result.to_zone
            kind = value.include?("/") ? "subnet" : (value.include?("-") ? "iprange" : "host")
            Elements::AddressObject.new(**context, zone: zone, member: [ { type: kind, value: value } ])
          end
        end
      end
    end
  end
end
