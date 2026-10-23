# frozen_string_literal: true

require_relative "../../policy"
require "shellwords"
require_relative "fields"

module Algosec
  module Vendors
    module Topsec
      # Topsec 生成网络对象、策略、时间和 NAT 命令。
      class Generator < Algosec::Policy::Generator
        command_policy placement: :append, permit: "accept", deny: "deny"
        command_fields sources: "src", destinations: "dst", services: "service"

        # 根据新规则结果生成该厂商的完整策略命令。
        def create_rule
          members = prepare(result.actions.fetch(:new))
          require_members!(members)
          schedule = create_schedule
          fields = [ "srcarea #{list([ result.from_zone ])}", "dstarea #{list([ result.to_zone ])}" ]
          command_fields.each { |dimension, field| fields << "#{field} #{list(members[dimension])}" }
          fields << "schedule #{identifier(schedule)}" if schedule
          emit("firewall policy add action #{policy_action} #{fields.join(" ")}")
          record_created_rule
        end

        # 把新增成员或 NAT 变更追加到已有策略，保留原规则范围。
        def modify_rule
          members = prepare(result.actions[:add])
          create_nat_only
          fields = rule_fields if command_fields.keys.any? { |dimension| members[dimension].any? }
          additions = command_fields.filter_map do |dimension, field|
            next if members[dimension].empty?
            existing = fields[field]
            raise Algosec::Policy::Error, "无法读取策略原有 #{field} 成员" unless existing
            "#{field} #{list((existing.split + members[dimension]).uniq)}"
          end
          emit("policy modify id #{identifier(result.rule.native_rule_id)} #{additions.join(" ")}") unless additions.empty?
        end

        # 按厂商语法创建或复用地址对象，并返回命令引用。
        def create_address(value, dimension:)
          parts = address_parts(value)
          return "any" if parts[:prefix] == 0
          define_object(:address, parts[:set], address_name(parts), type: [ Algosec::Elements::AddressObject, Algosec::Elements::AddressGroup ]) do |name|
            command = case parts[:prefix]
            when 32 then "host add name #{identifier(name)} ipaddr #{list([ parts[:first] ])}"
            when nil then "range add name #{identifier(name)} ip1 #{parts[:first]} ip2 #{parts[:last]}"
            else "subnet add name #{identifier(name)} ipaddr #{parts[:first]} mask #{IPAddr.netmask(parts[:prefix])}"
            end
            emit("define #{command}")
          end
        end

        # 按厂商语法创建或复用服务对象，并返回命令引用。
        def create_service(value)
          return "any" if %w[any 0].include?(value.downcase)
          parts = service_parts(value)
          preferred = "#{parts[:protocol].upcase}_#{parts[:text].tr("-", "_")}"
          define_object(:service, parts, preferred, type: [ Algosec::Elements::ServiceObject, Algosec::Elements::ServiceGroup ]) do |name|
            command = "define service add name #{identifier(name)} protocol #{IPAddr.protocol_number(parts[:protocol])} port #{parts[:first]}"
            command += " port2 #{parts[:last]}" unless parts[:first] == parts[:last]
            emit(command)
          end
        end

        # 把一次性时间条件转换为厂商计划命令。
        def create_schedule
          schedule_name do |name, schedule|
            emit("define schedule add name #{identifier(name)} sdate #{schedule.start_at.strftime("%Y-%m-%d")} stime #{schedule.start_at.strftime("%H:%M:%S")} edate #{schedule.end_at.strftime("%Y-%m-%d")} etime #{schedule.end_at.strftime("%H:%M:%S")}")
          end
        end

        # Elements 的前后方向用于命令：源 real -> mapped，目标 mapped -> real。
        # 校验静态 NAT 范围后生成转换命令，并登记可复用对象。
        def create_static_nat(record, direction:)
          unsupported_port_nat!
          equal_nat_ranges!(record)
          real = reusable_address(record[:real_ip], dimension: (direction == :nat_sources) ? :sources : :destinations)
          mapped = reusable_address(record[:nat][:address], dimension: (direction == :nat_sources) ? :sources : :destinations)
          command = if direction == :nat_sources
                      "nat policy add dstarea #{list([ result.to_zone ])} orig-src #{list([ real ])} trans-src #{list([ mapped ])}"
          else
                      "nat policy add srcarea #{list([ result.from_zone ])} orig-dst #{list([ mapped ])} trans-dst #{list([ real ])}"
          end
          once(command) { emit(command) }
        end

        # 按方向和分配组生成动态 NAT 命令，保持请求分组边界。
        def create_dynamic_nat(groups, direction:)
          unsupported_port_nat!
          groups.each do |records|
            nat = records.first[:nat]
            raise Algosec::Policy::Error, "Topsec NAT 需要明确的转换地址" unless nat[:address]
            dimension = (direction == :nat_sources) ? :sources : :destinations
            real = records.map { |record| reusable_address(record[:real_ip], dimension: dimension) }.uniq
            mapped = reusable_address(nat[:address], dimension: dimension)
            fields = [ "srcarea #{list([ result.from_zone ])}", "dstarea #{list([ result.to_zone ])}" ]
            if direction == :nat_sources
              fields << "orig-src #{list(real)}"
              if nat[:option].to_s.include?("d")
                peers = result.destinations.keys.map { |value| reusable_address(value, dimension: :destinations) }
                fields << "orig-dst #{list(peers)}"
              end
              fields << "trans-src #{identifier(mapped)}"
            else
              if nat[:option].to_s.include?("s")
                peers = result.sources.keys.map { |value| reusable_address(value, dimension: :sources) }
                fields << "orig-src #{list(peers)}"
              end
              fields << "orig-dst #{list([ mapped ])}"
              fields << "trans-dst #{list(real)}"
            end
            command = "nat policy add #{fields.join(" ")}"
            once(command) { emit(command) }
          end
          nil
        end

        private

        # 接受保存配置及已有的 policy add 原文，字段值中的引号和关键字仍按 token 处理。
        def rule_fields
          lines = result.rule.config.to_s.lines.reject { |line| line.strip.empty? }
          raise ArgumentError, "策略原文必须是单条声明" unless lines.one?

          words = Shellwords.split(lines.first)
          if words.first == "ID"
            unless words[1] == result.rule.native_rule_id
              raise ArgumentError, "策略原文编号与当前规则不一致"
            end
            words.shift(2)
          end
          words.shift if words.first == "firewall"
          raise ArgumentError, "缺少 policy add 声明" unless words.shift(2) == %w[policy add]

          Fields.parse(words)
        rescue ArgumentError => error
          raise Algosec::Policy::Error.new("无法读取策略原有成员：#{error.message}", code: :invalid_rule_config)
        end

        def list(values)
          "'#{values.map { |value| identifier(value) }.join(" ")} '"
        end
      end
    end
  end
end
