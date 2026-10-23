# frozen_string_literal: true

require_relative "../../policy"

module Algosec
  module Vendors
    module Hillstone
      # StoneOS 生成对象、策略、时间和 NAT 命令。
      class Generator < Algosec::Policy::Generator
        command_operation :remove_rule, using: :remove_rule
        command_policy placement: :prepend, permit: "permit", deny: "deny", logging_default: false
        command_frame before: [ "configure" ], after: [ "save" ]
        command_fields sources: "src-addr", destinations: "dst-addr", services: "service"

        # StoneOS 5.5R5 CLI, Policy chapter: scoped deletion in global configuration mode.
        def remove_rule(rule)
          if rule.vendor_data["aggregate_type"] || rule.vendor_data["aggregate_rule_id"]
            raise Algosec::Policy::Error.new("聚合策略需要先审阅成员依赖", code: :aggregate_dependency)
          end
          emit("no rule id #{numeric_identifier(rule.native_rule_id)}")
        end

        # 根据新规则结果生成该厂商的完整策略命令。
        def create_rule
          members = prepare(result.actions.fetch(:new))
          require_members!(members)
          schedule = create_schedule
          emit("rule top", "action #{policy_action}", "src-zone #{quoted(result.from_zone)}", "dst-zone #{quoted(result.to_zone)}")
          member_commands(members).each { |line| emit(line) }
          emit("schedule #{quoted(schedule)}") if schedule
          emit("exit")
          record_created_rule
        end

        # 把新增成员或 NAT 变更追加到已有策略，保留原规则范围。
        def modify_rule
          members = prepare(result.actions[:add])
          create_nat_only
          additions = member_commands(members)
          emit("rule id #{identifier(result.rule.native_rule_id)}", *additions, "exit") unless additions.empty?
        end

        # 按厂商语法创建或复用地址对象，并返回命令引用。
        def create_address(value, dimension:)
          parts = address_parts(value)
          return "any" if parts[:prefix] == 0
          name = if parts[:prefix]
                   (parts[:prefix] == 32) ? "Host_#{parts[:first]}" : "Net_#{parts[:text]}"
          else
                   "range_#{parts[:first]}-#{parts[:last]}"
          end
          definition = parts[:prefix] ? "ip #{parts[:text]}" : "range #{parts[:first]} #{parts[:last]}"
          define_object(:address, parts[:set], name, type: [ Algosec::Elements::AddressObject, Algosec::Elements::AddressGroup ]) { |selected| emit("address #{quoted(selected)}", definition, "exit") }
        end

        # 按厂商语法创建或复用服务对象，并返回命令引用。
        def create_service(value)
          return "any" if %w[any 0].include?(value.downcase)
          parts = service_parts(value)
          raise Algosec::Policy::Error, "Hillstone 服务端口不能全为 0" if parts[:last].zero?
          name = "#{parts[:protocol].upcase}_#{parts[:text].tr("-", "_")}"
          define_object(:service, parts, name, type: [ Algosec::Elements::ServiceObject, Algosec::Elements::ServiceGroup ]) do |selected|
            emit("service #{quoted(selected)}", "#{parts[:protocol]} dst-port #{parts[:text].tr("-", " ")}", "exit")
          end
        end

        # 把一次性时间条件转换为厂商计划命令。
        def create_schedule
          schedule_name do |name, schedule|
            emit("schedule #{quoted(name)}", "absolute start #{schedule.start_at.strftime("%m/%d/%Y %H:%M")} end #{schedule.end_at.strftime("%m/%d/%Y %H:%M")}", "exit")
          end
        end

        # 校验静态 NAT 范围后生成转换命令，并登记可复用对象。
        def create_static_nat(record, direction:)
          unsupported_nat_option!(record)
          unsupported_port_nat! if direction == :nat_destinations
          real, mapped = equal_nat_ranges!(record)
          command = "bnatrule virtual ip #{mapped[:text]} real ip #{real[:text]}"
          once(command) { emit("nat", command, "exit") }
        end

        # 按方向和分配组生成动态 NAT 命令，保持请求分组边界。
        def create_dynamic_nat(groups, direction:)
          groups.flatten.each do |record|
            unsupported_nat_option!(record)
            unsupported_port_nat! if direction == :nat_destinations
            real = address_parts(record[:real_ip])[:text]
            mapped = record[:nat][:address] && address_parts(record[:nat][:address])[:text]
            command = if direction == :nat_sources
                        "snatrule from #{quoted(real)} to \"Any\" service \"Any\" trans-to #{mapped || "eif-ip"} mode dynamicport"
            else
                        "dnatrule from \"Any\" to #{quoted(mapped)} service \"Any\" trans-to #{quoted(real)}"
            end
            once(command) { emit("nat", command, "exit") }
          end
          nil
        end

        private

        # 不静默丢弃统一 NAT 请求中 Hillstone 尚未实现的匹配选项。
        def unsupported_nat_option!(record)
          option = record.dig(:nat, :option)
          return if option.nil? || option == ""

          raise Algosec::Policy::Error.new("Hillstone 暂不支持 NAT option #{option.inspect}", code: :unsupported_nat_option)
        end
      end
    end
  end
end
