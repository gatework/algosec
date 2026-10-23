# frozen_string_literal: true

require_relative "../../policy"

module Algosec
  module Vendors
    module Netscreen
      # ScreenOS 生成地址、服务、策略和 NAT 命令。
      class Generator < Algosec::Policy::Generator
        command_policy placement: :prepend, permit: "permit", deny: "deny"
        command_operation :remove_rule, using: :remove_rule
        command_frame after: [ "save" ]
        command_fields sources: "src-address", destinations: "dst-address", services: "service"

        # 策略编号独立于执行顺序，删除精确编号并保留共享对象。
        def remove_rule(rule)
          emit("unset policy id #{numeric_identifier(rule.native_rule_id)}")
        end

        # 根据新规则结果生成该厂商的完整策略命令。
        def create_rule
          schedule = create_schedule
          split_policy_actions(result.actions.fetch(:new)).each do |action|
            members = prepare(action)
            require_members!(members)
            nat = Array(members[:nat_sources]) + Array(members[:nat_destinations])
            # 320000 起包含系统内置策略编号，不用于用户规则分配。
            id = available_id(:policy_id, rule_key(action), 1...320000, snapshot.rules.map(&:native_rule_id))
            command = "set policy id #{id} top from #{quoted(result.from_zone)} to #{quoted(result.to_zone)}"
            Algosec::Policy::Result::DIMENSIONS.each { |dimension| command += " #{quoted(members[dimension].first)}" }
            command += " nat #{nat.map { |value| value.delete_prefix("nat ") }.join(" ")}" unless nat.empty?
            command += " #{policy_action}"
            command += " schedule #{quoted(schedule)}" if schedule
            emit(command)
            additions = member_commands(members.transform_values { |values| values.is_a?(Array) ? values.drop(1) : values }, prefix: "set")
            emit("set policy id #{id}", *additions, "exit") unless additions.empty?
            record_created_rule(native_rule_id: id, members: action)
          end
        end

        # 把新增成员或 NAT 变更追加到已有策略，保留原规则范围。
        def modify_rule
          members = prepare(result.actions[:add])
          create_nat_only
          additions = member_commands(members, prefix: "set")
          additions.concat(Array(members[:nat_sources]).map { |value| "set #{value}" })
          additions.concat(Array(members[:nat_destinations]).map { |value| "set #{value}" })
          emit("set policy id #{identifier(result.rule.native_rule_id)}", *additions, "exit") unless additions.empty?
        end

        # 按厂商语法创建或复用地址对象，并返回命令引用。
        def create_address(value, dimension:)
          parts = address_parts(value)
          return "any" if parts[:prefix] == 0
          zone = (dimension == :sources) ? result.from_zone : result.to_zone
          if zone == "Global"
            mip = "MIP(#{parts[:text].delete_suffix("/32")})"
            found = snapshot.addresses.find { |address| address.zone == zone && address.name == mip && address.resolved_set == parts[:set] }
            return mip if found
          end
          unless parts[:prefix]
            members = cidrs(parts[:set]).map { |ip, mask| create_address("#{ip}/#{mask}", dimension: dimension) }
            return define_object(:address_group, [ zone, parts[:set] ], stable_name("range", parts[:set]), type: [ Algosec::Elements::AddressObject, Algosec::Elements::AddressGroup ], zone: zone) do |name|
              members.each { |member| emit("set group address #{quoted(zone)} #{quoted(name)} add #{quoted(member)}") }
            end
          end
          define_object(:address, [ zone, parts[:set] ], parts[:text], type: [ Algosec::Elements::AddressObject, Algosec::Elements::AddressGroup ], zone: zone) do |name|
            emit("set address #{quoted(zone)} #{quoted(name)} #{parts[:first]} #{IPAddr.netmask(parts[:prefix])}")
          end
        end

        # 按厂商语法创建或复用服务对象，并返回命令引用。
        def create_service(value)
          return "any" if %w[any 0].include?(value.downcase)
          parts = service_parts(value)
          preferred = parts[:text] + ((parts[:protocol] == "udp") ? "u" : "")
          define_object(:service, parts, preferred, type: [ Algosec::Elements::ServiceObject, Algosec::Elements::ServiceGroup ]) do |name|
            emit("set service #{quoted(name)} protocol #{parts[:protocol]} src-port #{ANY_PORTS} dst-port #{parts[:first]}-#{parts[:last]}")
          end
        end

        # 把一次性时间条件转换为厂商计划命令。
        def create_schedule
          schedule_name do |name, schedule|
            emit("set scheduler #{quoted(name)} once start #{schedule.start_at.strftime("%m/%d/%Y %H:%M")} stop #{schedule.end_at.strftime("%m/%d/%Y %H:%M")}")
          end
        end

        # 校验静态 NAT 范围后生成转换命令，并登记可复用对象。
        def create_static_nat(record, direction:)
          unsupported_port_nat!
          real, mapped = equal_nat_ranges!(record)
          unless real[:prefix] && mapped[:prefix]
            raise Algosec::Policy::Error.new("Netscreen MIP 需要对齐的等长网段", code: :unsupported_nat_range)
          end
          interface = identifier(record[:nat].fetch(:interface) { raise Algosec::Policy::Error, "MIP 缺少接口" })
          command = "set interface #{interface} mip #{mapped[:first]} host #{real[:first]} netmask #{IPAddr.netmask(real[:prefix])}"
          once(command) { emit(command) }
          "MIP(#{mapped[:text].delete_suffix("/32")})"
        end

        # 按方向和分配组生成动态 NAT 命令，保持请求分组边界。
        def create_dynamic_nat(groups, direction:)
          values = groups.map do |records|
            if direction == :nat_sources
              "nat src#{create_pool(records.first[:nat])}"
            else
              targets = records.map { |record| record[:real_ip] }.uniq
              raise Algosec::Policy::Error, "Netscreen 单策略目标 NAT 需要一个内网目标" unless targets.one?
              parts = address_parts(targets.first)
              raise Algosec::Policy::Error.new("Netscreen 目标 NAT 需要主机地址", code: :unsupported_nat_range) unless parts[:prefix] == 32
              command = "nat dst ip #{parts[:first]}"
              if result.services.values.any? { |service| service[:translated_port] }
                ports = port_mappings
                raise Algosec::Policy::Error.new("Netscreen 单策略只能转换到一个端口", code: :unsupported_port_nat) unless ports.map { |port| port[:after] }.uniq.one?
                command += " port #{ports.first[:after]}"
              end
              command
            end
          end.uniq
          raise Algosec::Policy::Error, "同一条 Netscreen 策略不能使用不同的 NAT 分配" if values.size > 1
          if result.type == :ignore || result.type == :modify
            raise Algosec::Policy::Error, "补充策略 NAT 必须关联已有策略" unless result.rule
            validate_policy_nat_scope!
            emit("set policy id #{identifier(result.rule.native_rule_id)}", *values.map { |value| "set #{value}" }, "exit") unless values.empty?
          end
          (result.type == :new) ? values : nil
        end

        protected

        def reusable_address_in_zone?(object, zone) = [ zone, "Global" ].include?(object.zone)

        def select_member(value, dimension, candidates)
          record = result.actions&.dig(:new, :nat_destinations, value)
          if dimension == :destinations && result.to_zone == "Global" && record&.dig(:nat, :type) == :static
            return create_static_nat(record, direction: :nat_destinations)
          end
          super
        end

        private

        def create_pool(nat)
          return "" unless nat[:address]
          interface_name = nat.fetch(:interface) { raise Algosec::Policy::Error, "DIP 地址池缺少接口" }
          interface = snapshot.interface(interface_name)
          set = IPAddr.parse(nat[:address])
          return "" if interface.host && set == IPAddr.parse(interface.host)
          pools = snapshot.elements(Algosec::Elements::NatPool)
          existing = pools.sort_by(&:name).find { |pool| pool.interface == interface_name && pool.set == set }
          return " dip-id #{identifier(existing.name)}" if existing
          id = available_id(:pool, [ interface_name, set ], 4..1022, pools.map(&:name))
          once([ :pool, id ]) do
            parts = address_parts(nat[:address])
            command = "set interface #{identifier(interface_name)}"
            unless interface.connected_set.cover?(set)
              raise Algosec::Policy::Error.new("接口外的 DIP 地址池需要对齐网段", code: :unsupported_nat_range) unless parts[:prefix]
              command += " ext ip #{parts[:first]} #{IPAddr.netmask(parts[:prefix])}"
            end
            emit("#{command} dip #{id} #{parts[:first]} #{parts[:last]}")
          end
          " dip-id #{id}"
        end
      end
    end
  end
end
