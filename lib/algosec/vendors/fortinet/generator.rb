# frozen_string_literal: true

require_relative "../../policy"

module Algosec
  module Vendors
    module Fortinet
      # FortiOS 生成策略、地址、服务、VIP 和 NAT 命令。
      class Generator < Algosec::Policy::Generator
        ADDRESS_NAME_TYPES = [ Algosec::Elements::AddressObject, Algosec::Elements::AddressGroup,
          Algosec::Elements::StaticNat, Algosec::Elements::DynamicNat ].freeze
        private_constant :ADDRESS_NAME_TYPES

        command_policy placement: :append, permit: "accept", deny: "deny"
        command_operation :remove_rule, using: :remove_rule
        command_frame before: :vdom_commands, after: :vdom_end_commands
        command_fields sources: "srcaddr", destinations: "dstaddr", services: "service"

        # 外壳复用当前 VDOM，只删除明确编号的策略。
        def remove_rule(rule)
          emit("config firewall policy", "delete #{numeric_identifier(rule.native_rule_id)}", "end")
        end

        # 根据新规则结果生成该厂商的完整策略命令。
        def create_rule
          split_policy_actions(result.actions.fetch(:new)).each { |action| write_rule(action) }
        end

        def write_rule(action)
          if result.services.values.any? { |record| record[:translated_port] } && action.fetch(:destinations).keys.all? { |value| action.dig(:nat_destinations, value) || result.destinations[value]&.dig(:nat, :rule) }
            # 端口与协议由每个 port-forward VIP 约束，策略引用全部 VIP 允许其转换后的服务。
            action = action.merge(services: { "any" => [ "ALL" ] })
          end
          members = prepare(action)
          require_members!(members)
          schedule = create_schedule
          emit("config firewall policy", "edit 0", "set srcintf #{quoted(result.from_zone)}", "set dstintf #{quoted(result.to_zone)}")
          emit("set srcaddr #{members[:sources].map { |name| quoted(name) }.join(" ")}",
               "set dstaddr #{members[:destinations].map { |name| quoted(name) }.join(" ")}", "set action #{policy_action}",
               "set schedule #{quoted(schedule)}", "set service #{members[:services].map { |name| quoted(name) }.join(" ")}",
               *Array(members[:nat_sources]), "next", "end")
          vdom = snapshot.settings[:vdom] || "root"
          record_created_rule(members: action, rule_set: vdom, scope: Algosec::Elements::Scope.new(device_id: snapshot.device_id, virtual_system: vdom))
        end

        # 把新增成员或 NAT 变更追加到已有策略，保留原规则范围。
        def modify_rule
          members = prepare(result.actions[:add])
          nat_commands = Array(members[:nat_sources])
          new_actions = result.actions.fetch(:new, {})
          %i[nat_sources nat_destinations].each do |direction|
            next unless new_actions[direction]
            generated = create_nat(new_actions[direction], direction)
            nat_commands.concat(Array(generated)) if direction == :nat_sources
          end
          additions = command_fields.filter_map do |dimension, field|
            next if members.fetch(dimension).empty?
            existing = result.rule.config&.match(/^\s*(set\s+#{field}\s+[^\r\n]+)\s*$/i)&.captures&.first
            raise Algosec::Policy::Error, "无法读取策略原有 #{field} 成员" unless existing
            "#{existing.strip} #{members[dimension].map { |name| quoted(name) }.join(" ")}"
          end
          emit("config firewall policy", "edit #{identifier(result.rule.native_rule_id)}", *additions, *nat_commands, "next", "end") unless additions.empty? && nat_commands.empty?
        end

        # 按厂商语法创建或复用地址对象，并返回命令引用。
        def create_address(value, dimension:)
          record = result.actions&.dig(:new, :nat_destinations, value) if dimension == :destinations
          return create_static_nat(record, direction: :nat_destinations) if record
          parts = address_parts(value)
          return "ALL" if parts[:prefix] == 0
          name = parts[:prefix] ? parts[:text] : "range_#{parts[:text]}"
          define_object(:address, parts[:set], name, type: ADDRESS_NAME_TYPES) do |selected|
            emit("config firewall address", "edit #{quoted(selected)}")
            if parts[:prefix]
              emit("set subnet #{parts[:first]} #{IPAddr.from_i(IPAddr::IPV4_MAX ^ ((1 << (32 - parts[:prefix])) - 1))}")
            else
              emit("set type iprange", "set start-ip #{parts[:first]}", "set end-ip #{parts[:last]}")
            end
            emit("next", "end")
          end
        end

        # 按厂商语法创建或复用服务对象，并返回命令引用。
        def create_service(value)
          return "ALL" if %w[any 0].include?(value.downcase)
          parts = service_parts(value)
          name = parts[:text] + ((parts[:protocol] == "udp") ? "u" : "")
          define_object(:service, parts, name, type: [ Algosec::Elements::ServiceObject, Algosec::Elements::ServiceGroup ]) do |selected|
            emit("config firewall service custom", "edit #{quoted(selected)}", "set protocol TCP/UDP/SCTP",
                 "set #{parts[:protocol]}-portrange #{parts[:text]}", "next", "end")
          end
        end

        # 把一次性时间条件转换为厂商计划命令。
        def create_schedule
          schedule_name do |name, schedule|
            emit("config firewall schedule onetime", "edit #{quoted(name)}",
                 "set start #{schedule.start_at.strftime("%H:%M %Y/%m/%d")}", "set end #{schedule.end_at.strftime("%H:%M %Y/%m/%d")}", "next", "end")
          end || "always"
        end

        # 校验静态 NAT 范围后生成转换命令，并登记可复用对象。
        def create_static_nat(record, direction:)
          existing = record.dig(:nat, :rule)
          reusable = existing.is_a?(Algosec::Elements::StaticNat) && existing.name
          reusable &&= direction != :nat_sources || existing.source_nat_enabled == true
          return existing.name if reusable
          if direction == :nat_destinations && result.services.values.any? { |service| service[:translated_port] }
            return port_mappings.map { |port| create_vip(record, direction: direction, port: port) }
          end
          create_vip(record, direction: direction)
        end

        def create_vip(record, direction:, port: nil)
          real, mapped = equal_nat_ranges!(record)
          interface = record[:nat].fetch(:interface) { raise Algosec::Policy::Error, "静态 NAT 缺少外部接口" }
          external = (mapped[:set].cardinality == 1) ? mapped[:first] : "#{mapped[:first]}-#{mapped[:last]}"
          internal = (real[:set].cardinality == 1) ? real[:first] : "#{real[:first]}-#{real[:last]}"
          name = "vip#{external}_#{interface}"
          name += "_#{port[:protocol]}_#{port[:before]}" if port
          binding = VipBinding.new(external: mapped[:set], internal: real[:set], interface: interface,
            protocol: port&.fetch(:protocol), external_port: port&.fetch(:before), internal_port: port&.fetch(:after))
          registry.register_batch(:vip_bindings, [ binding ]) do |previous|
            if previous.any? { |prior| binding.conflicts?(prior) }
              raise Algosec::Policy::Error.new("重叠的 VIP 匹配范围对应不同的私网地址或端口", code: :nat_scope_conflict)
            end
          end
          define_object(:vip, [ binding, direction ], name, type: ADDRESS_NAME_TYPES) do |selected|
            emit("config firewall vip", "edit #{quoted(selected)}", "set extip #{external}", "set extintf #{quoted(interface)}",
                 "set mappedip #{quoted(internal)}")
            emit("set nat-source-vip enable") if direction == :nat_sources
            if port
              emit("set portforward enable", "set protocol #{port[:protocol]}", "set extport #{port[:before]}", "set mappedport #{port[:after]}")
            end
            emit("next", "end")
          end
        end

        def create_nat(records, direction)
          if direction == :nat_destinations && result.type != :new && !records.empty?
            raise Algosec::Policy::Error.new("新增 Fortinet 目标 NAT 需要引用 VIP 的完整新策略", code: :nat_scope_conflict)
          end
          generated = super
          return generated unless direction == :nat_sources && records.values.any? { |record| record[:nat][:type] == :static }
          raise Algosec::Policy::Error, "同一条 Fortinet 策略不能混合静态和动态源 NAT" if records.values.any? { |record| record[:nat][:type] == :dynamic }
          additions = [ "set nat enable" ]
          validate_policy_nat_scope! unless result.type == :new
          write_existing_nat(additions) if result.type == :ignore
          additions
        end

        # 按方向和分配组生成动态 NAT 命令，保持请求分组边界。
        def create_dynamic_nat(groups, direction:)
          if direction == :nat_destinations
            groups.flatten.each { |record| create_static_nat(record, direction: direction) }
            return
          end
          addresses = groups.map { |records| records.first[:nat][:address] }.uniq
          raise Algosec::Policy::Error, "同一条 Fortinet 策略不能使用不同的源 NAT 分配" unless addresses.size == 1
          additions = [ "set nat enable" ]
          if addresses.first
            pool = create_pool(addresses.first)
            additions.concat([ "set ippool enable", "set poolname #{quoted(pool)}" ])
          end
          validate_policy_nat_scope! unless result.type == :new
          write_existing_nat(additions) if result.type == :ignore
          additions
        end

        protected

        def split_nat_record?(record) = true

        def select_member(value, dimension, candidates)
          record = result.actions&.dig(:new, :nat_destinations, value) if dimension == :destinations
          return create_static_nat(record, direction: :nat_destinations) if record
          existing = result.destinations[value]&.dig(:nat, :rule) if dimension == :destinations
          return existing.name if existing&.name
          super
        end

        private

        # VDOM 选择只改变命令外壳，不改变对象生成顺序。
        def vdom_commands
          snapshot.settings[:vdom] ? [ "config vdom", "edit #{quoted(snapshot.settings[:vdom])}" ] : []
        end

        def vdom_end_commands = snapshot.settings[:vdom] ? [ "end" ] : []

        def write_existing_nat(additions)
          validate_policy_nat_scope!
          emit("config firewall policy", "edit #{identifier(result.rule.native_rule_id)}", *additions, "next", "end")
        end

        def create_pool(value)
          parts = address_parts(value)
          existing = snapshot.elements(Algosec::Elements::NatPool).sort_by(&:name).find do |pool|
            pool.set == parts[:set] && pool.mode == "overload" && pool.interface.nil? && pool.arp_reply == true
          end
          return existing.name if existing
          define_object(:pool, parts[:set], "Pool-#{parts[:text]}", type: Algosec::Elements::NatPool) do |name|
            emit("config firewall ippool", "edit #{quoted(name)}", "set type overload",
                 "set arp-reply enable", "set endip #{parts[:last]}", "set startip #{parts[:first]}", "next", "end")
          end
        end
      end
    end
  end
end

require_relative "generator/vip_binding"
