# frozen_string_literal: true

require_relative "../../policy"

module Algosec
  module Vendors
    module Asa
      # ASA 生成 ACL、对象和 NAT 命令。
      class Generator < Algosec::Policy::Generator
        OBJECT_NAME_TYPES = [ Algosec::Elements::AddressObject, Algosec::Elements::AddressGroup,
          Algosec::Elements::ServiceObject, Algosec::Elements::ServiceGroup ].freeze
        private_constant :OBJECT_NAME_TYPES

        command_policy placement: :append, permit: "permit", deny: "deny"
        command_frame before: [ "configure terminal" ], after: [ "end" ]
        # 根据新规则结果生成该厂商的完整策略命令。
        def create_rule
          create_nat_only
          acl = snapshot.zone(result.from_zone).acl_name
          raise Algosec::Policy::Error, "安全域 #{result.from_zone} 未绑定 ACL" unless acl
          schedule = create_schedule
          addresses = %i[sources destinations].map do |dimension|
            values = result.public_send(dimension).keys.sort
            members = (values.size > 3) ? [ "object-group #{identifier(create_address_group(Algosec::Policy::Ranges.addresses(values)))}" ] : values.map { |value| address_command(value) }
            remember_members(dimension, members)
          end
          addresses.first.product(addresses.last, result.services.keys.sort).each do |source, destination, service|
            protocol, port = service_command(service)
            remember_members(:services, [ [ protocol, port ].compact.join(" ") ])
            command = "access-list #{identifier(acl)} extended #{policy_action} #{protocol} #{source} #{destination}"
            command += " #{port}" if port
            command += " time-range #{identifier(schedule)}" if schedule
            once(command) { emit(command) }
          end
          number = snapshot.rules.select { |rule| rule.rule_set == acl }.map(&:rule_number).compact.max.to_i + 1
          number = registry.available_id(:candidate_acl_line, rule_key, number..(number + 65535), [])
          members = Algosec::Policy::Result::DIMENSIONS.to_h { |dimension| [ dimension, result.public_send(dimension).transform_values { nil } ] }
          record_created_rule(rule_set: acl, rule_number: number.to_i, members: members)
        end

        # ASA 的修改保留旧 ACL 行，另加精确请求范围，不修改被共享的网络对象。
        # 把新增成员或 NAT 变更追加到已有策略，保留原规则范围。
        def modify_rule
          create_rule
        end

        # 把一次性时间条件转换为厂商计划命令。
        def create_schedule
          schedule_name do |name, schedule|
            emit("time-range #{identifier(name)}", "absolute start #{schedule.start_at.strftime("%H:%M %-d %B %Y")} end #{schedule.end_at.strftime("%H:%M %-d %B %Y")}", "exit")
          end
        end

        # 校验静态 NAT 范围后生成转换命令，并登记可复用对象。
        def create_static_nat(record, direction:)
          equal_nat_ranges!(record)
          modern? ? modern_nat(record, direction: direction, static: true) : legacy_nat(record, direction: direction, static: true)
        end

        # 按方向和分配组生成动态 NAT 命令，保持请求分组边界。
        def create_dynamic_nat(groups, direction:)
          groups.flatten.each do |record|
            if modern?
              modern_nat(record, direction: direction, static: direction == :nat_destinations)
            else
              legacy_nat(record, direction: direction, static: false)
            end
          end
          nil
        end

        private

        def modern? = snapshot.behavior.modern?

        def service_command(value)
          protocol = IPAddr.protocol_number(value.split("/", 2).first)
          return [ "ip", nil ] if protocol.zero?
          return [ protocol.to_s, nil ] unless [ IPAddr::TCP, IPAddr::UDP ].include?(protocol)
          parts = service_parts(value)
          [ parts[:protocol], (parts[:first] == parts[:last]) ? "eq #{parts[:first]}" : "range #{parts[:first]} #{parts[:last]}" ]
        end

        def address_command(value)
          parts = address_parts(value)
          case parts[:prefix]
          when 0 then "any"
          when 32 then "host #{parts[:first]}"
          when nil
            modern? ? "object #{identifier(network_object(value))}" : "object-group #{identifier(create_address_group(parts[:set]))}"
          else
            "#{parts[:first]} #{IPAddr.netmask(parts[:prefix])}"
          end
        end

        def create_address_group(set)
          define_object(:address_group, set, stable_name("addrgroup", set), type: OBJECT_NAME_TYPES) do |name|
            command_block("object-group network #{identifier(name)}", close: "exit") do
              cidrs(set).each do |ip, mask|
                emit((mask == 32) ? "network-object host #{ip}" : "network-object #{ip} #{IPAddr.netmask(mask)}")
              end
            end
          end
        end

        def network_object(value, nat_key: nil, command: nil)
          parts = address_parts(value)
          key = [ parts[:set], nat_key ]
          preferred = parts[:prefix] ? "obj-#{parts[:text].delete_suffix("/32")}" : "range_#{parts[:text]}"
          define_object(:address, key, preferred, type: OBJECT_NAME_TYPES) do |name|
            emit("object network #{identifier(name)}")
            emit(case parts[:prefix]
            when 32 then "host #{parts[:first]}"
            when nil then "range #{parts[:first]} #{parts[:last]}"
            else "subnet #{parts[:first]} #{IPAddr.netmask(parts[:prefix])}"
            end)
            emit(command) if command
            emit("exit")
          end
        end

        def modern_nat(record, direction:, static:)
          mapped = record[:nat][:address]
          equal_nat_ranges!(record) if static
          zones = (direction == :nat_sources) ? [ result.from_zone, result.to_zone ] : [ result.to_zone, result.from_zone ]
          ports = (direction == :nat_destinations && result.services.values.any? { |service| service[:translated_port] }) ? port_mappings : [ nil ]
          ports.each do |port|
            target = if mapped
                       parts = address_parts(mapped)
                       (static && parts[:prefix] == 32) ? parts[:first] : identifier(network_object(mapped))
            else
                       "interface"
            end
            command = "nat (#{zones.map { |zone| identifier(zone) }.join(",")}) #{static ? "static" : "dynamic"} #{target}"
            command += " service #{port[:protocol]} #{port[:after]} #{port[:before]}" if port
            network_object(record[:real_ip], nat_key: command, command: command)
          end
        end

        # 旧版 NAT 的 ACL 与池编号按本次配置快照分配，复用池须同时匹配区域和完整范围。
        def legacy_nat(record, direction:, static:)
          unsupported_port_nat!
          mapped = record[:nat][:address]
          zones = (direction == :nat_sources) ? [ result.from_zone, result.to_zone ] : [ result.to_zone, result.from_zone ]
          peers = (direction == :nat_sources) ? result.destinations.keys : result.sources.keys
          key = [ direction, record[:real_ip], mapped, peers.sort ]
          acl = available_id(:acl, key, 100..9999, snapshot.rules.map(&:rule_set) + snapshot.static_nats.map(&:acl_name) + snapshot.dynamic_nats.map(&:acl_name))
          once([ :nat_acl, acl ]) do
            source = address_command(record[:real_ip])
            peers.sort.each { |peer| emit("access-list #{acl} extended permit ip #{source} #{address_command(peer)}") }
          end
          if static || direction == :nat_destinations
            real, public_ip = equal_nat_ranges!(record)
            raise Algosec::Policy::Error.new("ASA 旧版静态 NAT 需要对齐的等长网段", code: :unsupported_nat_range) unless real[:prefix] && public_ip[:prefix]
            command = "static (#{zones.map { |zone| identifier(zone) }.join(",")}) #{public_ip[:first]} access-list #{acl}"
            command += " netmask #{IPAddr.netmask(public_ip[:prefix])}" unless public_ip[:prefix] == 32
          else
            pool = legacy_pool(zones.last, mapped)
            command = "nat (#{identifier(zones.first)}) #{pool} access-list #{acl}"
          end
          once(command) { emit(command) }
        end

        def legacy_pool(zone, value)
          set = value && IPAddr.parse(value)
          existing = snapshot.elements(Algosec::Elements::NatPool).sort_by(&:name).find { |pool| pool.zone == zone && pool.set == set }
          return existing.name if existing
          name = available_id(:pool, [ zone, set ], 100..9999, snapshot.elements(Algosec::Elements::NatPool).map(&:name))
          once([ :pool, name, zone ]) do
            target = if value
                       parts = address_parts(value)
                       (parts[:prefix] == 32) ? parts[:first] : "#{parts[:first]}-#{parts[:last]}"
            else
                       "interface"
            end
            emit("global (#{identifier(zone)}) #{name} #{target}")
          end
          name
        end
      end
    end
  end
end
