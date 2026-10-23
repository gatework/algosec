# frozen_string_literal: true

require "active_support/core_ext/object/deep_dup"
require_relative "../../config/parser"

module Algosec
  module Vendors
    module Asa
      # 解析 ASA 接口、对象、ACL、路由和 NAT，并按阶段装配引用。
      class Parser < Algosec::Config::Parser
        VENDOR = :asa

        stage :scan_document, using: :scan_document
        stage :finish_network, using: :finish_network
        stage :emit_objects, using: :emit_objects
        stage :object_references, using: :resolve_references
        stage :parse_rules, using: :parse_rules
        stage :emit_rules, using: :emit_rules
        stage :rule_references, using: :resolve_references
        stage :parse_nat, using: :parse_nat
        HEADERS = /\A(?:interface |object(?:-group)? |time-range |access-list |access-group |route |global |static )/

        private

        def any_address?(name, dimension: nil) = /\Aany\z/i.match?(name)

        def any_nat_address?(name) = /\Aany\z/i.match?(name)

        # 收集块式配置，将需要网络或对象引用的命令留给后续阶段。
        def scan_document
          index, @rules, @nats, @pools = 0, [], [], []
          @acl_zones = {}
          @rule_numbers = Hash.new(0)
          while index < @lines.size
            line = @lines[index]
            words = tokens(line)
            if %w[interface object object-group time-range].include?(words[0])
              rows, index = block_at(index, terminator: /\A!/, stop: HEADERS, include_end: words[0] == "interface")
              object_block(words, rows, @nats)
              next
            elsif words[0] == "access-group" && words[2, 2] == %w[in interface]
              @acl_zones[words[1]] = words[4]
              draft(:zone, words[4], name: words[4], acl_name: words[1])
              consume(line)
            elsif words[0] == "route"
              capture(draft(:route, line.index, zone: words[1], subnet: IPAddr.network_cidr(words[2], words[3]), next_hop: words[4]), line)
            elsif words[0] == "access-list" && (words[2] == "extended" || (words[2] == "line" && words[4] == "extended"))
              @rules << line
            elsif words[0] == "global"
              @pools << line
            elsif %w[nat static].include?(words[0])
              @nats << [ nil, line ]
            elsif words[0]&.start_with?("!")
              consume(line)
            end
            index += 1
          end
        end

        # 对象引用就绪后按源行顺序解析 ACL。
        def parse_rules
          @rules.each { |line| access_list(line) }
        end

        # 引用和规则就绪后生成 NAT，保留原文以及厂商执行顺序。
        def parse_nat
          @pools.each { |line| pool(line) }
          @nat_object_order = @nats.filter_map { |object, _line| object&.attributes&.fetch(:name) }.uniq.sort.each_with_index.to_h
          @nats.each { |object, line| nat(object, line) }
        end

        def object_block(words, rows, nats)
          if words[0] == "interface"
            object = draft(:interface, words[1], name: words[1])
            object.lines.concat(rows)
            rows.drop(1).each do |line|
              fields = tokens(line)
              if fields[0] == "nameif"
                bind_zone(words[1], fields[1], line)
                @drafts[:zone][fields[1]].lines.concat(rows)
              elsif fields[0, 2] == %w[ip address]
                ip, mask = ip_parts(fields[2], fields[3])
                object.attributes.merge!(ipaddr: IPAddr.host_cidr(ip, mask), mode: :layer3)
                route = connected_route(object, ip, mask, line)
                route.lines.replace(rows)
              elsif fields[0] != "security-level" && fields[0] != "!"
                next
              end
              consume(line)
            end
            return
          end
          type = (words[0] == "time-range") ? :schedule : { "network" => :address_group, "service" => :service_group, "protocol" => :service_group }[words[1]]
          return unless type
          name = (type == :schedule) ? words[1] : words[2]
          attributes = (type == :schedule) ? schedule_attributes(name: name) : { name: name }
          attributes[:protocol] = words[3] if words[1] == "service"
          object = draft(type, name, **attributes)
          object.lines << rows.first
          rows.drop(1).each do |line|
            fields = tokens(line)
            if type == :address_group && fields[0] == "nat"
              nats << [ object, line ]
              next
            end
            recognized = case type
            when :address_group
                           rest = fields.dup
                           rest.shift if rest[0] == "network-object"
                           if %w[group-object object].include?(rest[0])
                             (object.attributes[:members] ||= {})[rest[1]] = nil
                             true
                           elsif rest[0] == "host"
                             add_inline_address(object, rest[1], rest[1], 32)
                           elsif rest[0] == "range"
                             expression = rest[1, 2].join("-")
                             (object.attributes[:members] ||= {})[expression] = literal_reference(expression, line).last
                           elsif rest[0] == "subnet" || rest[0]&.match?(/\A\d+\./)
                             rest.shift if rest[0] == "subnet"
                             add_inline_address(object, rest.join(" "), rest[0], rest[1])
                           end
            when :service_group
                           if fields[0] == "group-object"
                             (object.attributes[:members] ||= {})[fields[1]] = nil
                             true
                           elsif fields[0] == "protocol-object"
                             key, service = literal_service(fields[1])
                             (object.attributes[:members] ||= {})[key] = service
                           elsif fields[0, 2] == %w[service-object object]
                             (object.attributes[:members] ||= {})[fields[2]] = nil
                             true
                           elsif %w[port-object service-object service].include?(fields[0])
                             rest = fields.drop(1)
                             protocols = ((fields[0] == "port-object") ? words[3] : rest.shift).to_s.split("-")
                             source = nil
                             if rest[0] == "source"
                               rest.shift
                               source = take_port_condition(rest)
                             end
                             rest.shift if rest[0] == "destination"
                             port = take_port_condition(rest) || ANY_SERVICE_PORTS
                             if rest.empty? && protocols.any?
                               protocols.each do |protocol|
                                 key, service = literal_service(protocol, port, source_port: source)
                                 (object.attributes[:members] ||= {})[key] = service
                               end
                             end
                           end
            when :schedule
                           schedule_command(object, fields, line)
            end
            if fields[0] == "description"
              object.attributes[:description] = fields.drop(1).join(" ")
              recognized = true
            end
            capture(object, line) if recognized
          end
        end

        # 多个周期相加；绝对窗口与周期的交集尚未建模，不能只保留其中一个限制。
        def schedule_command(object, fields, line)
          return if fields.first == "description"
          attributes = object.attributes.deep_dup
          if fields[0] == "absolute" &&
             ((fields.size == 11 && fields[1] == "start" && fields[6] == "end") || (fields.size == 6 && fields[1] == "end"))
            raise ArgumentError, "Combined absolute and periodic ranges are not modeled" if attributes[:kind] == :weekly
            attributes[:kind] = :once
            attributes[:start_at] = fields[2, 4].join(" ") if fields[1] == "start"
            attributes[:end_at] = fields[fields.index("end") + 1, 4].join(" ")
          elsif fields[0] == "periodic" && (index = fields.index("to")) && index >= 3 && fields.size == index + 2
            raise ArgumentError, "Combined absolute and periodic ranges are not modeled" if attributes[:end_at]
            attributes[:kind] = :weekly
            periods = (attributes[:periods] ||= {})
            clocks = fields.values_at(index - 1, index + 1)
            fields[1...(index - 1)].each { |day| periods[day] = (periods.fetch(day, []) + [ clocks ]).uniq }
          else
            raise ArgumentError, "Unsupported time-range statement"
          end
          parsed = Algosec::Elements::Schedule.new(**context, **attributes)
          if (parsed.start_at && parsed.end_at && parsed.end_at < parsed.start_at) ||
             parsed.weekly_windows.values.flatten.any? { |period| period.begin > period.end }
            raise ArgumentError, "Schedule end precedes start"
          end
          object.attributes.replace(attributes)
          true
        rescue ArgumentError => error
          object.attributes[:unparsed_commands] = (object.lines + [ line ]).map { |source| source.text.strip }.uniq
          diagnose(:unsupported_schedule, "Schedule #{object.attributes[:name]}: #{error.message}", line)
          true
        end

        def add_inline_address(object, name, ip, mask)
          (object.attributes[:members] ||= {})[name] = Algosec::Elements::AddressObject.new(**context, name: name, member: [ address_leaf(ip, mask) ])
        end

        def port_number(value)
          return super if value&.match?(/\A\d+\z/)
          object = builtin(value&.downcase)
          return Integer(object.destination_port, 10) if object&.destination_port
          raise Algosec::Config::ParseError, "Unknown built-in port #{value.inspect}"
        end

        def acl_address(words, line)
          case words[0]
          when "object", "object-group" then words.shift(2).last
          when "any" then address_reference(words.shift)
          when "host"
            words.shift
            literal_reference(words.shift, line)
          else
            ip, mask = words.shift(2)
            literal_reference(ip_parts(ip, mask).join("/"), line)
          end
        end

        def access_list(line)
          words = tokens(line)
          # 有 line 序号时保留设备值，其余按各 ACL 的出现顺序编号。
          explicit_number = Integer(words.slice!(2, 2).last, 10) if words[2] == "line"
          name, action = words.values_at(1, 3)
          rest = words.drop(4)
          protocol_object = %w[object object-group].include?(rest[0])
          protocol = protocol_object ? rest.shift(2).last : rest.shift
          source = acl_address(rest, line)
          source_port = take_port_condition(rest)
          destination = acl_address(rest, line)
          number = @rule_numbers[name] = explicit_number || @rule_numbers[name] + 1
          object = draft(:rule, [ name, number ], rule_set: name, rule_number: number, native_rule_type: :acl,
                         action: action, from_zones: @acl_zones[name] && [ @acl_zones[name] ], status: rest.include?("inactive") ? "disable" : "enable")
          capture(object, line)
          object.state[:sources], object.state[:destinations] = [ source ], [ destination ]
          base = protocol_object ? [ protocol, service(protocol) ] : literal_service(protocol)
          filter = if %w[object object-group].include?(rest[0])
                     referenced = rest.shift(2).last
                     [ referenced, service(referenced) ]
          end
          destination_port = take_port_condition(rest) unless filter
          rule_options(object, rest, line)
          if base.last.nil? || (filter && filter.last.nil?)
            missing = base.last.nil? ? base.first : filter.first
            object.state[:services] = [ missing ]
          elsif !filter && !source_port && !destination_port
            object.state[:services] = [ base ]
          else
            filtered = filter_services(base.last, filter&.last, source_port, destination_port: destination_port)
            object.state[:services] = [ [ filtered.name, filtered ] ]
          end
        rescue Algosec::Elements::Group::UnresolvedReference
          # 保留原引用图；不把不完整协议组的已知成员当成完整过滤结果。
          object.state[:services] = [ base, filter ].compact
          unsupported_rule_condition(object, line)
        end

        # ASA 的端口操作符消费自己的参数；gt/lt 是严格边界。
        def take_port_condition(words)
          return unless %w[eq range gt lt].include?(words[0])
          operator = words.shift
          port_condition([ operator, *words.shift(operator == "range" ? 2 : 1) ])
        end

        # 协议、源端口和目的端口按交集组合，不能把两个服务组当成并集。
        def filter_services(base, filter, source_port, destination_port: nil)
          definitions = ->(object) { object.is_a?(Algosec::Elements::ServiceGroup) ? object.unique_leaves.flat_map(&:terms) : object.terms }
          filter ||= literal_service("any").last
          result = Algosec::Elements::ServiceObject.new(**context, name: "#{base.name}:filtered")
          definitions.call(base).product(definitions.call(filter)).each do |left, right|
            lproto, rproto = [ left, right ].map { |item| IPAddr.protocol_number(item[:protocol]) }
            next unless lproto.zero? || rproto.zero? || lproto == rproto
            protocol = lproto.zero? ? right[:protocol] : left[:protocol]
            sources = IPAddr.ports(left[:source_port] || ANY_SERVICE_PORTS) &
                      IPAddr.ports(right[:source_port] || ANY_SERVICE_PORTS) & IPAddr.ports(source_port || ANY_SERVICE_PORTS)
            destinations = IPAddr.ports(left[:destination_port]) & IPAddr.ports(right[:destination_port]) &
                           IPAddr.ports(destination_port || ANY_SERVICE_PORTS)
            sources.to_a.product(destinations.to_a).each do |src, dst|
              result.add(**left.merge(protocol: protocol, source_port: "#{src.begin}-#{src.end}",
                                      destination_port: "#{dst.begin}-#{dst.end}"))
            end
          end
          result
        end

        # 只消费已建模选项；其他 ACL 限制继续作为未知条件保留。
        def rule_options(object, words, line)
          until words.empty?
            option = words.shift
            case option
            when "inactive" then object.attributes[:status] = "disable"
            when "time-range" then object.attributes[:schedule_name] = words.shift
            when "log", "log-input"
              options = [ option ]
              if words.first&.match?(/\A(?:[0-7]|emergencies|alerts|critical|errors|warnings|notifications|informational|debugging|disable|default)\z/)
                options << words.shift
              end
              if words.first == "interval"
                unless words[1]&.match?(/\A[1-9]\d*\z/)
                  unsupported_rule_condition(object, line)
                  break
                end
                options.concat(words.shift(2))
              end
              object.attributes[:log] = options.join(" ")
              object.attributes[:log_enabled] = !options.include?("disable")
            else
              unsupported_rule_condition(object, line)
              break
            end
          end
        end

        # 部分配置可供查看，但含未知限制的规则不能用于确定性覆盖。
        def unsupported_rule_condition(object, line)
          (object.attributes[:conditions] ||= {})[:unparsed_commands] = [ line.text.strip ]
          diagnose(:unsupported_rule_condition, "ACL contains unresolved service or match conditions", line)
        end

        def zone_ip(name, line)
          interface = find(:zone, name)&.interfaces&.values&.find(&:host)
          return interface.host if interface
          diagnose(:missing_interface, "Zone #{name} has no interface address", line)
        end

        def pool(line)
          words = tokens(line)
          zone = words[1]&.delete("()")
          name = words[2]
          unless zone.present? && name.present? && words[3].present?
            consume(line)
            return diagnose(:invalid_nat_pool, "ASA global requires a zone, pool ID, and address target", line)
          end

          expression = case words[3]
          when "interface"
            unless words.size == 4
              consume(line)
              return diagnose(:invalid_nat_pool, "ASA global interface target has unexpected fields", line)
            end
            zone_ip(zone, line)
          else
            if words[4] == "netmask"
              unless words.size == 6 && words[5].present?
                consume(line)
                return diagnose(:invalid_nat_pool, "ASA global netmask target requires one address and mask", line)
              end
              ip_parts(words[3], words[5]).join("/")
            else
              unless words.size == 4
                consume(line)
                return diagnose(:invalid_nat_pool, "ASA global address target has unexpected fields", line)
              end
              words[3]
            end
          end
          consume(line)
          return unless expression

          IPAddr.parse(expression)
          emit(:nat_pool, { name: name, zone: zone, ip: expression }, [ line ])
        rescue Algosec::Config::ParseError, IPAddr::Error, ArgumentError => error
          consume(line)
          diagnose(:invalid_nat_pool, "Invalid ASA global pool: #{error.message}", line)
        end

        # 粗粒度地址索引；命中时仍须核验 ACL 的地址配对、服务和其他条件。
        def acl_ranges(name, line)
          rules = @catalog.select { |element| element.is_a?(Algosec::Elements::SecurityRule) && element.rule_set == name }
          diagnose(:missing_reference, "ACL #{name}", line) if rules.empty?
          [ Set.new(*rules.flat_map { |rule| rule.sources.set.ranges }), Set.new(*rules.flat_map { |rule| rule.destinations.set.ranges }) ]
        end

        def nat(object, line)
          words = tokens(line)
          zone_pair = words[1]
          unless zone_pair&.match?(/\A\([^()]+\)\z/)
            consume(line)
            return diagnose(:invalid_nat, "ASA NAT requires a parenthesized interface or zone pair", line)
          end
          from, to = zone_pair.delete("()").split(",", 2)
          unless from.present? && (words[0] != "static" || to.present?)
            consume(line)
            return diagnose(:invalid_nat, "ASA static NAT requires both real and mapped zones", line)
          end
          if words[0] == "static"
            attributes = { real_zone: from, mapped_zone: to, mapped_ip: words[2] }
            if words[3] == "access-list"
              attributes[:acl_name] = words[4]
              attributes[:real_set], attributes[:destination_set] = acl_ranges(words[4], line)
              attributes[:mapped_set] = IPAddr.parse(words[2])
            elsif words[4] == "netmask"
              attributes.merge!(real_ip: words[3], real_set: IPAddr.subnet(words[3], words[5]), mapped_set: IPAddr.subnet(words[2], words[5]))
            else
              return
            end
            emit(:static_nat, attributes, [ line ])
          elsif !to && words[2] != "0" && words[3] == "access-list"
            pool = find(:nat_pool, words[2])
            consume(line)
            return diagnose(:missing_reference, "NAT pool #{words[2]}", line) unless pool
            source_set, destination_set = acl_ranges(words[4], line)
            emit(:dynamic_nat, { name: words[2], acl_name: words[4], from_zone: from, to_zone: pool.zone,
                                 source_set: source_set, destination_set: destination_set, source_pool: pool, translated_source_set: pool.set }, [ line ])
          elsif to
            rest = words.drop(2)
            section = object ? 2 : (rest[0] == "after-auto" ? 3 : 1)
            rest.shift if section == 3
            sequence = rest[0]&.match?(/\A[0-9]+\z/) ? Integer(rest.shift, 10) : line.number
            if object
              source_name = object.attributes[:name]
              mode = rest.shift
            elsif rest.shift == "source"
              mode, source_name = rest.shift(2)
            else
              return
            end
            return unless %w[static dynamic].include?(mode)
            rest.shift if rest[0] == "pat-pool"
            target_name = rest.shift
            target_name = zone_ip(to, line) if target_name == "interface"
            return unless target_name
            real_set, mapped_set = [ source_name, target_name ].map { |value| lookup_address_set(value, line) }
            return unless real_set && mapped_set
            lines = object ? object.lines + [ line ] : [ line ]
            if mode == "static" && rest.take_while { |word| word != "description" }.include?("unidirectional")
              diagnose(:unsupported_nat_condition, "Unidirectional static NAT requires directional matching", line)
            end
            disabled = !!rest.delete("inactive")
            # Section 2 在静态/动态分组内依次比较地址数量、起始地址和对象名称。
            order = if object
                      [ section, mode == "static" ? 0 : 1, real_set.cardinality, real_set.min || 0, @nat_object_order.fetch(source_name) ]
            else
                      [ section, sequence ]
            end
            metadata = { id: "nat:#{line.number}", nat_order: order }
            if mode == "static" && !rest.include?("service") && !rest.include?("destination")
              emit(:static_nat, { **metadata, disabled: disabled, real_zone: from, mapped_zone: to, real_ip: source_name, mapped_ip: target_name,
                                  real_set: real_set, mapped_set: mapped_set }, lines)
            elsif mode == "dynamic"
              attributes = { **metadata, extra_conf: { "disabled" => disabled }, name: object ? source_name : target_name, acl_name: "", direction: :source, from_zone: from, to_zone: to,
                             source_set: real_set, translated_source_set: mapped_set, destination_set: all_addresses }
              attributes[:destination_set] = lookup_address_set(rest[rest.index("destination") + 3], line) if rest.include?("destination")
              emit(:dynamic_nat, attributes, lines)
            elsif object && rest[0] == "service"
              protocol, real_port, mapped_port = rest[1, 3]
              emit(:dynamic_nat, { **metadata, extra_conf: { "disabled" => disabled }, name: source_name, acl_name: "", direction: :destination, from_zone: to, to_zone: from,
                                   source_set: all_addresses, destination_set: mapped_set, translated_destination_set: real_set,
                                   protocol: protocol, service_set: IPAddr.service("#{protocol}/#{mapped_port}"),
                                   translated_service_set: IPAddr.service("#{protocol}/#{real_port}"), destination_port: mapped_port,
                                   translated_destination_port: real_port }, lines)
            else
              modern_destination_nat(rest, source_name, target_name, from, to, real_set, mapped_set, lines, metadata.merge(extra_conf: { "disabled" => disabled }))
            end
          else
            return
          end
          consume(line)
        rescue Algosec::Config::ParseError, IPAddr::Error, ArgumentError => error
          consume(line)
          diagnose(:invalid_nat, "Invalid ASA NAT declaration: #{error.message}", line)
        end

        def modern_destination_nat(rest, source, target, from, to, real_set, mapped_set, lines, metadata)
          attributes = { **metadata, acl_name: "", direction: :destination, source_set: all_addresses }
          if rest[0, 2] == %w[destination static]
            public_name, private_name = rest[2, 2]
            attributes.merge!(name: public_name, from_zone: from, to_zone: to,
                              source_set: real_set, destination_set: lookup_address_set(public_name, lines.first),
                              translated_destination_set: lookup_address_set(private_name, lines.first))
          else
            attributes.merge!(name: target, from_zone: to, to_zone: from, destination_set: mapped_set, translated_destination_set: real_set)
          end
          if (index = rest.index("service"))
            service_name = rest[index + 1]
            attributes[:service_set] = lookup_service_set(service_name, lines.first)
            attributes[:service] = service(service_name)
            attributes[:translated_service_set] = lookup_service_set(rest[index + 2], lines.first)
          end
          emit(:dynamic_nat, attributes, lines)
        end
      end
    end
  end
end
