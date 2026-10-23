# frozen_string_literal: true

require_relative "../../config/parser"
require_relative "elements"

module Algosec
  module Vendors
    module PaloAlto
      # 读取 PAN-OS set 导出及终端会话。原文不改写，未建模语义显式诊断。
      class Parser < Algosec::Config::Parser
        VENDOR = :palo_alto
        OBJECTS = %w[address address-group service service-group schedule].freeze
        ROOTS = (OBJECTS + %w[network zone rulebase pre-rulebase post-rulebase deviceconfig]).freeze

        def initialize(builtin_services: {}, **options)
          defaults = { "service-http" => [ 80, 8080 ], "service-https" => [ 443 ] }.to_h do |name, ports|
            [ name, Algosec::Elements::ServiceObject.new(name: name, vendor: VENDOR,
              terms: ports.map { |port| { protocol: "tcp", destination_port: port.to_s } }) ]
          end
          super(builtin_services: defaults.merge(builtin_services), **options)
        end

        private

        def parse_document
          records = configuration_lines
          clock = records.find { |_line, w| w[0, 3] == %w[deviceconfig system timezone] }
          @time_zone = Time.find_zone!(clock[1][3]) if clock
          records.each { |line, w| object_command(line, w) if OBJECTS.include?(w[0]) }
          emit_objects
          resolve_references
          records.each { |line, w| network_command(line, w) if %w[network zone].include?(w[0]) }
          prepare_network_routes
          finish_network
          records.each { |line, w| rule_command(line, w) if %w[rulebase pre-rulebase post-rulebase].include?(w[0]) }
          build_rules
          build_nats
          records.each do |line, w|
            next if @reader.parsed?(line.index)
            unsupported(line, w.take(3).join(" "))
          end
        end

        # 跳过终端回显和配置外的帮助；不把证书、密码行写入诊断摘要。
        def configuration_lines
          shared_lines = {}
          records = @lines.filter_map do |line|
            text = line.text.gsub(/\e\[[0-?]*[ -\/]*[@-~]/, "").strip
            unless text.start_with?("set ")
              if text.empty? || text.match?(/\A(?:spawn |Last login:|Number of failed|--more--|\[edit\]|[>+]|[\w.-]+@[^ ]+[>#]|configure\z|commit\z|exit\z)/i) ||
                 @reader.content.include?("spawn ssh")
                consume(line)
              else
                unsupported(line, "input format")
              end
              next
            end
            root = text.split(/\s+/, 3)[1]
            if root == "cli"
              consume(line)
              next
            end
            unless ROOTS.include?(root) || %w[shared vsys].include?(root)
              unsupported(line, root)
              next
            end
            if root == "shared" && !OBJECTS.include?(text.split(/\s+/, 4)[2])
              unsupported(line, "shared #{text.split(/\s+/, 4)[2]}")
              next
            end
            w = Shellwords.split(text).drop(1)
            if w[0] == "vsys"
              unless w[1] == "vsys1"
                unsupported(line, "multiple-vsys", code: :unsupported_scope)
                next
              end
              w = w.drop(2)
            end
            if w[0] == "shared"
              shared_lines[line.index] = true
              w = w.drop(1)
            end
            if %w[pre-rulebase post-rulebase].include?(w[0])
              unsupported(line, "Panorama #{w[0]}", code: :unsupported_scope)
              next
            end
            if w[0, 3] == %w[deviceconfig system timezone]
              consume(line)
            end
            [ line, w ]
          end
          local_objects = records.filter_map { |line, w| w.take(2) if OBJECTS.include?(w[0]) && !shared_lines[line.index] }
          records.reject do |line, w|
            overridden = shared_lines[line.index] && local_objects.include?(w.take(2))
            consume(line) if overridden
            overridden
          end
        end

        def unsupported(line, path, code: :unsupported_command)
          diagnose(code, "PAN-OS unsupported: #{path}", line)
          consume(line)
        end

        def values(words) = Array(words).reject { |word| %w[[ ]].include?(word) }

        def object_command(line, w)
          root, name, field, *rest = w
          return consume(line) unless name
          type = root.tr("-", "_").to_sym
          if root == "schedule"
            # 部分 set 导出未给含空格的计划名称加引号。
            index = w.index("schedule-type")
            return unsupported(line, "schedule", code: :unsupported_schedule) unless index
            name, field, rest = w[1...index].join(" "), w[index + 1], w.drop(index + 2)
          end
          object = draft(type, name, name: name)
          case root
          when "address"
            case field
            when "ip-netmask"
              object.state[:ip_netmask] = rest.first
              object.attributes[:member] = [ address_leaf(rest.first) ]
            when "ip-range" then object.attributes[:member] = [ { type: "iprange", value: rest.first } ]
            when "fqdn" then object.attributes[:member] = [ { type: "domain", value: rest.first } ]
            when "description" then object.attributes[:description] = rest.join(" ")
            when "tag" # 元数据保留在配置原文。
            else return unsupported(line, "address #{field}")
            end
          when "address-group", "service-group"
            case field
            when "static", "members"
              object.attributes[:members] ||= {}
              values(rest).each { |member| object.attributes[:members][member] = nil }
            when "dynamic"
              object.attributes[:members] = { "__dynamic_filter__:#{name}" => nil }
              diagnose(:dynamic_address_group, "Dynamic address group #{name} needs runtime membership", line)
            when "description" then object.attributes[:description] = rest.join(" ")
            when "tag"
            else return unsupported(line, "#{root} #{field}")
            end
          when "service"
            if field == "protocol"
              protocol, parameter, *ports = rest
              if %w[port source-port].include?(parameter)
                key = parameter == "port" ? :destination_port : :source_port
                object.state[:protocol] = protocol
                object.state[key] = ports.join.delete("[] ").split(",")
              elsif parameter == "override"
                unless ports == %w[no]
                  diagnose(:unsupported_service, "Service #{name} has session overrides", line)
                end
              else
                return unsupported(line, "service #{parameter}")
              end
            elsif field == "description"
              object.attributes[:description] = rest.join(" ")
            elsif field != "tag"
              return unsupported(line, "service #{field}")
            end
          when "schedule"
            if field == "non-recurring"
              # XML member 和 set 多行声明都属于同一个计划，不能覆盖前一窗口。
              windows = object.state[:non_recurring_windows] = (object.state.fetch(:non_recurring_windows, []) + values(rest)).uniq
              (object.state[:non_recurring_lines] ||= []) << line.text
              object.attributes.merge!(schedule_attributes(name: name, start_at: windows.first&.split("-", 2)&.first,
                end_at: windows.first&.split("-", 2)&.last))
              if windows.size != 1
                object.attributes[:unparsed_commands] = object.state[:non_recurring_lines].uniq
                diagnose(:unsupported_schedule, "Multiple absolute windows: #{name}", line)
              end
            elsif field == "recurring"
              days = rest.shift
              if days == "weekly"
                days = rest.shift
              elsif days == "daily"
                days = "daily"
              else
                return unsupported(line, "schedule recurrence", code: :unsupported_schedule)
              end
              object.attributes.merge!(kind: :weekly, time_zone: @time_zone)
              object.attributes[:periods] ||= {}
              (object.attributes[:periods][days] ||= []).concat(values(rest).map { |period| period.split("-", 2) })
            else
              object.attributes.merge!(kind: :once, unparsed_commands: [ line.text ])
              diagnose(:unsupported_schedule, "Unsupported schedule #{name}", line)
            end
          end
          capture(object, line)
        end

        def emit_objects
          @drafts[:service].each_value do |object|
            state = object.state
            next unless state[:protocol]
            object.attributes[:terms] = Array(state[:destination_port]).product(state[:source_port] || [ ANY_SERVICE_PORTS ]).map do |dst, src|
              { protocol: state[:protocol], destination_port: dst, source_port: src }
            end
          end
          super
        end

        def network_command(line, w)
          @current_line = line
          if w[0] == "zone"
            name, section, mode, *members = w.drop(1)
            object = draft(:zone, name, name: name)
            if section == "network" && %w[layer3 layer2 virtual-wire tap].include?(mode)
              object.attributes[:mode] = %w[layer2 virtual-wire].include?(mode) ? :transparent : :routed
              values(members).each do |member|
                bind_zone(member, name, line)
                @drafts[:interface][member].attributes[:mode] = mode == "layer3" ? :layer3 : :layer2
              end
              capture(object, line)
            elsif section == "enable-user-identification" || mode == "zone-protection-profile"
              capture(object, line)
            end
          elsif w[1] == "interface"
            interface_command(line, w.drop(2))
          elsif w[1] == "virtual-router"
            vrf, section, *rest = w.drop(2)
            if section == "interface"
              values(rest).each { |name| capture(draft(:interface, name, name: name, vrf: vrf), line) }
            elsif section == "routing-table" && rest[0, 2] == %w[ip static-route]
              name, field, *args = rest.drop(2)
              object = draft(:route, [ vrf, name ], name: name, vrf: vrf)
              case field
              when "destination"
                address = find(:address, args.first)
                object.attributes[:subnet] = address && !address.conditional? ? IPAddr.cidrs(address.set).sole.join("/") : args.first
              when "interface" then object.attributes[:destination_interface] = args.first
              when "nexthop"
                if args[0] == "ip-address"
                  next_hop = interface_ip(args[1], object.lines.first)
                  object.attributes[:next_hop] = next_hop.split("/").first if next_hop
                elsif args[0] == "next-vr"
                  object.attributes[:destination_vrf] = args[1]
                else
                  unsupported(line, "route nexthop #{args[0]}")
                end
              when "metric" then object.attributes[:priority] = Integer(args.fetch(0), 10)
              when "admin-dist" then object.attributes[:distance] = Integer(args.fetch(0), 10)
              when "bfd", "route-table"
              when "path-monitor"
                diagnose(:conditional_route, "Route #{name} has path monitoring", line) if args[0, 2] == %w[enable yes]
              else return
              end
              capture(object, line)
            end
          end
        end

        def interface_ip(expression, line = nil)
          unless expression
            diagnose(:unsupported_interface_address, "Interface or route address is missing", line)
            return
          end
          object = @drafts[:address][expression]
          value = object&.state&.fetch(:ip_netmask, nil) || expression
          IPAddr.host_cidr(value)
          value
        rescue ArgumentError
          code = object ? :unsupported_interface_address : :missing_reference
          message = object ? "Address #{expression} is not a usable IPv4 host" : "Address #{expression}"
          diagnose(code, message, line)
          nil
        end

        def interface_command(line, w)
          family = w.shift
          name = %w[ethernet aggregate-ethernet].include?(family) ? w.shift : family
          if (unit = w.index("units"))
            name, w = w[unit + 1], w.drop(unit + 2)
          end
          return consume(line) unless name
          object = draft(:interface, name, name: name)
          object.attributes[:mode] = :layer3 if %w[loopback tunnel vlan].include?(family)
          mode = w.shift if %w[layer3 layer2 virtual-wire tap].include?(w.first)
          object.attributes[:mode] = %w[layer2 virtual-wire].include?(mode) ? :layer2 : :layer3 if mode
          if w.first == "ip"
            expression = w[1]
            expression = interface_ip(expression, line)
            if expression
              cidr = IPAddr.host_cidr(expression)
              object.attributes[:ipaddr] ||= cidr
              object.attributes[:mode] ||= :layer3
              ip, mask = ip_parts(cidr)
              connected_route(object, ip, mask, line, next_hop: ip).attributes[:extra_conf] = { "connected" => true }
            end
          elsif w.first == "comment"
            object.attributes[:description] = w.drop(1).join(" ")
          elsif w.first == "tag"
            object.attributes[:vlans] = [ w[1] ]
          end
          capture(object, line)
        end

        # 先解析所有接口地址，再解析静态路由，避免配置行顺序影响下一跳定位。
        def prepare_network_routes
          @drafts[:route].each_value do |object|
            interface = @drafts[:interface][object.attributes[:destination_interface]]
            if object.state[:connected] && interface
              object.attributes[:vrf] = interface.attributes.fetch(:vrf, "default")
            end
          end
          @drafts[:route].each_value do |object|
            target = route_target(object, [])
            object.attributes[:destination_interface] = target if target
          end
        end

        # Next VR 必须按同一目的范围递归查表，循环或多出口不能任取第一个。
        def route_target(object, path)
          attributes = object.attributes
          return attributes[:destination_interface] if attributes[:destination_interface] && !attributes[:destination_vrf]
          if path.include?(object.object_id)
            diagnose(:cross_vrf_route, "Routing loop: #{attributes[:name]}", object.lines.first)
            return nil
          end
          if attributes[:destination_vrf]
            destination = IPAddr.parse(attributes[:subnet])
            candidates = @drafts[:route].values.select do |candidate|
              candidate.attributes[:vrf] == attributes[:destination_vrf] && candidate.attributes[:subnet] &&
                IPAddr.parse(candidate.attributes[:subnet]).overlap?(destination)
            end
            # 覆盖整个查询范围的最长前缀决定基线，内部更具体路由也必须到同一接口。
            covering = candidates.select { |candidate| IPAddr.parse(candidate.attributes[:subnet]).cover?(destination) }
            if covering.empty?
              diagnose(:cross_vrf_route, "No covering route in #{attributes[:destination_vrf]} for #{attributes[:subnet]}", object.lines.first)
              return nil
            end
            rank = ->(candidate) { [ -IPAddr.new(candidate.attributes[:subnet]).prefix, candidate.attributes.fetch(:distance, 10), candidate.attributes.fetch(:priority, 0) ] }
            best = covering.map(&rank).min
            chosen = covering.select { |candidate| rank.call(candidate) == best }
            chosen.concat(candidates.select { |candidate| IPAddr.new(candidate.attributes[:subnet]).prefix > -best[0] })
            targets = chosen.uniq.map { |candidate| route_target(candidate, path + [ object.object_id ]) }
            if targets.include?(nil) || targets.uniq.size != 1
              diagnose(:cross_vrf_route, "Ambiguous next VR #{attributes[:destination_vrf]} for #{attributes[:subnet]}", object.lines.first)
              return nil
            end
            targets.first
          elsif attributes[:next_hop]
            hop = IPAddr.parse(attributes[:next_hop])
            matches = @drafts[:route].values.select do |candidate|
              candidate.state[:connected] && candidate.attributes[:vrf] == attributes.fetch(:vrf, "default") &&
                IPAddr.parse(candidate.attributes[:subnet]).cover?(hop)
            end
            targets = matches.map { |candidate| candidate.attributes[:destination_interface] }.uniq
            return targets.first if targets.one?
            diagnose(:missing_interface, "Cannot uniquely locate next hop #{attributes[:next_hop]} in #{attributes[:vrf]}", object.lines.first)
            nil
          end
        rescue ArgumentError => error
          diagnose(:invalid_route, error.message, object.lines.first)
          nil
        end

        def prepare_route(object, target)
          object.attributes[:vrf] = target.vrf if object.state[:connected] && target
        end

        # 出口已在草稿阶段完整定位，禁止通用回退任取一个歧义接口。
        def route_interface?(interface, attributes) = false
        def prepare_zone(object, members) = object.attributes[:vrf] ||= members.first&.vrf

        def rule_command(line, w)
          chain, family, marker, name, field, *rest = w
          return unless marker == "rules" && %w[security nat default-security-rules].include?(family)
          type = family == "nat" ? :pan_nat : :pan_rule
          object = draft(type, [ chain, family, name ], name: name)
          object.state[:chain] = chain
          object.state[:family] = family
          fields = (object.state[:fields] ||= {})
          if %w[from to source destination service application source-user category source-hip destination-hip tag].include?(field)
            fields[field] = (fields.fetch(field, []) + values(rest)).uniq
          else
            fields[field] = values(rest)
          end
          (object.state[:translations] ||= []) << [ field, *rest ] if field&.end_with?("translation")
          capture(object, line)
        end

        def build_rules
          ordered = @drafts[:pan_rule].values.sort_by { |raw| raw.state[:family] == "default-security-rules" ? 1 : 0 }
          ordered.each.with_index(1) do |raw, number|
            fields = raw.state[:fields]
            default = raw.state[:family] == "default-security-rules"
            fields["rule-type"] ||= [ raw.attributes[:name].start_with?("intrazone") ? "intrazone" : "interzone" ] if default
            service_names = fields.fetch("service", [ default ? "any" : "application-default" ])
            scope = "vsys1/#{raw.state[:chain]}"
            scope += "/default-security-rules" if default
            object = draft(:rule, [ scope, raw.attributes[:name] ], name: raw.attributes[:name], native_rule_id: raw.attributes[:name],
              rule_set: scope, rule_number: number,
              scope: Algosec::Elements::Scope.new(device_id: @reader.device_id, virtual_system: "vsys1", rulebase: raw.state[:chain]),
              rule_type: fields.fetch("rule-type", [ "universal" ]).first,
              applications: fields.fetch("application", [ "any" ]), source_users: fields.fetch("source-user", [ "any" ]),
              service_selection: service_names.include?("application-default") ? :application_default : :explicit,
              action: fields.fetch("action", [ "deny" ]).first,
              status: { "yes" => "disable", "no" => "enable" }.fetch(fields.fetch("disabled", [ "no" ]).join(" ")) { fields["disabled"].join(" ") },
              from_zones: fields.fetch("from", [ "any" ]), to_zones: fields.fetch("to", [ "any" ]),
              description: fields["description"]&.join(" "), schedule_name: fields["schedule"]&.first,
              vendor_data: { "panos" => JSON.generate(fields.except("source", "destination", "service").merge("family" => raw.state[:family])) })
            object.lines.concat(raw.lines)
            %w[source destination].zip(%i[sources destinations]).each do |key, dimension|
              if fields["negate-#{key}"] == [ "yes" ]
                object.attributes[dimension] = Algosec::Elements::AddressGroup::Negated.new(**context, name: "#{raw.attributes[:name]}:#{dimension}")
              end
              fields.fetch(key, [ "any" ]).each { |name| add_pan_address(object, dimension, name) }
            end
            service_names.each do |name|
              next if name == "application-default"
              if name == "any"
                svc = service("any") || emit(:service, { name: "any", protocol: "any" })
                add_members(object, :services, [ [ "any", svc ] ])
              else
                add_members(object, :services, [ name ])
              end
            end
            conditions = {}
            conditions["security_profiles"] = { "panos" => fields["profile-setting"].join(" ") } if fields["profile-setting"]
            restricted = %w[category source-hip destination-hip].any? { |key| fields[key] && fields[key] != [ "any" ] }
            user_selector = (fields.fetch("source-user", []) & %w[known-user unknown pre-logon]).any?
            restricted ||= user_selector
            restricted ||= service_names.include?("application-default") && service_names.size > 1
            if restricted
              conditions["unparsed_commands"] = raw.lines.map(&:text).select { |text| text.match?(/(?:category|hip|negate-|application-default)/) || (user_selector && text.include?("source-user")) }
              diagnose(:conditional_rule, "Rule #{raw.attributes[:name]} needs application/user/negation context", raw.lines.first)
            end
            known = %w[from to source destination source-user category application source-hip destination-hip action service disabled tag profile-setting description group-tag rule-type negate-source negate-destination log-start log-end log-setting schedule option]
            (fields.keys - known).each do |key|
              (conditions["unparsed_commands"] ||= []) << "#{key} #{fields[key].join(' ')}"
              diagnose(:unsupported_rule_condition, "Rule #{raw.attributes[:name]}: #{key}", raw.lines.first)
            end
            object.attributes[:conditions] = conditions
            object.attributes[:log] = %w[log-start log-end].select { |key| fields[key] == [ "yes" ] }.join(" ").presence
            # 至少一个显式 yes 即可证明开启；两个显式 no 才能证明关闭。
            # 省略值可能依赖默认值或继承，不用猜测补全。
            logging = fields.values_at("log-start", "log-end")
            object.attributes[:log_enabled] = if logging.include?([ "yes" ]) then true
            elsif logging.all? { |value| value == [ "no" ] } then false
            end
          end
          emit_rules
          resolve_references
          @catalog.select { |item| item.is_a?(Algosec::Elements::SecurityRule) }.each do |rule|
            [ rule.sources, rule.destinations ].each do |group|
              if group.is_a?(Algosec::Elements::AddressGroup::Negated) && !group.resolved?
                diagnose(:conditional_rule, "Rule #{rule.name} has unresolved negated addresses")
              end
            end
          end
        end

        def any_address_member(_name, dimension: nil) = { type: "any", value: "any" }

        def add_pan_address(object, dimension, name)
          if any_address?(name)
            add_members(object, dimension, [ name ], addresses: true)
          elsif find(:address, name) || find(:address_group, name)
            add_members(object, dimension, [ name ])
          elsif name.match?(/\A[0-9]+\.[0-9.\/-]+\z/)
            literal = Algosec::Elements::AddressObject.new(**context, name: name, member: [ name.include?("-") ? { type: "iprange", value: name } : address_leaf(name) ])
            add_members(object, dimension, [ [ name, literal ] ])
          else
            add_members(object, dimension, [ name ])
          end
        end

        def nat_addresses(names, line)
          sets = Array(names).map { |name| lookup_address_set(name, line) }
          return nil if sets.empty? || sets.any?(&:nil?)
          Set.new(*sets.flat_map(&:ranges))
        end

        # 服务组展开保留源端口与目的端口的配对，范围索引不能替代完整条件。
        def nat_service(object, line)
          return object unless object.is_a?(Algosec::Elements::ServiceGroup)
          projection = object.service_projection
          unless projection[:resolution]["complete"]
            diagnose(:missing_reference, "NAT service group #{object.name} is incomplete", line)
          end
          object
        end

        def build_nats
          @drafts[:pan_nat].each_value.with_index(1) do |raw, position|
            f, line = raw.state[:fields], raw.lines.first
            known = %w[from to source destination service to-interface source-translation destination-translation disabled description tag group-tag nat-type]
            (f.keys - known).each do |key|
              diagnose(:unsupported_nat_condition, "NAT #{raw.attributes[:name]}: #{key}", line)
            end
            if f["nat-type"] && f["nat-type"] != [ "ipv4" ]
              diagnose(:unsupported_nat_condition, "NAT #{raw.attributes[:name]} requires non-IPv4 translation", line)
            end
            if %w[from to].any? { |key| f.fetch(key, []).size > 1 }
              diagnose(:unsupported_nat_condition, "NAT #{raw.attributes[:name]} has multiple matching zones", line)
            end
            to_interfaces = f.fetch("to-interface", [])
            if to_interfaces.size > 1 || (f.key?("to-interface") && to_interfaces.empty?)
              diagnose(:unsupported_nat_condition, "NAT #{raw.attributes[:name]} requires one to-interface value", line)
            elsif to_interfaces.first && to_interfaces.first != "any" && !find(:interface, to_interfaces.first)
              diagnose(:missing_reference, "Interface #{to_interfaces.first}", line)
            end
            # 多行 translation 字段必须按子路径合并，不能让后一行覆盖前一行。
            translations = raw.state.fetch(:translations, [])
            snat = translations.select { |w| w[0] == "source-translation" }
            dnat = translations.select { |w| w[0] == "destination-translation" }
            unsupported_modes = snat.map { |words| words[1] }.uniq - %w[static-ip dynamic-ip dynamic-ip-and-port]
            unless unsupported_modes.empty?
              diagnose(:unsupported_nat_condition, "NAT #{raw.attributes[:name]} has unsupported source translation modes: #{unsupported_modes.join(', ')}", line)
              next
            end
            direction = snat.any? && dnat.any? ? :bidirectional : (snat.any? ? :source : :destination)
            from_zones, to_zones = f.fetch("from", [ "any" ]), f.fetch("to", [ "any" ])
            attributes = { name: raw.attributes[:name], id: raw.attributes[:name], direction: direction, nat_order: [ position ],
              source_set: nat_addresses(f.fetch("source", [ "any" ]), line),
              destination_set: nat_addresses(f.fetch("destination", [ "any" ]), line),
              from_zone: from_zones.one? ? from_zones.first : nil,
              to_zone: to_zones.one? ? to_zones.first : nil,
              interface: f["to-interface"]&.first == "any" ? nil : f["to-interface"]&.first,
              extra_conf: { "disabled" => f["disabled"] == [ "yes" ], "src_zones" => from_zones,
                            "dst_zones" => to_zones, "panos" => f.merge("translations" => translations) },
              description: f["description"]&.join(" ") }
            svc_name = f.fetch("service", [ "any" ]).first
            svc = service(svc_name)
            attributes[:service_set] = svc_name == "any" ? all_services : lookup_service_set(svc_name, line)
            attributes[:service] = nat_service(svc, line)
            attributes[:protocol] = svc.is_a?(Algosec::Elements::ServiceObject) ? (svc.protocol || "any") : "any"
            attributes[:destination_port] = svc.destination_port if svc.is_a?(Algosec::Elements::ServiceObject)
            snat.each do |w|
              attributes[:nat_type] = w[1]
              if w[2] == "translated-address"
                attributes[:translated_source_set] = nat_addresses(values(w.drop(3)), line)
              elsif w[2, 2] == %w[interface-address interface]
                iface = find(:interface, w[4])
                if iface&.host
                  attributes[:interface] = iface.name
                  attributes[:translated_source_set] ||= IPAddr.parse(iface.host)
                else
                  diagnose(iface ? :unsupported_nat_condition : :missing_reference,
                    iface ? "NAT #{raw.attributes[:name]} interface #{iface.name} has no IPv4 address" : "Interface #{w[4] || '(missing)'}", line)
                end
              elsif w[2, 2] == %w[interface-address ip]
                attributes[:translated_source_set] = nat_host_address(w[4], raw.attributes[:name], line)
              elsif w[1, 3] == %w[static-ip bi-directional no]
                # 显式单向静态源转换，无需合成反向规则。
              else
                diagnose(:unsupported_nat_condition, "NAT #{raw.attributes[:name]} source translation", line)
              end
            end
            dnat.each do |w|
              if w[1] == "translated-address"
                attributes[:translated_destination_set] = nat_addresses(w.drop(2), line)
              elsif w[1] == "translated-port"
                attributes[:translated_destination_port] = w[2]
              else
                diagnose(:unsupported_nat_condition, "NAT #{raw.attributes[:name]} destination translation", line)
              end
            end
            if snat.empty? && dnat.empty?
              attributes[:extra_conf]["no_translation"] = true
              diagnose(:unsupported_nat_condition, "NAT #{raw.attributes[:name]} exemption", line)
            end
            names = f.fetch("source", []) + f.fetch("destination", [])
            translations.each do |words|
              index = words.index("translated-address") || (words[0, 3] == %w[source-translation dynamic-ip-and-port interface-address] && words.index("ip"))
              names.concat(values(words.drop(index + 1))) if index
            end
            attributes[:references] = names.uniq.filter_map { |name| find(:address, name) || find(:address_group, name) }
            attributes[:references] << svc if svc
            emit(:dynamic_nat, attributes, raw.lines)
          end
        end

        # NAT interface-address ip 指向单个可解析的 IPv4 主机值；非法值保留为诊断，不中断整份配置解析。
        def nat_host_address(expression, nat_name, line)
          unless expression
            diagnose(:unsupported_nat_condition, "NAT #{nat_name} interface-address ip has no address", line)
            return
          end
          object = @drafts[:address][expression]
          value = object&.state&.fetch(:ip_netmask, nil) || expression
          address = IPAddr.parse(IPAddr.host(value))
          unless address.ranges.all? { |range| range.end <= IPAddr::IPV4_MAX }
            diagnose(:unsupported_nat_condition, "NAT #{nat_name} interface-address ip must resolve to IPv4", line)
            return
          end
          address
        rescue ArgumentError
          code = object ? :unsupported_nat_condition : :missing_reference
          message = object ? "NAT #{nat_name} interface-address ip requires an IP address object" : "Address #{expression}"
          diagnose(code, message, line)
          nil
        end
      end
    end
  end
end
