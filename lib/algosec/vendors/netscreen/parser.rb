# frozen_string_literal: true

require_relative "../../config/parser"

module Algosec
  module Vendors
    module Netscreen
      # 解析 ScreenOS 地址、服务、接口 NAT 和策略。
      class Parser < Algosec::Config::Parser
        VENDOR = :netscreen

        stage :reset_network, using: :reset_network
        stage :network
        line_rule :network, :set, prefix: %w[set], using: :network_command
        line_rule :network, :unset, prefix: %w[unset], using: :network_command
        line_rule :network, :exit, prefix: %w[exit], using: :network_command
        stage :finish_network, using: :finish_network
        stage :objects
        line_rule :objects, :set, prefix: %w[set], using: :object_command
        stage :emit_objects, using: :emit_objects
        stage :pools, using: :emit_pools
        stage :interface_nat
        line_rule :interface_nat, :set, prefix: %w[set], using: :interface_nat
        stage :reset_policy, using: :reset_policy
        stage :policies
        line_rule :policies, :set, prefix: %w[set], using: :policy_command
        line_rule :policies, :exit, prefix: %w[exit], using: :policy_command
        stage :emit_rules, using: :emit_rules
        stage :rule_references, using: :resolve_references
        stage :vip_nat, using: :build_vips
        stage :policy_nat, using: :build_policy_nat

        private

        def any_address?(name, dimension: nil) = /\A(?:any|any-ipv4)\z/i.match?(name)

        def address_reference_scope(zone) = { zone: zone }

        def service(name)
          find(:service, name) || builtin(name) || find(:service_group, name)
        end

        # 在接口 NAT 使用地址池之前发射池对象。
        def emit_pools
          @drafts[:nat_pool].each_value { |object| emit_draft(:nat_pool, object) }
        end

        # 策略续行上下文只属于本次文档。
        def reset_policy
          @policy_context = nil
        end

        # 路由上下文和开关只属于本份配置；源路由必须显式启用。
        def reset_network
          @vrouter = nil
          @default_vrouter = Elements.default_vrf
          @routers = Hash.new { |routers, name| routers[name] = { connected: 0, static: 20, source_routing: false } }
        end

        def network_command(line, words)
          if words == [ "exit" ] && @vrouter
            @vrouter = nil
            consume(line)
          elsif %w[set unset].include?(words[0]) && words[1] == "vrouter"
            name, *rest = words.drop(2)
            if words[0] == "set" && name == "name" && rest.one?
              @vrouter = rest.first
              consume(line)
            elsif words[0] == "set" && name && rest.empty?
              @vrouter = name
              consume(line)
            elsif name
              router_command(line, words[0], name, rest)
            end
          elsif words[0, 2] == %w[set zone] && words[3] == "vrouter" && words.size == 5
            capture(draft(:zone, words[2], name: words[2], vrf: words[4]), line)
          elsif words[0, 2] == %w[set interface]
            interface_command(line, words.drop(2))
          elsif %w[set unset].include?(words[0])
            router_command(line, words[0], @vrouter || @default_vrouter, words.drop(1))
          end
        end

        def interface_command(line, words)
          name, *rest = words
          rest = rest.drop(2) if rest[0] == "tag"
          if rest[0] == "zone"
            capture(bind_zone(name, rest[1], line), line)
          elsif rest[0] == "ip"
            ip, mask = ip_parts(rest[1], (rest[2] == "secondary") ? nil : rest[2])
            object = draft(:interface, name, name: name)
            secondary = rest.include?("secondary")
            object.attributes.merge!(ipaddr: IPAddr.host_cidr(ip, mask), mode: :layer3) unless secondary
            capture(object, line)
            connected_route(object, ip, mask, line, next_hop: secondary ? ip : nil)
          elsif rest.include?("dip")
            index = rest.index("dip")
            id, first, last = rest[index + 1, 3]
            capture(draft(:nat_pool, id, name: id, ip: "#{first}-#{last}", interface: name), line)
          end
        end

        # 只消费已建模的 VR 指令；动态协议和自定义查表顺序仍保留未支持诊断。
        def router_command(line, action, vrf, words)
          settings = @routers[vrf]
          if action == "set" && words.first == "route"
            return route_command(line, words.drop(1), vrf: vrf)
          elsif action == "set" && words == [ "default-vrouter" ]
            @default_vrouter = vrf
          elsif words == %w[source-routing enable] || words == [ "enable-source-routing" ]
            settings[:source_routing] = action == "set"
          elsif words.first == "preference" && %w[connected static].include?(words[1])
            kind = words[1].to_sym
            if action == "set" && words.size == 3
              settings[kind] = route_number(words[2], "preference", 0..255)
            elsif action == "unset" && words.size == 2
              settings[kind] = kind == :connected ? 0 : 20
            else
              return
            end
          else
            return
          end
          consume(line)
        rescue ArgumentError => error
          consume(line)
          diagnose(:invalid_route, error.message, line)
        end

        # 草稿按路径区分；同一路径后续调整 metric 时更新属性，不覆盖其他出口。
        def route_command(line, words, vrf:)
          attributes = route_fields(words).merge(vrf: vrf)
          key = attributes.values_at(:kind, :vrf, :source, :subnet, :destination_interface, :next_hop, :destination_vrf)
          capture(draft(:route, key, **attributes), line)
        rescue ArgumentError => error
          consume(line)
          diagnose(:invalid_route, error.message, line)
        end

        def route_fields(words)
          rest = words.dup
          policy = rest.first == "source"
          rest.shift if policy
          expression = rest.shift
          raise ArgumentError, "Route requires an IPv4 prefix" unless expression
          network = IPAddr.network_cidr(expression)
          attributes = { kind: policy ? :policy : :static, source: policy ? network : nil,
                         subnet: policy ? "#{WILDCARD_IPV4}/0" : network, priority: 1, extra_conf: {} }
          fields = {}
          until rest.empty?
            key, value = rest.shift(2)
            unless %w[interface gateway vrouter metric tag].include?(key) && value && !fields.key?(key)
              raise ArgumentError, "Unsupported or incomplete route field #{key}"
            end
            fields[key] = value
          end
          if fields["vrouter"]
            raise ArgumentError, "Route cannot combine a virtual router and an interface or gateway" if fields["interface"] || fields["gateway"]
            attributes[:destination_vrf] = fields["vrouter"]
          else
            raise ArgumentError, "Route requires an interface or gateway" unless fields["interface"] || fields["gateway"]
            attributes[:destination_interface] = fields["interface"]
            attributes[:next_hop] = IPAddr.from_i(IPAddr.to_i(fields["gateway"])) if fields["gateway"]
          end
          attributes[:priority] = route_number(fields["metric"], "metric") if fields["metric"]
          attributes[:extra_conf]["tag"] = route_number(fields["tag"], "tag") if fields["tag"]
          attributes
        end

        # 先确定 VRF 和下一跳接口，再交给共享装配器建立对象及区域投影。
        def finish_network
          # 系统默认查表 VR 不改变安全区归属；区域只有显式绑定才离开 trust-vr。
          @drafts[:zone].each_value { |object| object.attributes[:vrf] ||= Elements.default_vrf }
          @drafts[:interface].each_value do |object|
            object.attributes[:vrf] ||= @drafts[:zone][object.attributes[:zone]]&.attributes&.fetch(:vrf, nil) || Elements.default_vrf
          end
          @drafts[:route].each_value do |object|
            attributes = object.attributes
            target = @drafts[:interface][attributes[:destination_interface]]
            attributes[:vrf] = target&.attributes&.fetch(:vrf, nil) if object.state[:connected]
            attributes[:vrf] ||= @default_vrouter
          end
          @drafts[:route].each_value { |object| resolve_route_target(object) }
          super
        end

        # 出口已在草稿阶段解析，禁止共享装配器任取同网段接口。
        def route_interface?(interface, attributes) = false

        def prepare_route(object, target)
          attributes = object.attributes
          settings = @routers[attributes[:vrf]]
          attributes[:distance] = settings.fetch(object.state[:connected] ? :connected : :static)
          extra = (attributes[:extra_conf] ||= {})
          if object.state[:connected]
            attributes[:priority] = 0
            extra["connected"] = true
          elsif attributes[:kind] == :policy
            extra["disabled"] = !settings[:source_routing]
          end
        end

        def object_command(line, words)
          case words[0, 2]
          when %w[set address]
            zone, name, ip, mask, description = words.drop(2)
            capture(draft(:address, [ zone, name ], name: name, zone: zone, member: [ address_leaf(ip, mask) ], description: description), line)
          when %w[set group]
            type = { "address" => :address_group, "service" => :service_group }[words[2]]
            return unless type
            rest = words.drop(3)
            zone = (type == :address_group) ? rest.shift : nil
            name = rest.shift
            scope = (type == :address_group) ? { zone: zone } : {}
            object = draft(type, [ zone, name ], name: name, **scope)
            if rest[0] == "add"
              (object.attributes[:members] ||= {})[rest[1]] = nil
            elsif rest[0] == "comment"
              object.attributes[:description] = rest[1]
            elsif !rest.empty?
              return
            end
            capture(object, line)
          when %w[set service]
            service_command(line, words.drop(2))
          when %w[set scheduler]
            name, kind, *rest = words.drop(2)
            object = draft(:schedule, name, **schedule_attributes(name: name))
            if kind == "once" && rest[0] == "start" && rest[3] == "stop"
              object.attributes.merge!(start_at: rest[1, 2].join(" "), end_at: rest[4, 2].join(" "))
            elsif kind == "recurrent"
              day = rest.shift
              periods = []
              while rest[0] == "start" && rest[2] == "stop"
                periods << rest.values_at(1, 3)
                rest = rest.drop(4)
              end
              object.attributes[:kind] = :weekly
              (object.attributes[:periods] ||= {})[day] = periods
              object.attributes[:description] = rest[1] if rest[0] == "comment"
            else
              return
            end
            capture(object, line)
          end
        end

        def service_command(line, words)
          name, command, *rest = words
          if command == "timeout"
            object = @drafts[:service][name]
            unless object
              template = builtin(name)
              return diagnose(:missing_reference, "Service #{name} has no definition", line) unless template
              object = draft(:service, name, name: name, terms: template.terms)
            end
            object.attributes[:terms] = object.attributes.fetch(:terms, []).map { |term| term.merge(timeout: rest[0]) }
          elsif %w[protocol +].include?(command) && rest[1] == "src-port" && rest[3] == "dst-port"
            object = draft(:service, name, name: name)
            object.attributes[:terms] = [] if command == "protocol"
            term = { protocol: rest[0], source_port: rest[2], destination_port: rest[4],
                     timeout: (rest[5] == "timeout") ? rest[6] : nil }
            (object.attributes[:terms] ||= []) << term
          else
            return
          end
          capture(object, line)
        end

        def interface_nat(line, words)
          return unless words[0, 2] == %w[set interface] && %w[mip vip].include?(words[3])
          interface = find(:interface, words[2])
          unless interface&.zone
            consume(line)
            return diagnose(:missing_interface, "NAT interface #{words[2]} has no zone", line)
          end
          if words[3] == "mip"
            mip(line, interface, words.drop(4))
          elsif words[3] == "vip"
            vip(line, interface, words.drop(4))
          else
            return
          end
          consume(line)
        end

        # MIP 的主机 VR 独立于入接口；掩码缺省为单主机，选项顺序不影响含义。
        def mip(line, interface, words)
          mapped, host, real, *rest = words
          raise ArgumentError, "MIP requires a mapped address and host" unless host == "host" && real
          fields = {}
          until rest.empty?
            key, value = rest.shift(2)
            key = "vrouter" if key == "vr"
            unless %w[netmask vrouter].include?(key) && value && !fields.key?(key)
              raise ArgumentError, "Unsupported or incomplete MIP field #{key}"
            end
            fields[key] = value
          end
          prefix = IPAddr.prefix_length(fields.fetch("netmask", 32))
          real_set, mapped_set = [ real, mapped ].map { |ip| IPAddr.subnet(ip, prefix) }
          real_zone = zone_for(real_set, vrf: fields.fetch("vrouter", Elements.default_vrf))
          return diagnose(:missing_zone, "No route to MIP target #{real}/#{prefix}", line) unless real_zone

          emit(:static_nat, { mapped_ip: mapped, real_ip: real, mask: prefix, interface: interface.name,
                              mapped_zone: interface.zone, real_zone: real_zone, mapped_set: mapped_set, real_set: real_set }, [ line ])
          name = "MIP(#{mapped}#{"/#{prefix}" unless prefix == 32})"
          emit(:address, { name: name, zone: "Global", member: [ address_leaf(mapped, prefix) ], description: "mip" }, [ line ])
        rescue ArgumentError => error
          diagnose(:invalid_nat, "MIP: #{error.message}", line)
        end

        # VIP 的命名服务属于内侧；外侧匹配使用显式虚拟端口和同一传输协议。
        def vip(line, interface, words)
          mapped, *rest = words
          rest.shift if rest.first == "+"
          port, service_name, real, *options = rest
          unless rest.size >= 3 && /\A[0-9]+\z/.match?(port) && (options.empty? || options == [ "manual" ])
            return diagnose(:unsupported_nat_condition, "VIP requires an address, port, service and target", line)
          end
          mapped_set, real_set = [ mapped, real ].map { |ip| IPAddr.parse(ip) }
          unless mapped_set.cardinality == 1 && real_set.cardinality == 1
            return diagnose(:unsupported_nat_condition, "VIP requires single host addresses", line)
          end
          IPAddr.ports(port)
          capture(draft(:vip, [ interface.name, mapped, port, service_name ], interface: interface.name, from_zone: interface.zone, vrf: interface.vrf,
                        destination_ip: mapped, destination_port: port, destination_set: mapped_set,
                        translated_destination_ip: real, translated_destination_set: real_set, service_name: service_name), line)
          emit(:address, { name: "VIP(#{mapped})", zone: "Global", member: [ address_leaf(mapped, 32) ], description: "vip" }, [ line ])
        rescue ArgumentError => error
          diagnose(:invalid_nat, "VIP: #{error.message}", line)
        end

        # 地址对象先供策略和地址组引用，服务组解析完成后再构造 VIP 映射。
        def build_vips
          @drafts[:vip].each_value { |object| build_vip(object) }
        end

        def build_vip(raw)
          line = raw.lines.first
          service_name = raw.attributes[:service_name]
          object = service(service_name)
          return diagnose(:missing_reference, "VIP service #{service_name}", line) unless object
          projection = object.service_projection
          unless projection[:resolution]["complete"] && !object.set.empty?
            return diagnose(:unresolved_service, "VIP service #{service_name} is empty or incomplete", line)
          end
          protocols = object.ports.keys.map { |protocol| IPAddr.protocol_number(protocol) }.uniq
          ports = Set.new(*object.ports.values.flat_map(&:ranges))
          if (protocols - [ IPAddr::TCP, IPAddr::UDP ]).any? || ports.cardinality != 1
            return diagnose(:unsupported_nat_condition, "VIP service #{service_name} requires one TCP/UDP destination port", line)
          end
          zone = zone_for(raw.attributes[:translated_destination_set], vrf: raw.attributes[:vrf])
          return diagnose(:missing_zone, "No route to VIP target #{raw.attributes[:translated_destination_ip]}", line) unless zone

          attributes = raw.attributes.except(:service_name).merge(direction: :destination, to_zone: zone, source_set: all_addresses,
                                                                 translated_service: object)
          protocols.each do |protocol|
            emit(:dynamic_nat, attributes.merge(protocol: protocol, service_set: IPAddr.service("#{protocol}/#{attributes[:destination_port]}"),
                                                translated_service_set: object.set & IPAddr.service("#{protocol}/#{ANY_SERVICE_PORTS}")), raw.lines)
          end
        end

        def policy_command(line, words)
          if words[0, 3] == %w[set policy id]
            id = words[3]
            rest = words.drop(4)
            if rest.include?("from")
              if @drafts[:rule].key?(id)
                consume(line)
                return diagnose(:duplicate_rule, "Policy #{id} is declared twice", line)
              end
              name = (rest[0] == "name") ? rest.slice!(0, 2).last : nil
              return unless rest[0] == "from" && rest[2] == "to"
              from, to, src, dst, srv = rest.values_at(1, 3, 4, 5, 6)
              tail = rest.drop(7)
              action = tail.find { |value| %w[permit deny reject tunnel].include?(value) }
              return unless action
              object = draft(:rule, id, native_rule_id: id, name: name, from_zones: [ from ], to_zones: [ to ],
                             action: action, rule_number: @drafts[:rule].size)
              parse_policy_tail(object, tail, action, line)
              add_members(object, :sources, [ src ], zone: from, addresses: true)
              add_members(object, :destinations, [ dst ], zone: to, addresses: true)
              add_members(object, :services, [ srv ])
            else
              object = @drafts[:rule][id]
              unless object
                consume(line)
                return diagnose(:missing_reference, "Policy #{id} has no declaration", line)
              end
              if rest[0] == "disable"
                object.attributes[:status] = "disable"
              elsif rest[0] == "application"
                (object.attributes[:conditions] ||= {})["application_check"] = rest[1]
              elsif !rest.empty?
                return
              end
            end
            @policy_context = object
            capture(object, line)
          elsif @policy_context
            object = @policy_context
            if words == [ "exit" ]
              @policy_context = nil
            elsif words[0] == "set" && %w[src-address dst-address service].include?(words[1])
              dimension = { "src-address" => :sources, "dst-address" => :destinations, "service" => :services }.fetch(words[1])
              zone = object.attributes[(dimension == :sources) ? :from_zones : :to_zones].first
              add_members(object, dimension, [ words[2] ], zone: zone, addresses: dimension != :services)
            elsif words == %w[set log session-init]
              object.attributes[:log] = "session-init"
            elsif words[0, 2] == %w[set nat]
              apply_policy_nat(object, words.drop(1), line)
            else
              @policy_context = nil
              return
            end
            capture(object, line)
          end
        end

        # 声明尾部必须完整消费，未知匹配词附着于规则，不能退化为普通允许策略。
        def parse_policy_tail(object, words, action, line)
          index = words.index(action)
          before, after = words.take(index), words.drop(index + 1)
          unsupported = []
          if before.first == "nat"
            apply_policy_nat(object, before, line)
          else
            unsupported.concat(before)
          end
          until after.empty?
            field = after.shift
            if field == "log"
              object.attributes[:log] = "log"
            elsif field == "schedule" && after.any?
              object.attributes[:schedule_name] = after.shift
            else
              unsupported << field
            end
          end
          return if unsupported.empty?

          ((object.attributes[:conditions] ||= {})["unparsed_commands"] ||= []) << line.text
          diagnose(:unsupported_rule_condition, "Policy #{object.attributes[:native_rule_id]} has unsupported fields: #{unsupported.join(' ')}", line)
        end

        # 声明行与策略上下文共用 NAT 语法，操作数不完整时保留规则的未知条件。
        def apply_policy_nat(object, words, line)
          object.attributes[:nat] = true
          fields = policy_nat_fields(words, line)
          if fields
            object.state.merge!(fields)
          else
            ((object.attributes[:conditions] ||= {})["unparsed_commands"] ||= []) << line.text
            object.state[:invalid_nat] = true
          end
        end

        def policy_nat_fields(words, line)
          rest = words.dup
          raise ArgumentError, "Expected nat declaration" unless rest.shift == "nat"
          fields = {}
          if rest.first == "src"
            rest.shift
            fields.merge!(nat_source: true, pool: nil)
            if rest.first == "dip-id"
              rest.shift
              fields[:pool] = rest.shift
              raise ArgumentError, "DIP ID must be numeric" unless /\A[0-9]+\z/.match?(fields[:pool].to_s)
            end
          end
          if rest.first == "dst"
            rest.shift
            raise ArgumentError, "Expected destination IP" unless rest.shift == "ip"
            fields[:nat_destination] = rest.shift
            IPAddr.to_i(fields[:nat_destination])
            fields[:nat_port] = nil
            if rest.first == "port"
              rest.shift
              fields[:nat_port] = rest.shift
              raise ArgumentError, "Destination port must be numeric" unless /\A[0-9]+\z/.match?(fields[:nat_port].to_s)
              IPAddr.ports(fields[:nat_port])
            end
          end
          unless rest.empty? && !fields.empty?
            return diagnose(:unsupported_nat_condition, "Unsupported policy NAT fields: #{words.join(" ")}", line)
          end
          fields
        rescue ArgumentError => error
          diagnose(:invalid_nat, "Policy NAT: #{error.message}", line)
        end

        def build_policy_nat
          @drafts[:rule].each_value do |object|
            next if object.state[:invalid_nat]
            next unless object.state[:nat_source] || object.state[:pool] || object.state[:nat_destination]
            build_rule_nat(object)
          end
        end

        # 策略 NAT 复用完整规则条件；缺失引用不能变成全匹配或空转换目标。
        def build_rule_nat(object)
          pool_name, destination, port = object.state.values_at(:pool, :nat_destination, :nat_port)
          line = object.lines.first
          rule = @catalog.detect { |element| element.is_a?(Algosec::Elements::SecurityRule) && element.native_rule_id == object.attributes[:native_rule_id] }
          unless [ rule.sources, rule.destinations, rule.services ].all?(&:resolved?) && !rule.services.set.empty?
            return diagnose(:missing_reference, "Policy NAT #{rule.native_rule_id} has incomplete members", line)
          end
          destination_set = destination && IPAddr.parse(destination)
          attributes = { policy_id: rule.native_rule_id, from_zone: rule.from_zones.first, to_zone: rule.to_zones.first,
                         match_rule: rule, source_set: rule.sources.set, destination_set: rule.destinations.set, service_set: rule.services.set,
                         translated_destination_ip: destination, translated_destination_set: destination_set, translated_destination_port: port }
          if pool_name || object.state[:nat_source]
            source = policy_nat_source(rule, pool_name, destination_set, line)
            return unless source
            attributes.merge!(source)
            attributes[:direction] = destination ? :bidirectional : :source
          else
            attributes[:direction] = :destination
          end
          if port
            attributes[:translated_service_set] = service_projection(rule.services.ports.transform_values { IPAddr.ports(port) })
          end
          emit(:dynamic_nat, attributes, object.lines)
        rescue ArgumentError => error
          diagnose(:invalid_nat, "Policy NAT #{object.attributes[:native_rule_id]}: #{error.message}", line)
        end

        # 多接口区域必须经完整路由选择确定出口，不能用区域内首个接口推断转换地址。
        def policy_nat_source(rule, pool_name, destination_set, line)
          if pool_name
            pool = find(:nat_pool, pool_name)
            return diagnose(:missing_reference, "NAT pool #{pool_name}", line) unless pool
            return { source_pool: pool, translated_source_set: pool.set }
          end
          zone = find(:zone, rule.to_zones.first)
          interfaces = zone ? zone.interfaces.values : []
          ingress = find(:zone, rule.from_zones.first)
          interface = if interfaces.one?
                        interfaces.first
          elsif ingress
                        egress_interface(rule.sources.set, destination_set || rule.destinations.set, vrf: ingress.vrf)
          end
          unless interface&.host && interface.zone == rule.to_zones.first
            return diagnose(:missing_nat_context, "Policy NAT #{rule.native_rule_id} has no definite egress address", line)
          end
          { interface: interface.name, vrf: ingress&.vrf || interface.vrf, translated_source_set: IPAddr.parse(interface.host) }
        end
      end
    end
  end
end
