# frozen_string_literal: true

require "active_support/core_ext/object/deep_dup"
require_relative "../../config/parser"

module Algosec
  module Vendors
    module H3c
      # 解析 H3C 对象组、接口、区域、ACL 和 NAT 命令。
      class Parser < Algosec::Config::Parser
        VENDOR = :h3c

        stage :scan_document, using: :scan_document
        stage :finish_network, using: :finish_network
        stage :finish_services, using: :finish_services
        stage :emit_objects, using: :emit_objects
        stage :parse_policies, using: :parse_policies
        stage :emit_rules, using: :emit_rules
        stage :rule_references, using: :resolve_references
        stage :parse_nat, using: :parse_nat
        HEADERS = /\A(?:object-group (?:ip address|service|port) |interface |security-zone name |zone-pair security |acl (?:basic|advanced) |object-policy ip |nat address-group )/
        STATIC_ROUTE_PREF = 60
        OBJECT_FIELDS = { "source-ip" => :sources, "destination-ip" => :destinations, "service" => :services }.freeze

        PORTS = { "bgp" => 179, "chargen" => 19, "cmd" => 514, "daytime" => 13, "discard" => 9,
                  "dns" => 53, "domain" => 53, "echo" => 7, "exec" => 512, "finger" => 79, "ftp" => 21,
                  "ftp-data" => 20, "gopher" => 70, "hostname" => 101, "irc" => 194, "klogin" => 543,
                  "kshell" => 544, "login" => 513, "lpd" => 515, "nntp" => 119, "pop2" => 109,
                  "pop3" => 110, "smtp" => 25, "sunrpc" => 111, "tacacs" => 49, "talk" => 517,
                  "telnet" => 23, "time" => 37, "uucp" => 540, "whois" => 43, "www" => 80 }.freeze

        private

        def any_address?(name, dimension: nil)
          expression = (dimension == :sources) ? /\A(?:any|any-ip)\z/i : /\A(?:any|all)\z/i
          expression.match?(name)
        end

        def port_number(value)
          return Integer(value, 10) if value&.match?(/\A\d+\z/)
          PORTS.fetch(value) { raise Algosec::Config::ParseError, "Unknown port name #{value.inspect}" }
        end

        # 收集块式配置，将需要网络或对象引用的命令留给后续阶段。
        def scan_document
          @port_groups, @nat_commands, @static_nat_interface_states = {}, [], {}
          @route_pref = STATIC_ROUTE_PREF
          index, @policies = 0, []
          while index < @lines.size
            line = @lines[index]
            words = tokens(line)
            if HEADERS.match?(line.text.strip)
              rows, index = block_at(index, terminator: /\A#/, stop: HEADERS)
              if words[0] == "acl" || words[0] == "object-policy"
                @policies << rows
              else
                object_block(words, rows)
              end
              next
            elsif words[0, 2] == %w[ip route-static]
              route_command(words.drop(2), line)
            elsif words == %w[undo ip route-static default-preference]
              @route_pref = STATIC_ROUTE_PREF
              consume(line)
            elsif words[0] == "time-range"
              schedule(words, line)
            elsif words[0, 2] == %w[nat static]
              @nat_commands << [ nil, line ]
            elsif words == [ "#" ]
              consume(line)
            end
            index += 1
          end
        end

        # 先发射地址池，再装配策略所需的对象引用。
        def parse_policies
          @drafts[:nat_pool].each_value { |object| emit_draft(:nat_pool, object) }
          validate_bindings
          @policies.each { |rows| policy(rows) }
          finish_object_policies
        end

        # 引用和规则就绪后生成 NAT，保留原配置的转换顺序。
        def parse_nat
          @nat_commands.each_with_index { |(header, line), id| nat(header, line, id) }
        end

        def object_block(words, rows)
          type, name = if words[0, 3] == %w[object-group ip address]
                         [ :address, words[3] ]
          elsif words[0] == "object-group"
                         [ (words[1] == "port") ? :port : :service_group, words[2] ]
          elsif words[0] == "interface"
                         [ :interface, interface_name(words.drop(1)) ]
          elsif words[0] == "security-zone"
                         [ :zone, words[2] ]
          elsif words[0] == "zone-pair"
                         [ :zone_pair, nil ]
          else
                         [ :nat_pool, (words[2] == "name") ? words[3] : words[2] ]
          end
          return if type == :nat_pool && name.to_s.empty?
          if type == :service_group && (words.size != 3 || name.to_s.empty?)
            diagnose(:invalid_service, "Service group header requires one name", rows.first)
            return
          end

          key = type == :service_group ? name.downcase : name || rows.first.index
          object = draft(type, key)
          object.attributes[:name] ||= name
          object.lines.concat(rows)
          object.attributes[:alias_name] = words[4] if type == :nat_pool && words[2] != "name" && words[3] == "name"
          rows.drop(1).each do |line|
            fields = tokens(line)
            recognized = case type
            when :address
                           case fields[0, 2]
                           when %w[network subnet]
                             (object.attributes[:member] ||= []) << address_leaf(ip_parts(fields[2], fields[3]).join("/")) if fields.size == 4
                             fields.size == 4
                           when %w[network range]
                             (object.attributes[:member] ||= []) << { type: "iprange", value: fields[2, 2].join(" ") } if fields.size == 4
                             fields.size == 4
                           when %w[network group-object]
                             (object.attributes[:references] ||= []) << fields[2] if fields.size == 3
                             fields.size == 3
                           when %w[network host]
                             valid = fields.size == 4 && fields[2] == "address" && fields[3].match?(/\A\d+\./)
                             (object.attributes[:member] ||= []) << address_leaf("#{fields[3]}/32") if valid
                             valid
                           end
            when :interface
                           interface_command(object, fields, line, rows.first)
            when :zone
                           bind_zone(interface_name(fields.drop(2)), name, line) if fields[0, 2] == %w[import interface]
            when :zone_pair
                           bind_policy(words, fields, rows.first, line)
            when :port
                           (@port_groups[name] ||= []) << fields.drop(1) if fields[0] == "port"
            when :service_group
                           service_command(object, fields, line)
            when :nat_pool
                           if fields[0] == "address" && fields.size == 3
                             (object.attributes[:ip] ||= []) << fields[1, 2].join(" ")
                             true
                           end
            end
            if fields[0] == "description"
              object.attributes[:description] = fields.drop(1).join(" ")
              recognized = true
            end
            consume(line) if recognized
          end
          object.attributes[:ip] ||= [] if type == :nat_pool
          if type == :zone_pair && !@catalog.any? { |element| element.is_a?(Algosec::Elements::RuleBinding) &&
            element.from_zone.casecmp?(words[3].to_s) && element.to_zone.casecmp?(words[5].to_s) }
            diagnose(:unsupported_policy_binding, "Zone pair has no supported policy binding; fallback is not proven", rows.first)
          end
        end

        # 一条应用命令对应一个区域对；同名策略的多个绑定不能互相覆盖。
        def bind_policy(header, words, first, line)
          unless header.size == 6 && header[0, 3] == %w[zone-pair security source] && header[4] == "destination"
            diagnose(:unsupported_policy_binding, "Invalid zone pair", first)
            return false
          end
          type, name = if words.size == 4 && words[0, 3] == %w[object-policy apply ip]
                         [ :object, words[3] ]
          elsif words[0] == "packet-filter" && ((words.size == 2 && words[1].match?(/\A\d+\z/)) || (words.size == 3 && words[1] == "name"))
                         [ :acl, words.last ]
          end
          return false unless type

          emit(:rule_binding, { rule_type: type, rule_set: name, from_zone: header[3], to_zone: header[5] }, [ first, line ])
          true
        end

        # 空策略也有声明；缺失引用和同一区域对的冲突不能由最后一条绑定掩盖。
        def validate_bindings
          declared = @policies.map do |rows|
            header = tokens(rows.first)
            [ header[0] == "acl" ? :acl : :object, policy_name(header).downcase ]
          end
          bindings = @catalog.select { |element| element.is_a?(Algosec::Elements::RuleBinding) }
          bindings.each do |binding|
            next if declared.include?([ binding.rule_type, binding.rule_set.downcase ])
            diagnose(:missing_reference, "Policy #{binding.rule_set}", @origins[binding.object_id])
          end
          bindings.group_by { |binding| [ binding.rule_type, binding.from_zone.downcase, binding.to_zone.downcase ] }.each_value do |group|
            next if group.map { |binding| binding.rule_set.downcase }.uniq.one?
            diagnose(:conflicting_policy_binding, "Zone pair has conflicting policy bindings", @origins[group.last.object_id])
          end
        end

        def policy_name(header)
          name = header[0] == "acl" && header[2] == "name" ? header[3] : header[2]
          raise ArgumentError, "Policy requires a name" if name.to_s.empty?
          name
        end

        # 接口类型和编号可连写或分写，声明、区域绑定及 NAT 引用使用同一名称。
        def interface_name(words)
          unless (words.one? && /\A[a-z][a-z-]*\d[\d\/.:-]*\z/i.match?(words.first)) ||
                 (words.size == 2 && /\A[a-z][a-z-]*\z/i.match?(words.first) && /\A\d[\d\/.:-]*\z/.match?(words.last))
            raise ArgumentError, "Interface requires a type and number"
          end
          words.join
        end

        def interface_command(object, fields, line, header)
          name = object.attributes.fetch(:name)
          if fields[0, 2] == %w[ip address]
            interface_address(object, fields, line, header)
          elsif (fields[0, 3] == %w[ip binding vpn-instance] && fields.size == 4) || fields == %w[undo ip binding vpn-instance]
            object.attributes[:vrf] = fields.first == "undo" ? Elements.default_vrf : vpn_name(fields.last)
            object.attributes.delete(:ipaddr)
            object.state.delete(:primary_route)
            @drafts[:route].delete_if { |_key, route| route.state[:connected] && route.attributes[:destination_interface] == name }
            true
          elsif fields == %w[nat static enable] || fields == %w[undo nat static enable]
            @static_nat_interface_states[name] = fields.first != "undo"
            true
          elsif fields[0] == "nat"
            @nat_commands << [ header, line ]
            # 登记待解析命令不代表已理解；未知 NAT 必须留给完整性诊断。
            false
          end
        rescue ArgumentError => error
          consume(line)
          diagnose(:invalid_interface, "Interface #{name}: #{error.message}", line)
        end

        # 主地址单独用于接口源地址；主、次地址各自声明直连网段。
        def interface_address(object, fields, line, header)
          return unless fields.size == 4 || (fields.size == 5 && fields.last == "sub")
          ip, mask = IPAddr.from_i(IPAddr.to_i(fields[2])), IPAddr.prefix_length(fields[3])
          address = IPAddr.host_cidr(ip, mask)
          secondary = fields.last == "sub"
          unless secondary
            previous = object.state[:primary_route]
            @drafts[:route].delete_if { |_key, route| route.equal?(previous) } if previous
            object.attributes[:ipaddr] = address
          end
          object.attributes[:mode] = :layer3
          route = connected_route(object, ip, mask, line, next_hop: ip)
          route.attributes.merge!(distance: 0, extra_conf: { "connected" => true })
          route.lines.unshift(header) unless route.lines.include?(header)
          object.state[:primary_route] = route unless secondary
          true
        end

        # 缺省 preference 只影响其后声明的路由；未知条件不能被丢弃后生成普通路由。
        def route_command(words, line)
          if words.first == "default-preference"
            raise ArgumentError, "Default preference requires one value" unless words.size == 2
            @route_pref = route_number(words.last, "preference", 1..255)
            consume(line)
          else
            capture(draft(:route, [ :static, line.index ], **route_fields(words)), line)
          end
        rescue ArgumentError => error
          consume(line)
          diagnose(:invalid_route, error.message, line)
        end

        def route_fields(words)
          rest = words.dup
          vrf = Elements.default_vrf
          if rest.first == "vpn-instance"
            rest.shift
            vrf = vpn_name(rest.shift)
          end
          address, mask = rest.shift(2)
          raise ArgumentError, "Route requires an IPv4 address and mask" unless address && mask
          subnet = IPAddr.network_cidr(IPAddr.from_i(IPAddr.to_i(address)), mask)
          attributes = { vrf: vrf, subnet: subnet, distance: @route_pref, extra_conf: {} }
          if rest.first == "vpn-instance"
            rest.shift
            attributes[:destination_vrf] = vpn_name(rest.shift)
          elsif rest.first&.match?(/\A[a-z]/i) && !%w[preference tag description track bfd permanent dhcp backup-interface ldp-sync public].include?(rest.first)
            count = /\A[a-z-]+\z/i.match?(rest.first) && rest[1]&.match?(/\A\d[\d\/.:-]*\z/) ? 2 : 1
            attributes[:destination_interface] = interface_name(rest.shift(count))
          end
          attributes[:next_hop] = IPAddr.from_i(IPAddr.to_i(rest.shift)) if rest.first&.match?(/\A\d/)
          if rest.first == "public" && attributes[:next_hop] && !attributes[:destination_interface] && !attributes[:destination_vrf]
            attributes[:destination_vrf] = Elements.default_vrf
            rest.shift
          end
          unless attributes[:destination_interface] || attributes[:next_hop] || attributes[:destination_vrf]
            raise ArgumentError, "Route requires an interface, next hop or destination VPN instance"
          end
          route_options(attributes, rest)
          attributes
        end

        def vpn_name(value)
          raise ArgumentError, "VPN instance name must contain 1 to 31 characters" unless value && (1..31).cover?(value.length)
          value
        end

        def route_options(attributes, rest)
          fields = {}
          until rest.empty?
            field = rest.shift
            raise ArgumentError, "Duplicate route field #{field}" if fields[field]
            fields[field] = true
            case field
            when "preference" then attributes[:distance] = route_number(rest.shift, field, 1..255)
            when "tag" then attributes[:extra_conf]["tag"] = route_number(rest.shift, field, 1..4_294_967_295)
            when "description"
              raise ArgumentError, "Route description is empty" if rest.empty?
              attributes[:description] = rest.join(" ")
              rest.clear
            else raise ArgumentError, "Unsupported route field #{field}"
            end
          end
        end

        # 先确定接口及直连路由的 VRF，再按全部直连网段定位静态路由出口。
        def finish_network
          @drafts[:interface].each_value { |object| object.attributes[:vrf] ||= Elements.default_vrf }
          @drafts[:route].each_value do |object|
            next unless object.state[:connected]
            attributes = object.attributes
            attributes[:vrf] = @drafts[:interface].fetch(attributes[:destination_interface]).attributes[:vrf]
          end
          @drafts[:route].each_value { |object| resolve_route_target(object) }
          super
        end

        # 出口已在草稿阶段解析，不能再次按首个匹配网段推断。
        def route_interface?(interface, attributes) = false

        def prepare_zone(object, members)
          vrfs = members.map(&:vrf).uniq
          object.attributes[:vrf] = vrfs.first if vrfs.one?
        end

        # 对象编号属于组内；同一编号重新定义时替换服务或引用，不累加旧条件。
        def service_command(object, words, line)
          rest = words.dup
          id = Integer(rest.shift, 10) if rest.first&.match?(/\A\d+\z/)
          return false unless rest.shift == "service"

          entries = object.state[:services] ||= {}
          id ||= entries.empty? ? 0 : (entries.keys.max / 10 + 1) * 10
          raise ArgumentError, "Service object ID must be in 0..4294967294" unless (0..4_294_967_294).cover?(id)
          entry = if rest.first == "group-object"
                    raise ArgumentError, "Service group reference requires one name" unless rest.size == 2 && !rest.last.empty?
                    rest.last
          else
                    service_term(rest).merge(term: id.to_s)
          end
          entries[id] = entry
          true
        rescue ArgumentError, Algosec::Config::ParseError => error
          diagnose(:invalid_service, "Service group #{object.attributes[:name]}: #{error.message}", line)
          true
        end

        # 完整消费条件；ICMP 的 type/code 沿用服务项的目的/源字段表示。
        def service_term(words)
          protocol = words.shift
          unless protocol&.match?(/\A(?:\d+|tcp|udp|icmp|icmpv6)\z/i)
            raise ArgumentError, "Service requires an IP protocol number or supported name"
          end
          number = IPAddr.protocol_number(protocol)
          raise ArgumentError, "Literal IP protocol 0 cannot be represented as any" if number.zero?
          protocol = { IPAddr::TCP => "tcp", IPAddr::UDP => "udp", IPAddr::ICMP => "icmp", IPAddr::ICMPV6 => "icmpv6" }.fetch(number, number.to_s)
          term = { protocol: protocol, source_port: ANY_SERVICE_PORTS, destination_port: ANY_SERVICE_PORTS }
          if [ IPAddr::TCP, IPAddr::UDP ].include?(number)
            fields = []
            until words.empty?
              field = words.shift
              unless %w[source destination].include?(field) && !fields.include?(field)
                raise ArgumentError, "Unknown or repeated service field #{field.inspect}"
              end
              fields << field
              count = { "eq" => 2, "lt" => 2, "gt" => 2, "range" => 3 }[words.first]
              raise ArgumentError, "Incomplete service port condition" unless count && words.size >= count
              port = port_condition(words.shift(count))
              range = IPAddr.ports(port).first
              term[:"#{field}_port"] = range.begin == range.end ? range.begin.to_s : "#{range.begin}-#{range.end}"
            end
          elsif IPAddr.icmp?(protocol) && !words.empty?
            unless words.size == 2 && words.all? { |value| /\A\d+\z/.match?(value) && (0..255).cover?(Integer(value, 10)) }
              raise ArgumentError, "ICMP requires a type and code in 0..255"
            end
            term[:destination_port], term[:source_port] = words.map { |value| Integer(value, 10).to_s }
          elsif !words.empty?
            raise ArgumentError, "Unsupported service protocol conditions"
          end
          term
        end

        # 直接定义留在内部叶子，命名引用交给公共解析器，保留依赖及缺失状态。
        def finish_services
          @drafts[:service_group].each_value do |object|
            entries = object.state.fetch(:services, {}).values
            references = entries.grep(String).uniq(&:downcase).to_h { |name| [ name, nil ] }
            terms = entries.grep(Hash)
            unless terms.empty?
              name = "#{object.attributes[:name]}:services"
              name += ":inline" while references.keys.any? { |reference| reference.casecmp?(name) }
              references[name] = Algosec::Elements::ServiceObject.new(**context, name: name, terms: terms)
            end
            object.attributes[:members] = references
          end
        end

        # H3C 服务名称不区分大小写，设备中的显式组优先于内建模板。
        def service(name)
          declared = @drafts[:service_group][name.downcase]
          return find(:service_group, declared.attributes.fetch(:name)) if declared

          @builtin_names ||= @builtin_templates.keys.group_by(&:downcase)
          names = @builtin_names.fetch(name.downcase, [])
          raise Algosec::Elements::Catalog::AmbiguousReference, "Built-in service #{name.inspect} has conflicting names" if names.size > 1
          builtin(names.first || name)
        end

        # 同名声明相加；周期保留星期与时段的配对，无法表达的交集或多绝对窗口保持未知。
        def schedule(words, line)
          object = capture(draft(:schedule, words[1], **schedule_attributes(name: words[1])), line)
          attributes = object.attributes.deep_dup
          if words.size == 8 && words[2] == "from" && words[5] == "to"
            raise ArgumentError, "Combined absolute and periodic ranges are not modeled" if attributes[:kind] == :weekly
            interval = { start_at: words[3, 2].join(" "), end_at: words[6, 2].join(" ") }
            if attributes[:start_at] && attributes.slice(:start_at, :end_at) != interval
              raise ArgumentError, "Multiple absolute ranges are not modeled"
            end
            attributes.merge!(interval).merge!(kind: :once)
          elsif words.size >= 6 && words[3] == "to" && !words.include?("from")
            raise ArgumentError, "Combined absolute and periodic ranges are not modeled" if attributes[:start_at]
            attributes[:kind] = :weekly
            periods = (attributes[:periods] ||= {})
            words.drop(5).each { |day| periods[day] = (periods.fetch(day, []) + [ words.values_at(2, 4) ]).uniq }
          else
            raise ArgumentError, "Unsupported time-range statement"
          end
          parsed = Algosec::Elements::Schedule.new(**context, **attributes)
          if (parsed.start_at && parsed.end_at && parsed.end_at < parsed.start_at) ||
             parsed.weekly_windows.values.flatten.any? { |period| period.begin > period.end }
            raise ArgumentError, "Schedule end precedes start"
          end
          object.attributes.replace(attributes)
        rescue ArgumentError => error
          object.attributes[:unparsed_commands] = object.lines.map { |source| source.text.strip }.uniq
          diagnose(:unsupported_schedule, "Schedule #{words[1]}: #{error.message}", line)
        end

        def policy(rows)
          tokens(rows.first).first == "acl" ? acl_policy(rows) : object_policy(rows)
        end

        # 绑定是规则的显示范围；执行时仍由 Policy 按精确区域对选择规则链。
        def policy_scope(type, name)
          bindings = @catalog.select do |element|
            element.is_a?(Algosec::Elements::RuleBinding) && element.rule_type == type && element.rule_set.casecmp?(name)
          end
          bindings.empty? ? {} : { from_zones: bindings.map(&:from_zone).uniq.sort, to_zones: bindings.map(&:to_zone).uniq.sort }
        end

        # ACL 使用原生编号排序；对象策略独立维护创建和移动顺序。
        def acl_policy(rows)
          header = tokens(rows.first)
          name = policy_name(header)
          options = header.drop(header[2] == "name" ? 4 : 3)
          known_order = options.empty? || options == %w[match-order config]
          diagnose(:unsupported_policy_order, "Policy header contains unmodeled options or match order", rows.first) unless known_order
          scope = policy_scope(:acl, name)
          rows.drop(1).each do |line|
            words = tokens(line)
            next unless words[0] == "rule" && words[1]&.match?(/\A\d+\z/)
            object = draft(:rule, [ :acl, name, words[1] ], **scope, rule_type: :acl, rule_set: name,
                           native_rule_id: words[1], rule_number: words[1], vendor_data: { acl_type: header[1] }, action: words[2])
            (object.attributes[:conditions] ||= {})[:unparsed_commands] = [ rows.first.text.strip ] unless known_order
            object.lines << rows.first unless object.lines.include?(rows.first)
            capture(object, line)
            clauses = acl_options(object, words.drop(header[1] == "basic" ? 3 : 4), line)
            %i[sources destinations].each do |dimension|
              keyword = (dimension == :sources) ? "source" : "destination"
              parts = clauses.fetch(keyword, [ "any" ])
              reference = if parts[0] == "object-group"
                            parts[1]
              elsif parts[0] == "any"
                            address_reference("any")
              else
                            mask = (parts[1] == "0") ? 32 : IPAddr.prefix_length(IPAddr.wildcard_mask(parts[1]))
                            literal_reference("#{parts[0]}/#{mask}", line)
              end
              (object.state[dimension] ||= []) << reference
            end
            protocol = (header[1] == "basic") ? "any" : words[3]
            sources = acl_ports(clauses["source-port"], line, default: nil)
            destinations = acl_ports(clauses["destination-port"], line, default: ANY_SERVICE_PORTS)
            sources.product(destinations).each do |source, destination|
              (object.state[:services] ||= []) << literal_service(protocol, destination, source_port: source)
            end
          end
        end

        # 同名块共享规则草稿，保留首次声明的名称拼写和按命令演进的顺序。
        def object_policy(rows)
          header = tokens(rows.first)
          chain = draft(:object_policy, policy_name(header).downcase)
          chain.attributes[:name] ||= policy_name(header)
          chain.state[:rules] ||= {}
          chain.state[:order] ||= []
          chain.state[:scope] ||= policy_scope(:object, chain.attributes.fetch(:name))
          if header.size != 3
            chain.state[:unknown_order] = true
            mark_unparsed_policy_line(chain, rows.first)
          end
          capture(chain, rows)
          rows.drop(1).each do |line|
            # comment 的尾部是自由文本，单引号和双引号不作为对象名转义解析。
            words = line.text.strip.split(/\s+/, 4)
            words = tokens(line) unless words.first == "description" || (words.first == "rule" && words[2] == "comment")
            if words.first == "rule"
              object_rule(chain, words.drop(1), line)
            elsif words[0, 2] == %w[move rule]
              move_object_rule(chain, words.drop(2), line)
            elsif words.empty? || words == [ "#" ] || words == [ "accelerate" ] || words == %w[undo accelerate] ||
                  (words.first == "description" && words.size > 1)
              next
            else
              chain.state[:unknown_order] = true
              mark_unparsed_policy_line(chain, line)
            end
          end
        end

        # 只有基础定义可创建规则；续行和注释必须引用当时已存在的编号。
        def object_rule(chain, words, line)
          id = words.first&.match?(/\A\d+\z/) ? words.shift.to_i : nil
          action = words.shift
          rules = chain.state.fetch(:rules)
          defining = %w[pass drop inspect].include?(action)
          if id.nil? && defining
            largest = rules.keys.max
            id = largest.nil? ? 0 : largest + 1
            id = (0..65534).find { |number| !rules.key?(number) } if id > 65534
          end
          unless id && (0..65534).cover?(id) && (defining || rules.key?(id))
            chain.state[:unknown_order] = true
            return mark_unparsed_policy_line(chain, line)
          end
          if defining && !rules.key?(id)
            name = chain.attributes.fetch(:name)
            rules[id] = draft(:rule, [ :object, name.downcase, id ], **chain.state.fetch(:scope),
                              rule_set: name, native_rule_id: id.to_s)
            rules[id].lines << chain.lines.first
            chain.state[:order] << id
          end
          object = rules.fetch(id)
          capture(object, line)
          case action
          when "pass", "drop"
            object.attributes[:action] = action
            update_object_rule(object, words, line)
          when "inspect"
            object.attributes[:action] = "inspect"
            mark_unparsed_policy_line(object, line)
          when "append"
            append_object_rule(object, words, line)
          when "comment"
            if words.empty?
              mark_unparsed_policy_line(object, line)
            else
              object.attributes[:description] = words.join(" ")
            end
          else
            mark_unparsed_policy_line(object, line)
          end
        end

        # 先完整读取一条定义，再覆盖显式字段；省略项保持原配置。
        def update_object_rule(object, words, line)
          fields = object_policy_fields(words)
          return mark_unparsed_policy_line(object, line) unless fields

          base = object.state[:base] ||= {}
          OBJECT_FIELDS.each_key do |field|
            next unless fields.key?(field)
            value = fields[field]
            # 同字段重新定义与已追加项的交互尚无充分固件证据，不能冒充完整匹配。
            appended = object.state.fetch(:appends, {}).fetch(field, [])
            if !appended.empty? && !value.casecmp?("any") && (base[field].nil? || !base[field].casecmp?(value))
              mark_unparsed_policy_line(object, line)
            end
            base[field] = value
          end
          object.attributes[:schedule_name] = fields["time-range"] if fields.key?("time-range")
          object.attributes[:status] = "disable" if fields.key?("disable")
          object.attributes.merge!(log: "logging", log_enabled: true) if fields.key?("logging")
        end

        # append 每行只增加一个命名对象，不能设置 any、时间或规则状态。
        def append_object_rule(object, words, line)
          field, value = words
          unless words.size == 2 && OBJECT_FIELDS.key?(field) && !value.to_s.empty? && !value.casecmp?("any")
            return mark_unparsed_policy_line(object, line)
          end
          appends = object.state[:appends] ||= {}
          (appends[field] ||= []) << value
        end

        # 编号定位和顺序分开；移动必须同时找到两端，65535 表示末尾。
        def move_object_rule(chain, words, line)
          valid = words.size == 3 && words[1] == "before" && [ words[0], words[2] ].all? { |word| /\A\d+\z/.match?(word) }
          id, target = words.values_at(0, 2).map { |word| word.to_i } if valid
          order = chain.state.fetch(:order)
          unless valid && id != target && order.include?(id) && (target == 65535 || order.include?(target))
            chain.state[:unknown_order] = true
            return mark_unparsed_policy_line(chain, line)
          end
          order.delete(id)
          target == 65535 ? order.push(id) : order.insert(order.index(target), id)
          capture(chain.state.fetch(:rules).fetch(id), line)
        end

        # 默认 any 在全部续行之后补齐，未指定的维度不会吞掉后续限制。
        def finish_object_policies
          @drafts[:object_policy].each_value do |chain|
            chain.state.fetch(:order).each_with_index do |id, index|
              object = chain.state.fetch(:rules).fetch(id)
              object.attributes[:rule_number] = index + 1 unless chain.state[:unknown_order]
              unknown = chain.attributes.dig(:conditions, :unparsed_commands)
              if unknown
                conditions = object.attributes[:conditions] ||= {}
                conditions[:unparsed_commands] = (Array(conditions[:unparsed_commands]) + unknown).uniq
              end
              OBJECT_FIELDS.each do |field, dimension|
                values = [ object.state.fetch(:base, {})[field], *object.state.fetch(:appends, {}).fetch(field, []) ].compact.uniq(&:downcase)
                values = [ "any" ] if values.empty? || values.any? { |value| value.casecmp?("any") }
                if dimension == :services && values == [ "any" ]
                  object.state[dimension] = [ literal_service("any") ]
                else
                  add_members(object, dimension, values, addresses: dimension != :services)
                end
              end
            end
          end
        end

        # 按字段元数消费，避免对象名称与关键字碰撞；不发布半条已解析定义。
        def object_policy_fields(words)
          fields = {}
          until words.empty?
            key = words.shift
            return nil if fields.key?(key)
            if %w[disable logging].include?(key)
              fields[key] = true
            elsif OBJECT_FIELDS.key?(key) || key == "time-range"
              value = words.shift
              return nil if value.to_s.empty?
              fields[key] = value
            else
              return nil
            end
          end
          fields
        end

        # 未知、重复或缺值字段保留在规则中，宽松解析也不能作无条件结论。
        def mark_unparsed_policy_line(object, line)
          conditions = object.attributes[:conditions] ||= {}
          conditions[:unparsed_commands] = (Array(conditions[:unparsed_commands]) + [ line.text.strip ]).uniq
          diagnose(:unsupported_rule_condition, "Object policy contains incomplete or unsupported fields", line)
        end

        # 逐项读取子句，名称里的关键字不参与分派；未建模的限制保留为诊断。
        def acl_options(object, words, line)
          clauses = {}
          until words.empty?
            keyword = words.shift
            count = case keyword
            when "source", "destination"
                      words.first == "any" ? 1 : 2
            when "source-port", "destination-port"
                      case words.first
                      when "eq", "lt", "gt", "object-group" then 2
                      when "range" then 3
                      end
            when "time-range" then 1
            when "logging", "flow-logging"
                      object.attributes[:log] = keyword
                      0
            when "counting" then 0
            end
            unless count && words.size >= count
              (object.attributes[:conditions] ||= {})[:unparsed_commands] = [ line.text.strip ]
              diagnose(:unsupported_rule_condition, "ACL contains unsupported match conditions", line)
              break
            end
            clauses[keyword] = words.shift(count)
            object.attributes[:schedule_name] = clauses[keyword].first if keyword == "time-range"
          end
          clauses
        end

        # 两侧端口使用相同语法，组只展开该维度；服务项再保存完整端口配对。
        def acl_ports(condition, line, default:)
          return [ default ] unless condition
          return [ port_condition(condition) ] unless condition[0] == "object-group"

          conditions = @port_groups[condition[1]]
          diagnose(:missing_reference, "Port group #{condition[1]}", line) unless conditions
          Array(conditions).map { |entry| port_condition(entry) }
        end

        def acl_sets(name, line, dimensions: %i[sources destinations services])
          return [ all_addresses, all_addresses, all_services ] unless name
          rules = @catalog.select { |element| element.is_a?(Algosec::Elements::SecurityRule) && element.native_rule_type == :acl && element.rule_set == name }
          diagnose(:missing_reference, "ACL #{name}", line) if rules.empty?
          unless rules.empty? || exact_acl_projection?(rules, dimensions: dimensions)
            diagnose(:conditional_nat_acl, "NAT ACL #{name} needs ordered rule and condition evaluation", line)
          end
          [ Set.new(*rules.flat_map { |rule| rule.sources.set.ranges }),
           Set.new(*rules.flat_map { |rule| rule.destinations.set.ranges }),
           Set.new(*rules.flat_map { |rule| service_projection(rule.services.ports).ranges }) ]
        end

        # 单条无条件 permit 的三维投影才是原谓词；多条规则会丢失配对及顺序。
        def exact_acl_projection?(rules, dimensions:)
          return false unless rules.one?
          rule = rules.first
          rule.action == "allow" && rule.status_known? && !rule.disabled? && !rule.schedule_name && !rule.schedule &&
            !rule.starts_at && !rule.expires_at && !rule.application_or_user_restricted? && rule.security_profiles.empty? && !rule.unparsed_commands? &&
            !rule.from_interface && rule.dst_interfaces.empty? && rule.from_vlans.empty? && rule.to_vlans.empty? &&
            rule.sources.resolved? && rule.destinations.resolved? && !rule.sources.conditional? && !rule.destinations.conditional? &&
            rule.services.resolved? && !rule.services.service_projection.dig(:resolution, "conditional") &&
            (%i[sources destinations services] - dimensions).all? do |dimension|
              rule.public_send(dimension).set == (dimension == :services ? all_services : all_addresses)
            end
        end

        def nat(header, line, id)
          words = tokens(line)
          return static_nat(words.drop(2), line) if words[0, 2] == %w[nat static]
          return unless header
          interface_name = interface_name(tokens(header).drop(1))
          interface = find(:interface, interface_name)
          unless interface
            diagnose(:missing_reference, "Interface #{interface_name}", line)
            return
          end
          attributes = { id: id, interface: interface.name }
          if words[0, 2] == %w[nat outbound]
            rest = words.drop(2)
            if rest.first == "name"
              return if rest[1].to_s.empty?
              acl = rest.slice!(0, 2).last
            elsif rest.first&.match?(/\A\d+\z/)
              acl = rest.shift
            end
            if rest.first == "address-group"
              pool_name = (rest[1] == "name") ? rest[2] : rest[1]
              return if pool_name.to_s.empty?
              rest.shift(rest[1] == "name" ? 3 : 2)
            end
            return unless rest.empty?

            pool = find(:nat_pool, pool_name)
            diagnose(:missing_reference, "NAT pool #{pool_name}", line) if pool_name && !pool
            attributes[:source_set], attributes[:destination_set], attributes[:service_set] = acl_sets(acl, line)
            attributes.merge!(direction: :source, to_zone: interface.zone, source_pool: pool,
                              translated_source_set: pool_name ? pool&.set : interface.host && IPAddr.parse(interface.host))
          elsif words[0, 2] == %w[nat server]
            rest = words.drop(2)
            protocol = rest.slice!(0, 2).last if rest[0] == "protocol"
            return unless rest.shift == "global" && rest.include?("inside")
            public = rest.shift(rest.index("inside"))
            rest.shift
            private = rest
            return if public.empty? || private.empty?

            attributes.merge!(direction: :destination, from_zone: interface.zone, source_set: all_addresses)
            [ [ public, :destination_set, :destination_port, :service_set ],
             [ private, :translated_destination_set, :translated_destination_port, :translated_service_set ] ].each do |parts, set_key, port_key, service_key|
              first = parts.shift
              last = parts.first&.include?(".") ? parts.shift : first
              attributes[set_key] = IPAddr.between(first, last)
              if protocol && parts.first&.match?(/\A\d+\z/)
                port = parts.shift
                attributes[port_key] = port
                attributes[service_key] = IPAddr.service("#{protocol}/#{port}")
              end
            end
            return unless public.empty?
            return if private[0] == "name" && private.size != 2
            return if private[0] != "name" && private.size > 1

            acl = (private[0] == "name") ? private[1] : private[0]
            attributes[:source_set] = acl_sets(acl, line, dimensions: [ :sources ])[0] if acl
          else
            return
          end
          emit(:dynamic_nat, attributes, [ header, line ])
          consume(line)
        end

        def static_nat(words, line)
          direction = words.shift
          return unless %w[inbound outbound].include?(direction)
          consume(line)
          if direction == "inbound"
            return diagnose(:unsupported_nat_direction, "Inbound static NAT translates external host aliases and is not modeled", line)
          end

          fields = static_nat_fields(words, line)
          return unless fields
          real, mapped, real_set, mapped_set, rest = fields
          options = static_nat_options(rest)
          return diagnose(:unsupported_nat_condition, "Static NAT contains incomplete or unsupported options", line) unless options
          if options[:acl_name] || options[:acl_number]
            return diagnose(:conditional_nat_acl, "Static NAT ACL requires forward and reverse connection checks", line)
          end

          interfaces = @static_nat_interface_states.filter_map { |name, enabled| name if enabled }.sort
          attributes = { real_ip: real, mapped_ip: mapped, real_set: real_set, mapped_set: mapped_set,
                         interfaces: interfaces, disabled: options.fetch(:disabled, false) || interfaces.empty?,
                         description: options[:description] }
          emit(:static_nat, attributes, [ line ])
        rescue ArgumentError => error
          diagnose(:invalid_nat, "Static NAT: #{error.message}", line)
        end

        # 主机、完整网段和对象引用分别解释；地址投影必须保持精确的一对一映射。
        def static_nat_fields(words, line)
          if words[0] == "net-to-net"
            first, last, target, network, mask = words.drop(1).first(5)
            unless target == "global" && [ first, last, network, mask ].all? { |value| !value.to_s.empty? }
              raise ArgumentError, "Net-to-net mapping requires a range and a global network"
            end
            raise ArgumentError, "NAT address range is reversed" if IPAddr.to_i(first) > IPAddr.to_i(last)
            prefix = IPAddr.prefix_length(mask)
            raise ArgumentError, "Net-to-net prefix must be between 8 and 31" unless (8..31).cover?(prefix)
            real, mapped = "#{first}-#{last}", IPAddr.network_cidr(network, prefix)
            real_set, mapped_set = IPAddr.between(first, last), IPAddr.parse(mapped)
            raise ArgumentError, "Net-to-net range cannot exceed 256 addresses" if real_set.cardinality > 256
            rest = words.drop(6)
          elsif words[0] == "object-group"
            unless words[2] == "object-group" && words[1] && words[3]
              raise ArgumentError, "Static NAT requires two address object groups"
            end
            real, mapped = words.values_at(1, 3)
            real_set, mapped_set = [ real, mapped ].map { |name| nat_group_set(name, line) }
            return unless real_set && mapped_set
            rest = words.drop(4)
          else
            raise ArgumentError, "Static NAT requires two host addresses" unless words.size >= 2
            real, mapped = words.first(2).map { |value| IPAddr.from_i(IPAddr.to_i(value)) }
            real_set, mapped_set = [ real, mapped ].map { |value| IPAddr.parse(value) }
            rest = words.drop(2)
          end
          unless real_set.cardinality == mapped_set.cardinality && [ real_set, mapped_set ].all? { |set| IPAddr.cidrs(set).one? }
            return diagnose(:unsupported_nat_range, "Static NAT requires equally sized complete subnets; partial network mapping is not modeled", line)
          end
          [ real, mapped, real_set, mapped_set, rest ]
        end

        # 设备要求一个主机或子网成员；组引用、排除项或多成员并集不能冒充该形态。
        def nat_group_set(name, line)
          group = find(:address, name)
          return diagnose(:missing_reference, "Static NAT address group #{name}", line) unless group
          unless group.resolved? && group.references.empty? && group.excluded_member.empty? && group.direct_member.one? &&
                 %w[host subnet].include?(group.direct_member.first.fetch("type"))
            return diagnose(:unsupported_nat_range, "Static NAT address group #{name} requires one host or subnet member", line)
          end
          group.set
        end

        # 只消费可无损表达的 NAT 选项；未知 VPN、优先级或反向匹配语义留给完整性诊断。
        def static_nat_options(words)
          options = {}
          index = 0
          while index < words.length
            case words[index]
            when "disable", "counting"
              key = (words[index] == "disable") ? :disabled : :counting
              return if options.key?(key)
              options[key] = true
              index += 1
            when "description"
              return if options.key?(:description) || words[index + 1].to_s.empty?
              options[:description] = words[index + 1]
              index += 2
            when "acl"
              return if options.key?(:acl_name) || options.key?(:acl_number)
              if words[index + 1] == "name" && !words[index + 2].to_s.empty?
                options[:acl_name] = words[index + 2]
                index += 3
              elsif words[index + 1]&.match?(/\A\d+\z/)
                options[:acl_number] = words[index + 1]
                index += 2
              else
                return
              end
            else
              return
            end
          end
          options
        end
      end
    end
  end
end
