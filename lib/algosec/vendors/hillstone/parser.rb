# frozen_string_literal: true

require "active_support/core_ext/object/deep_dup"
require_relative "../../config/parser"

module Algosec
  module Vendors
    module Hillstone
      # 解析 StoneOS 块状配置、对象、策略、路由和 NAT。
      class Parser < Algosec::Config::Parser
        VENDOR = :hillstone

        field :rule, "action", to: :action
        field :rule, "name", to: :name
        field :rule, "src-zone", to: :from_zones, convert: :values, merge: :union
        field :rule, "dst-zone", to: :to_zones, convert: :values, merge: :union

        stage :clock_context, using: :clock_context
        stage :scan_document, using: :scan_document
        stage :network_context, using: :network_context
        stage :finish_network, using: :finish_network
        stage :emit_objects, using: :emit_objects
        stage :aggregate_rules, using: :aggregate_rules
        stage :rule_zones, using: :finalize_rule_zones
        stage :emit_rules, using: :emit_rules
        stage :rule_references, using: :resolve_references
        stage :policy_routes, using: :emit_policy_routes
        stage :parse_nat, using: :parse_nat

        private

        # 仅关注已建表对象及影响其解释的路由、时间和策略上下文。
        def diagnostic_line?(line)
          @diagnostic_lines&.include?(line.index) || line.text.match?(/\Aclock zone(?:\s|\z)/)
        end

        # 管理服务、链路监控和区域防护没有对应的数据投影。
        def ancillary_command?(type, fields)
          case type
          when :interface then %w[manage bandwidth mirror lacp].include?(fields[0])
          when :zone then %w[ad type].include?(fields[0]) || (fields[0] == "bind" && fields[1] != "pbr-policy")
          when :rule then fields == %w[assistant enable]
          else false
          end
        end

        # 先读取设备声明的时区，使计划与规则失效时间共用设备本地时间。
        def clock_context
          @lines.each do |line|
            next unless line.text.strip.match?(/\Aclock zone\s/)
            words = tokens(line)
            zone = { "china" => "Asia/Shanghai", "utc" => "UTC", "gmt" => "UTC" }[words[2]&.downcase]
            next unless words.size == 3 && zone
            @time_zone = Time.find_zone!(zone)
            consume(line)
          end
        end

        # 分阶段解析网络、对象和策略，最后装配引用并发射 NAT。
        # 收集块式配置，将需要网络或对象引用的命令留给后续阶段。
        def scan_document
          index = 0
          policy = {}
          vrf = nil
          @nat_lines = []
          @pbr_policies, @pbr_bindings = {}, []
          @diagnostic_lines = ::Set.new
          unsupported_scope = false
          while index < @lines.size
            line = @lines[index]
            if line.text.match?(/\A\S/)
              unsupported_scope = line.text.match?(/\A(?:domain-book|natpool)(?:\s|\z)/)
            end
            if unsupported_scope
              @diagnostic_lines.add(line.index) unless line.text.strip == "exit"
              index += 1
              next
            end
            if line.text.match?(/\Apbr-policy(?:\s|\z)/)
              rows = [ line ]
              index += 1
              while index < @lines.size
                rows << @lines[index]
                index += 1
                break if rows.last.text == "exit"
              end
              @diagnostic_lines.merge(rows.map(&:index))
              parse_pbr(rows)
              next
            end
            # access-address-pool 等未建模块内部也使用 address 关键字；
            # 只有无缩进的 address 才是 StoneOS 地址对象定义。
            if line.text.match?(/\A\s+(?:address|interface|zone|service|servgroup|schedule)(?:\s|\z)/)
              index += 1
              next
            end
            # 未建模的设置可能包含多行带引号的界面数据。
            # 保留原文，不把它们解释为命令行语法。
            unless /\A(?:interface|zone|address|service|servgroup|schedule|rule|policy|exit|ip|bind|pbr-match|bnatrule|snatrule|dnatrule)(?:\s|\z)/.match?(line.text.lstrip)
              index += 1
              next
            end
            words = tokens(line)
            if %w[interface zone address service servgroup schedule].include?(words[0]) || words[0, 2] == %w[rule id]
              rows, index = block_at(index, terminator: /\Aexit\z/, include_end: true)
              @diagnostic_lines.merge(rows.map(&:index))
              parse_block(words, rows, policy)
              next
            elsif words[0, 2] == %w[policy from] && words[3] == "to"
              policy = { from_zones: [ words[2] ], to_zones: [ words[4] ] }
              consume(line)
            elsif words == [ "exit" ]
              policy = {}
              vrf = nil
              consume(line)
            elsif words[0, 2] == %w[ip vrouter]
              vrf = words[2]
              consume(line)
            elsif words[0, 2] == %w[bind pbr-policy] && vrf
              register_pbr_binding(:vrouter, vrf, words, line)
            elsif words[0] == "pbr-match"
              @diagnostic_lines.add(line.index)
            elsif words[0, 2] == %w[ip route]
              @diagnostic_lines.add(line.index)
              route_command(line, words.drop(2), vrf: vrf)
            elsif %w[bnatrule snatrule dnatrule].include?(words[0])
              @diagnostic_lines.add(line.index)
              @nat_lines << [ line, vrf ]
            end
            index += 1
          end
        end

        # 引用和规则就绪后生成 NAT，保留原配置的转换顺序。
        def parse_nat
          @nat_lines.each { |line, vrf| nat_command(line, tokens(line), vrf: vrf) }
        end

        def parse_block(words, rows, policy)
          body = rows.drop(1).reject { |line| line.text.strip == "exit" || line.text.blank? }
          # StoneOS 先输出空预声明，再输出实际定义；空地址不能成为查询对象。
          return if words[0] == "address" && body.empty?

          name = (words[0] == "rule") ? words[2] : words[1]
          type = { "interface" => :interface, "zone" => :zone, "address" => :address,
                   "service" => :service, "servgroup" => :service_group, "schedule" => :schedule, "rule" => :rule }.fetch(words[0])
          rule_number = @drafts[:rule][name]&.attributes&.fetch(:rule_number, nil) || @drafts[:rule].size
          attributes = (type == :rule) ? { native_rule_id: name, rule_number: rule_number, **policy } : { name: name }
          attributes[:mode] = :transparent if type == :zone && words[2] == "l2"
          attributes = schedule_attributes(**attributes) if type == :schedule
          object = draft(type, name, **attributes)
          # 追加成员的规则块没有 log 命令时，保留先前已解析的日志状态。
          object.attributes[:log_enabled] = false if type == :rule && !object.attributes.key?(:log_enabled)
          object.lines.concat(rows)
          body.each do |line|
            begin
              fields = tokens(line)
            rescue Algosec::Config::ParseError => error
              raise unless type == :schedule
              (object.attributes[:unparsed_commands] ||= []) << line.text.strip
              diagnose(:invalid_schedule, error.message, line)
              consume(line)
              next
            end
            if ancillary_command?(type, fields)
              @diagnostic_lines.delete(line.index)
              next
            end
            recognized = case type
            when :interface
                           if fields[0, 2] == %w[ip address]
                             ip, mask = ip_parts(fields[2], fields[3])
                             object.attributes[:ipaddr] = IPAddr.host_cidr(ip, mask) unless fields.include?("secondary") && object.attributes[:ipaddr]
                             object.attributes[:mode] = :layer3
                             connected_route(object, ip, mask, line, next_hop: ip).attributes[:extra_conf] = { "connected" => true }
                           elsif fields == %w[ipv6 enable]
                             object.attributes[:mode] = :layer3
                           elsif fields[0, 2] == %w[ipv6 address] && fields.size == 3
                             value = validated_ipv6(fields[2], line, host: true)
                             (object.attributes[:ipv6_addresses] ||= []) << value if value
                             object.attributes[:mode] = :layer3
                           elsif fields[0] == "aggregate" && fields.size == 2
                             object.attributes[:aggregate] = fields[1]
                           elsif fields[0, 2] == %w[bind pbr-policy]
                             register_pbr_binding(:interface, name, fields, line)
                           elsif fields[0] == "zone"
                             bind_zone(name, fields[1], line, record_zone: false)
                           end
            when :zone
                           if fields[0] == "vrouter"
                             object.attributes[:vrf] = fields[1]
                           elsif fields[0, 2] == %w[bind pbr-policy]
                             register_pbr_binding(:zone, name, fields, line)
                           end
            when :address
                           case fields[0]
                           when "ip"
                             if fields[1].include?(":")
                               value = validated_ipv6(fields[1], line)
                               (object.attributes[:member] ||= []) << { type: "ipv6", value: value } if value
                             else
                               (object.attributes[:member] ||= []) << address_leaf(fields[1])
                             end
                             true
                           when "range"
                             ipv6 = fields[1].include?(":")
                             value = fields[1, 2].join(ipv6 ? "-" : " ")
                             value = validated_ipv6(value, line) if ipv6
                             (object.attributes[:member] ||= []) << { type: ipv6 ? "ipv6" : "iprange", value: value } if value
                             true
                           when "host"
                             (object.attributes[:member] ||= []) << { type: "domain", value: fields[1] }
                             true
                           when "member" then (object.attributes[:references] ||= []) << fields[1]
                           when "exclude"
                             if fields[1] == "ip" && fields.size == 3 && !fields[2].include?(":")
                               (object.attributes[:excluded_member] ||= []) << address_leaf(fields[2])
                             elsif fields[1] == "range" && fields.size == 4 && fields[2, 2].none? { |value| value.include?(":") }
                               (object.attributes[:excluded_member] ||= []) << { type: "iprange", value: fields[2, 2].join("-") }
                             end
                           when "reference-zone" then object.attributes[:zone] = fields[1]
                           end
            when :service
                           if fields[0] == "protocol" && fields.size == 2
                             add_term(object, fields[1], ANY_SERVICE_PORTS)
                           elsif fields[1] == "dst-port"
                             split = fields.index("src-port") || fields.size
                             destination = fields[2...split].join("-")
                             source_port = fields[split + 1..]&.join("-")
                             add_term(object, fields[0], destination, source_port)
                           elsif fields[0] == "icmp"
                             add_term(object, "icmp", NONZERO_SERVICE_PORTS)
                           end
            when :service_group
                           (object.attributes[:members] ||= {})[fields[1]] = nil if fields[0] == "service"
                           fields[0] == "service"
            when :schedule then validated_schedule_command(object, fields, line)
            when :rule then rule_command(object, fields, line)
            end
            if fields[0] == "description"
              object.attributes[:description] = fields.drop(1).join(" ")
              recognized = true
            end
            if type == :rule && !recognized
              ((object.attributes[:conditions] ||= {})["unparsed_commands"] ||= []) << line.text.strip
            end
            if type == :schedule && !recognized
              (object.attributes[:unparsed_commands] ||= []) << line.text.strip
              unless @diagnostics.any? { |entry| entry.code == :invalid_schedule && entry.line_number == line.number }
                diagnose(:unsupported_schedule, "Unsupported schedule entry: #{line.text.strip}", line)
              end
              consume(line)
            end
            consume(line) if recognized
          end
        end

        # 坏地址只诊断当前行，保留其他有效对象继续入库。
        def validated_ipv6(value, line, host: false)
          host ? IPv6.canonical(value, host: true) : IPv6.normalize(value)
        rescue ArgumentError => error
          diagnose(:invalid_address, error.message, line)
          nil
        end

        def add_term(object, protocol, destination, source_port = nil)
          (object.attributes[:terms] ||= []) << { protocol: protocol, destination_port: destination, source_port: source_port }
        end

        # 先在独立草稿中校验；异常仅标记当前计划，不能污染已解析窗口。
        def validated_schedule_command(object, fields, line)
          candidate = Draft.new(object.attributes.deep_dup, [], object.state.dup)
          return false unless schedule_command(candidate, fields)
          if candidate.state[:periodic] && candidate.state[:monthly]
            candidate.attributes[:kind] = candidate.state[:absolute] ? :mixed : :periodic
          end
          attributes = candidate.attributes
          if attributes[:start_at] && attributes[:end_at]
            schedule = Algosec::Elements::Schedule.new(**context, **attributes)
            raise ArgumentError, "Schedule end precedes start" if schedule.end_at < schedule.start_at
          else
            Algosec::Elements::Schedule.new(**context, **attributes)
          end
          object.attributes.replace(attributes)
          object.state.replace(candidate.state)
          true
        rescue ArgumentError => error
          diagnose(:invalid_schedule, error.message, line)
          false
        end

        def schedule_command(object, fields)
          if fields[0] == "absolute"
            return false unless (fields.size == 7 && fields[1] == "start" && fields[4] == "end") ||
                                (fields.size == 4 && fields[1] == "end")
            return false if object.state[:absolute]
            object.state[:absolute] = true
            object.attributes[:kind] = (object.state[:periodic] || object.state[:monthly]) ? :mixed : :once
            object.attributes[:start_at] = fields[fields.index("start") + 1, 2].join(" ") if fields.include?("start")
            object.attributes[:end_at] = fields[fields.index("end") + 1, 2].join(" ") if fields.include?("end")
          elsif fields[0] == "periodic" && (index = fields.index("to"))
            return monthly_schedule_command(object, fields) if %w[day-range day-in-month].include?(fields[1])
            if fields.size == 6 && index == 3
              return weekly_span(object, fields)
            end
            return false unless index >= 3 && fields.size == index + 2
            object.state[:periodic] = true
            clocks = fields.values_at(index - 1, index + 1).map { |clock| clock&.sub(/\A(\d{1,2}:\d{2}):00\z/, '\1') }
            return false unless clocks.all? { |clock| clock.match?(/\A(?:[01]?\d|2[0-3]):[0-5]\d\z/) }
            return false if clocks.map { |clock| clock.split(":").map(&:to_i) }.then { |first, last| (first <=> last).positive? }
            object.attributes[:kind] = object.state[:absolute] ? :mixed : :weekly
            periods = (object.attributes[:periods] ||= {})
            fields[1...(index - 1)].each { |day| (periods[day] ||= []) << clocks }
          end
        end

        # 每月连续日期窗口与按月指定日期均保留为独立周期条目。
        def monthly_schedule_command(object, fields)
          periods = if fields[1] == "day-range" && fields.size == 7 && fields[4] == "to"
            [ { start_day: Integer(fields[2], 10), start_time: fields[3], end_day: Integer(fields[5], 10), end_time: fields[6] } ]
          elsif fields[1] == "day-in-month" && fields.size == 6 && fields[4] == "to"
            fields[2].split(",", -1).map do |day|
              { start_day: Integer(day, 10), start_time: fields[3], end_day: Integer(day, 10), end_time: fields[5] }
            end
          else
            return false
          end
          object.state[:monthly] = true
          object.attributes[:kind] = object.state[:absolute] ? :mixed : :monthly
          (object.attributes[:monthly_periods] ||= []).concat(periods)
          true
        end

        # 每周连续时段按每天拆开保存，避免把结束星期误当成时钟。
        def weekly_span(object, fields)
          days = %w[sunday monday tuesday wednesday thursday friday saturday]
          first, last = [ fields[1], fields[4] ].map { |day| days.index(day.downcase) }
          return false unless first && last
          clocks = fields.values_at(2, 5).map { |value| value.sub(/\A(\d{1,2}:\d{2}):00\z/, '\1') }
          return false unless clocks.all? { |value| value.match?(/\A(?:[01]?\d|2[0-3]):[0-5]\d\z/) }
          minutes = clocks.map { |clock| clock.split(":").map(&:to_i).then { |hour, minute| hour * 60 + minute } }
          return false if first == last && minutes.first > minutes.last
          object.state[:periodic] = true
          object.attributes[:kind] = object.state[:absolute] ? :mixed : :weekly
          periods = (object.attributes[:periods] ||= {})
          length = (last - first) % 7
          (0..length).each do |offset|
            day = days[(first + offset) % 7]
            (periods[day] ||= []) << [ offset.zero? ? clocks.first : "00:00", offset == length ? clocks.last : "23:59" ]
          end
          true
        end

        def rule_command(object, fields, line)
          if %w[src-zone dst-zone].include?(fields[0])
            return false if fields.size < 2
            key = fields[0] == "src-zone" ? :from_zones : :to_zones
            unless object.state[fields[0]]
              object.attributes[key] = []
              object.state[fields[0]] = true
            end
          end
          return true if map_field(:rule, object, fields[0], fields.drop(1), line)
          case fields[0]
          when "av", "ips", "url"
            ((object.attributes[:conditions] ||= {})["security_profiles"] ||= {})[fields[0]] = fields.drop(1).join(" ")
          when "log"
            logs = (object.state[:logs] ||= [])
            logs << fields.drop(1).join(" ")
            object.attributes[:log] = logs.uniq.join("\n")
            object.attributes[:log_enabled] = true
          when "application"
            return false unless fields.size == 2
            applications = (object.state[:applications] ||= [])
            applications << fields[1]
            (object.attributes[:conditions] ||= {})["application_check"] = applications.uniq.join("\n")
            true
          when "expire-time", "start-time"
            return false unless fields.size == 3
            begin
              instant = Algosec::Elements::Schedule.new(**context, **schedule_attributes(name: "rule-time"))
                                                   .parse_time(fields.drop(1).join(" "))
            rescue ArgumentError => error
              diagnose(:invalid_rule_time, error.message, line)
              consume(line)
              return false
            end
            key = fields[0] == "start-time" ? "starts_at" : "expires_at"
            (object.attributes[:conditions] ||= {})[key] = instant.iso8601
          when "aggregate-type"
            return false unless fields.size == 1
            (object.attributes[:vendor_data] ||= {})["aggregate_type"] = "container"
          when "aggregate-rule"
            return false unless fields.size == 2 && fields[1].match?(/\A\d+\z/)
            (object.attributes[:vendor_data] ||= {})["aggregate_rule_id"] = fields[1]
          when "src-addr", "dst-addr"
            return false unless fields.size == 2
            add_members(object, (fields[0] == "src-addr") ? :sources : :destinations, [ fields[1] ], addresses: true)
          when "src-host", "dst-host"
            return false unless fields.size == 2
            dimension = fields[0] == "src-host" ? :sources : :destinations
            address = Algosec::Elements::AddressObject.new(**context, name: fields[1], member: [ { type: "domain", value: fields[1] } ])
            address.resolve_domains!(@dns_resolver) if @dns_resolver
            (object.state[dimension] ||= []) << [ fields[1], address ]
            unless DomainName.exact?(fields[1]) || DomainName.wildcard?(fields[1])
              diagnose(:unsupported_domain_pattern, "Unsupported domain expression: #{fields[1]}", line)
            end
            true
          when "src-ip", "dst-ip", "src-range", "dst-range"
            expected_size = fields[0].end_with?("range") ? 3 : 2
            return false unless fields.size == expected_size
            dimension = fields[0].start_with?("src") ? :sources : :destinations
            expression = fields[0].end_with?("range") ? fields[1, 2].join("-") : fields[1]
            (object.state[dimension] ||= []) << literal_reference(expression, line)
          when "service-rule"
            destination_index = fields.index("dst-port")
            source_index = fields.index("src-port")
            if !fields[1] || !destination_index || !fields[destination_index + 1]
              diagnose(:unsupported_command, "Incomplete service-rule: #{fields.join(" ")}", line)
              false
            else
              destination = fields[destination_index + 1..(source_index ? source_index - 1 : -1)].join("-")
              source = source_index && fields[(source_index + 1)..].join("-")
              object.state[:services] ||= []
              object.state[:services] << literal_service(fields[1], destination, source_port: source)
              true
            end
          when "service"
            return false unless fields.size == 2
            add_members(object, :services, [ fields[1] ])
          when "schedule" then object.attributes[:schedule_name] = fields[1]
          when "disable" then object.attributes[:status] = "disable"
          when "exit" then true
          end
        end

        # 导出顺序必须保持分组成员连续；无法证明顺序时保留诊断。
        # 容器的禁用状态影响成员，但不覆盖成员自身的状态。
        def aggregate_rules
          current_group = nil
          @drafts[:rule].each_value do |object|
            data = object.attributes[:vendor_data] || {}
            if data["aggregate_type"] == "container"
              current_group = object.attributes[:native_rule_id]
              next
            end
            group_id = data["aggregate_rule_id"]
            unless group_id
              current_group = nil
              next
            end
            parent = @drafts[:rule][group_id]
            if parent&.attributes&.dig(:vendor_data, "aggregate_type") != "container" || current_group != group_id
              diagnose(:unsupported_aggregate, "Unresolved aggregate or member order: #{group_id}", object.lines.first)
              ((object.attributes[:conditions] ||= {})["unparsed_commands"] ||= []) << "aggregate-rule #{group_id}"
              next
            end
            data["aggregate_status"] = parent.attributes.fetch(:status, "enable")
          end
        end

        # StoneOS 省略方向表示不限区域；只在完整规则装配后填充，避免覆盖显式区域。
        def finalize_rule_zones
          @drafts[:rule].each_value do |object|
            %i[from_zones to_zones].each do |key|
              values = Array(object.attributes[key])
              object.attributes[key] = values.empty? ? [ "any" ] : values.map { |value| value.casecmp?("any") ? "any" : value }.uniq
            end
          end
        end

        def network_context
          @drafts[:interface].each_value { |object| inherit_aggregate_zone(object, []) }
          @drafts[:interface].each_value do |object|
            zone = @drafts[:zone][object.attributes[:zone]]
            object.attributes[:vrf] ||= zone&.attributes&.fetch(:vrf, nil)
          end
        end

        # 物理成员沿聚合接口继承安全域，不把聚合成员误存成 VLAN。
        def inherit_aggregate_zone(object, path)
          parent_name = object.attributes[:aggregate]
          return unless parent_name
          if path.include?(object.attributes[:name])
            diagnose(:invalid_aggregate, "Circular interface aggregate: #{parent_name}", object.lines.first)
            return
          end
          parent = @drafts[:interface][parent_name]
          unless parent
            diagnose(:missing_reference, "Aggregate interface #{parent_name}", object.lines.first)
            return
          end
          inherit_aggregate_zone(parent, path + [ object.attributes[:name] ])
          zone = parent.attributes[:zone]
          if object.attributes[:zone] && object.attributes[:zone] != zone
            diagnose(:conflicting_zone, "Aggregate #{parent_name} and member have different zones", object.lines.first)
            return
          end
          bind_zone(object.attributes[:name], zone, object.lines.first, record_zone: false) if zone
          object.attributes[:vrf] ||= parent.attributes[:vrf]
        end

        # PBR 分组可先空声明再补规则；规则顺序使用导出次序而不是设备 ID。
        def parse_pbr(rows)
          fields = tokens(rows.first)
          return unless fields.size == 4 && fields[2] == "vrouter"
          policy = (@pbr_policies[fields[1]] ||= { vrf: fields[3], rules: {}, lines: [] })
          if policy[:vrf] != fields[3]
            policy[:conditions] ||= {}
            policy[:conditions][rows.first.number.to_s] = "Conflicting PBR vrouter: #{fields[3]}"
            diagnose(:conflicting_pbr_vrf, "PBR #{fields[1]} is declared in multiple vrouters", rows.first)
          end
          policy[:lines].concat(rows)
          consume(rows.first)
          current = nil
          rows.drop(1).each do |line|
            fields = tokens(line)
            if fields == [ "exit" ]
              current&.lines&.push(line)
              current = nil
              consume(line)
              next
            end
            next if fields.empty?
            if fields[0, 2] == %w[match id] && fields.size == 3
              current = (policy[:rules][fields[2]] ||= Draft.new({ id: fields[2] }, [], {}))
              current.lines << line
              consume(line)
              next
            end
            next unless current
            current.lines << line
            key = { "src-addr" => :sources, "dst-addr" => :destinations, "service" => :services }[fields[0]]
            if key && fields.size == 2
              (current.attributes[key] ||= []) << fields[1]
            elsif fields[0] == "nexthop" && fields.size == 2
              previous = current.attributes[:next_hop]
              if previous && previous != fields[1]
                conditions = current.attributes[:conditions] ||= {}
                conditions[line.number.to_s] = line.text.strip
                diagnose(:conflicting_pbr_next_hop, "PBR #{policy[:vrf]}/#{current.attributes[:id]} has conflicting next hops", line)
              else
                current.attributes[:next_hop] = fields[1]
              end
            elsif fields == [ "disable" ]
              current.attributes[:disabled] = true
            elsif fields == %w[log enable]
              current.attributes[:log] = "enable"
            elsif fields[0] == "description"
              current.attributes[:description] = fields.drop(1).join(" ")
            else
              (current.attributes[:conditions] ||= {})[line.number.to_s] = line.text.strip
              diagnose(:unsupported_pbr_condition, "PBR #{policy[:vrf]}/#{current.attributes[:id]}: #{line.text.strip}", line)
            end
            consume(line)
          end
        end

        def register_pbr_binding(type, name, fields, line)
          return false unless fields.size == 3
          @pbr_bindings << { policy: fields[2], type: type.to_s, name: name, line: line }
          consume(line)
          true
        end

        # 解析对象后再装配 PBR，地址集合沿用对象引用与 DNS 有效期。
        def emit_policy_routes
          @pbr_bindings.each do |binding|
            diagnose(:missing_reference, "PBR policy #{binding[:policy]}", binding[:line]) unless @pbr_policies.key?(binding[:policy])
          end
          @pbr_policies.each do |name, policy|
            bindings = @pbr_bindings.select { |binding| binding[:policy] == name }
            policy[:rules].each_value.with_index do |object, sequence|
              fields = object.attributes
              groups = %i[sources destinations services].to_h do |dimension|
                names = fields.fetch(dimension, [ "Any" ]).uniq
                klass = dimension == :services ? Algosec::Elements::ServiceGroup : Algosec::Elements::AddressGroup
                group = klass.new(**context, name: "pbr/#{name}/#{fields[:id]}/#{dimension}")
                names.each do |reference|
                  target = if dimension == :services
                    reference.casecmp?("any") ? literal_service("ip", ANY_SERVICE_PORTS).last : service(reference)
                  elsif any_address?(reference)
                    address_reference(reference).last
                  else
                    find(:address, reference) || find(:address_group, reference)
                  end
                  diagnose(:missing_reference, "PBR #{name}: #{reference}", object.lines.first) unless target
                  group.add(reference, target)
                end
                [ dimension, group ]
              end
              hop = fields[:next_hop]
              unless hop
                diagnose(:invalid_pbr, "PBR #{name}/#{fields[:id]} has no next hop", object.lines.first)
              end
              target = find(:interface, hop)
              unless target || hop.nil?
                begin
                  address = IPAddr.parse(hop)
                  route = @catalog.select { |item| item.is_a?(Algosec::Elements::Route) && !item.policy? && item.vrf == policy[:vrf] }
                                  .sort_by { |item| -item.prefix }.find { |item| item.covers?(address) }
                  target = find(:interface, route&.destination_interface)
                rescue ArgumentError
                  diagnose(:missing_reference, "PBR next-hop interface #{hop}", object.lines.first)
                end
              end
              metadata = { "policy" => name, "rule_id" => fields[:id], "sequence" => sequence,
                          "bindings" => bindings.map { |binding| binding.slice(:type, :name).stringify_keys },
                          "sources" => fields.fetch(:sources, [ "Any" ]), "destinations" => fields.fetch(:destinations, [ "Any" ]),
                          "services" => fields.fetch(:services, [ "Any" ]),
                          "conditions" => policy.fetch(:conditions, {}).merge(fields.fetch(:conditions, {})) }
              extra = { "pbr" => metadata, "disabled" => fields.fetch(:disabled, false), "log" => fields[:log] }.compact
              source = groups[:sources].member.map { |leaf| leaf.fetch("value") }.join(",")
              emit(:route, { name: "#{name}/#{fields[:id]}", kind: :policy, vrf: policy[:vrf], source: source,
                            source_interface: bindings.one? && bindings.first[:type] == "interface" ? bindings.first[:name] : nil,
                            next_hop: hop, destination_interface: target&.name, zone: target&.zone, priority: sequence,
                            description: fields[:description], extra_conf: extra, **groups },
                   [ policy[:lines].first, *object.lines, policy[:lines].last ])
            end
          end
        end

        def route_interface?(interface, attributes)
          attributes[:vrf].nil? || interface.vrf == attributes[:vrf]
        end

        def prepare_route(object, target)
          object.attributes[:vrf] ||= target&.vrf
        end

        def route_command(line, rest, vrf:)
          attributes = { vrf: vrf }
          if rest[0] == "source"
            rest.shift
            attributes[:kind] = :policy
            attributes[:source_interface] = rest.slice!(0, 2).last if rest[0] == "in-interface"
            attributes[:source] = rest.shift if rest.first&.match?(/\A\d+\./)
          end
          if rest.first&.match?(/\A\d+\./)
            attributes[:subnet] = IPAddr.network_cidr(rest.shift)
          end
          attributes[:subnet] ||= "0.0.0.0/0"
          attributes[:destination_interface] = rest.shift if rest.first&.match?(/\A[a-z]/i)
          attributes[:next_hop] = rest.shift
          return if attributes[:destination_interface].to_s.empty? && attributes[:next_hop].to_s.empty?

          capture(draft(:route, [ :route, line.index ], **attributes), line)
        end

        def nat_command(line, words, vrf:)
          return unless words[1] == "id" && !words[2].to_s.empty?

          id = words[2]
          if words[0] == "bnatrule" && words[3] == "virtual" && words[6] == "real"
            mapped, real = words.values_at(5, 8)
            return if mapped.to_s.empty? || real.to_s.empty?

            mapped_set, real_set = [ mapped, real ].map { |value| lookup_address_set(value, line) }
            return unless mapped_set && real_set
            emit(:static_nat, { id: id, mapped_ip: mapped, real_ip: real, mapped_set: mapped_set, real_set: real_set, log_enabled: words.drop(9).include?("log") }, [ line ])
          elsif %w[snatrule dnatrule].include?(words[0]) && words[3] == "from" && words.include?("trans-to")
            source_name, source_end = nat_operand(words, 4)
            return if source_name.to_s.empty?

            to_index = words.each_index.find { |index| index >= source_end && words[index] == "to" }
            return unless to_index
            destination_name, = nat_operand(words, to_index + 1)
            return if destination_name.to_s.empty?

            source_set = lookup_address_set(source_name, line)
            destination_set = lookup_address_set(destination_name, line)
            service_index = words.index("service")
            service_name = words[service_index + 1] if service_index
            return if service_index && service_name.to_s.empty?

            service_set = /\Aany\z/i.match?(service_name.to_s) ? all_services : lookup_service_set(service_name, line)
            rest = words.drop(words.index("trans-to") + 1)
            target, = nat_operand(rest, 0)
            return if target.to_s.empty?

            interface_name = words[words.index("eif") + 1] if words.include?("eif")
            egress = interface_name ? find(:interface, interface_name) : egress_interface(source_set, destination_set, vrf: vrf)
            diagnose(:missing_reference, "Interface #{interface_name}", line) if interface_name && !egress
            translated = if target == "eif-ip"
              egress&.host && IPAddr.parse(egress.host)
            else
              lookup_address_set(target, line)
            end
            service_object = service(service_name) if service_name
            protocol = service_object&.protocol || "any"
            nat_type = words[words.index("mode") + 1] if words.include?("mode")
            attributes = { name: id, id: id, direction: (words[0] == "snatrule") ? :source : :destination,
                           source_set: source_set, destination_set: destination_set, service_set: service_set,
                           service: service_object, protocol: protocol, destination_ip: destination_name,
                           nat_type: nat_type, vrf: vrf, interface: interface_name, log_enabled: rest.include?("log"),
                           extra_conf: { "mode" => nat_type, "disabled" => rest.include?("disable"),
                                         "sticky" => rest.include?("sticky") }.compact }
            if attributes[:direction] == :source
              attributes[:translated_source_set] = translated
              attributes[:to_zone] = egress&.zone
              attributes[:interface] ||= egress&.name if target == "eif-ip"
              attributes[:translated_source_port] = rest[rest.index("port") + 1] if rest.include?("port")
            else
              attributes[:translated_destination_set] = translated
              attributes[:translated_destination_ip] = target
              if rest.include?("port")
                port = rest[rest.index("port") + 1]
                attributes[:translated_destination_port] = port
                if service_set && !service_set.empty? && service_set != all_services
                  # 端口转换保留全部协议，不能把多项服务或服务组缩成第一个协议。
                  ports = service_object.ports.transform_values { IPAddr.ports(port) }
                  attributes[:translated_service_set] = service_projection(ports)
                end
              end
            end
            emit(:dynamic_nat, attributes, [ line ])
          else
            return
          end
          consume(line)
        end

        def nat_operand(words, index)
          return [ words[index + 1], index + 2 ] if %w[address-book ip].include?(words[index])

          [ words[index], index + 1 ]
        end
      end
    end
  end
end
