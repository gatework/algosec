# frozen_string_literal: true

require "active_support/core_ext/object/deep_dup"
require_relative "../../config/parser"
require_relative "nat/action"
require_relative "nat/server"
require_relative "network_syntax"
require_relative "service_terms"

module Algosec
  module Vendors
    module Huawei
      # 解析 Huawei 对象、接口、路由、安全策略和 NAT。
      class Parser < Algosec::Config::Parser
        VENDOR = :huawei

        field :rule, "action", to: :action, convert: :rule_value
        field :rule, "time-range", to: :schedule_name, convert: :rule_value
        field :rule, "source-zone", to: :from_zones, convert: :rule_zones, merge: :union
        field :rule, "destination-zone", to: :to_zones, convert: :rule_zones, merge: :union

        stage :scan_document, using: :scan_document
        stage :finish_network, using: :finish_network
        stage :emit_objects, using: :emit_objects
        stage :parse_policies, using: :parse_policies
        stage :emit_rules, using: :emit_rules
        stage :rule_references, using: :resolve_references
        stage :parse_nat, using: :parse_nat
        HEADERS = /\A(?:interface |firewall zone |ip (?:address-set|service-set) |time-range |(?:nat|destination-nat) address-group |security-policy\z|nat-policy\z)/

        private

        # any 是原生任意服务关键字，不依赖外部预定义服务目录。
        def service(name)
          super || (literal_service("any").last if name == "any")
        end

        # 收集块式配置，将需要网络或对象引用的命令留给后续阶段。
        def scan_document
          index, @policies, @nats, @servers = 0, [], [], []
          @server_names = {}
          @set_types = {}
          @route_pref = NetworkSyntax::DEFAULT_PREF
          while index < @lines.size
            line = @lines[index]
            words = tokens(line)
            if HEADERS.match?(line.text.strip)
              # 策略内的 time-range 是规则引用，不能截断为全局时间对象。
              stop = %w[security-policy nat-policy].include?(words[0]) ? /\A(?!time-range )#{HEADERS}/o : HEADERS
              rows, index = block_at(index, terminator: /\A#/, stop: stop)
              if words[0] == "security-policy"
                @policies.concat(rule_blocks(rows.drop(1)))
              elsif words[0] == "nat-policy"
                @nats.concat(rule_blocks(rows.drop(1)))
                @servers.concat(rows.drop(1).select { |row| row.text.strip.start_with?("nat server ") })
              elsif %w[nat destination-nat].include?(words[0])
                nat_pool_block(words, rows)
              else
                object_block(words, rows)
              end
              next
            elsif words[0, 2] == %w[ip route-static]
              route_command(words.drop(2), line)
            elsif words[0, 2] == %w[nat server]
              @servers << line
            elsif words == [ "#" ] || line.text.include?("Software Version")
              consume(line)
            end
            index += 1
          end
        end

        # 先发射地址池，再装配策略所需的对象引用。
        def parse_policies
          @drafts[:nat_pool].each_value { |object| emit_draft(:nat_pool, object) }
          grouped_rules(@policies).each { |rows| policy(rows) }
        end

        # 引用和规则就绪后生成 NAT，保留原配置的转换顺序。
        def parse_nat
          grouped_rules(@nats).each { |rows| nat_policy(rows) }
          @servers.each { |line| nat_server(line) }
        end

        # 同名规则重开时先合并命令，再补默认条件，保留首次位置和全部来源行。
        def grouped_rules(blocks)
          blocks.group_by { |rows| tokens(rows.first)[2] }.values.map { |groups| groups.flatten }
        end

        def rule_blocks(rows)
          groups = []
          rows.each do |line|
            if /\Arule\s+name\s+/.match?(line.text.strip)
              diagnose(:unsupported_rule_header, "Huawei rule header has unsupported fields", line) unless tokens(line).size == 3
              groups << [ line ]
              consume(line)
            elsif !groups.empty? && !line.text.strip.start_with?("nat server ")
              groups.last << line
            end
          end
          groups
        end

        def object_block(words, rows)
          type, name = if words[0] == "interface"
                         [ :interface, NetworkSyntax.interface_name(words.drop(1)) ]
          elsif words[0, 2] == %w[firewall zone]
                         [ :zone, (words[2] == "name") ? words[3] : words[2] ]
          elsif %w[address-set service-set].include?(words[1]) && words[0] == "ip"
                         set_header(words, rows.first)
          elsif words[0] == "time-range"
                         if words.size == 2 && !words[1].empty?
                           [ :schedule, words[1] ]
                         else
                           diagnose(:invalid_schedule, "Time range header requires one name", rows.first)
                         end
          end
          return consume(rows) unless type

          attributes = { name: name }
          attributes = schedule_attributes(**attributes) if type == :schedule
          object = draft(type, name, **attributes)
          object.lines.concat(rows)
          rows.drop(1).each do |line|
            fields = tokens(line)
            recognized = case type
            when :interface
                           interface_command(object, fields, line, rows.first)
            when :zone
                           zone_command(name, fields, line)
            when :address
                           address_command(object, fields, line)
            when :service, :service_group
                           service_member(object, fields, line, type: type)
            when :schedule
                           schedule_command(object, fields, line)
            end
            if fields[0] == "description"
              object.attributes[:description] = fields.drop(1).join(" ")
              recognized = true
            end
            consume(line) if recognized
          end
        end

        # 对象和组共用命名空间；省略 type 只用于重开，不丢弃 VPN 或其他头部限定。
        def set_header(words, line)
          namespace, name = words[1, 2]
          raise ArgumentError, "Object set requires a non-reserved name" if name.to_s.empty? || %w[any all].include?(name.downcase)

          key = [ namespace, name ]
          rest = words.drop(3)
          kind = @set_types[key]
          unless rest.empty?
            unless rest.shift == "type" && %w[object group].include?(rest.first)
              raise ArgumentError, "Object set requires type object or group"
            end
            declared = rest.shift
            raise ArgumentError, "Object set cannot change type" if kind && kind != declared
            kind = declared
            rest.shift if rest.first&.match?(/\A\d+\z/)
            raise ArgumentError, "Unsupported object set header fields: #{rest.join(' ')}" unless rest.empty?
          end
          raise ArgumentError, "Object set must be declared before reopening it" unless kind

          @set_types[key] = kind
          type = namespace == "address-set" ? :address : (kind == "object" ? :service : :service_group)
          [ type, name ]
        rescue ArgumentError => error
          diagnose(:invalid_object_header, error.message, line)
          nil
        end

        def zone_command(name, fields, line)
          return unless fields[0, 2] == %w[add interface]

          bind_zone(NetworkSyntax.interface_name(fields.drop(2)), name, line)
        rescue ArgumentError => error
          diagnose(:invalid_interface, "Zone #{name}: #{error.message}", line)
          true
        end

        # VPN 绑定会清除接口三层地址；不能把旧网段带入新的路由域。
        def interface_command(object, fields, line, header)
          if fields[0, 2] == %w[ip address]
            interface_address(object, fields, line, header)
          elsif fields[0, 3] == %w[ip binding vpn-instance] && fields.size == 4
            object.attributes[:vrf] = NetworkSyntax.vpn_name(fields.last)
            object.attributes.delete(:ipaddr)
            object.state.delete(:primary_route)
            @drafts[:route].delete_if do |_key, route|
              route.state[:connected] && route.attributes[:destination_interface] == object.attributes[:name]
            end
            true
          end
        rescue ArgumentError => error
          diagnose(:invalid_interface, "Interface #{object.attributes[:name]}: #{error.message}", line)
          true
        end

        # 主地址用于接口源地址，次地址只增加直连网段；重开接口时替换旧主地址。
        def interface_address(object, fields, line, header)
          return unless fields.size == 4 || (fields.size == 5 && fields.last == "sub")

          ip, mask = NetworkSyntax.ipv4(fields[2]), IPAddr.prefix_length(fields[3])
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

        # 先确定全部接口和直连路由的 VRF，再按最长直连前缀解析静态路由出口。
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

        # 出口已由草稿解析；禁止公共阶段再按首个匹配接口猜测。
        def route_interface?(interface, attributes) = false

        def prepare_zone(object, members)
          vrfs = members.map(&:vrf).uniq
          object.attributes[:vrf] = vrfs.first if vrfs.one?
        end

        # 池的方向和原生编号属于声明；重开不重置模式，也不丢弃未知头部限定。
        def nat_pool_block(words, rows)
          attributes = nat_pool_header(words)
          name = attributes.fetch(:name)
          previous = @drafts[:nat_pool][name]&.attributes
          if previous && previous[:direction] != attributes[:direction]
            raise ArgumentError, "Source and destination NAT pools share the name #{name}"
          end
          if attributes[:id]
            if previous && previous[:id] && previous[:id] != attributes[:id]
              raise ArgumentError, "NAT pool #{name} has conflicting IDs"
            end
            if @drafts[:nat_pool].any? { |other_name, pool| other_name != name && pool.attributes.values_at(:direction, :id) == attributes.values_at(:direction, :id) }
              raise ArgumentError, "NAT pool ID #{attributes[:id]} is already assigned"
            end
          end
          object = draft(:nat_pool, name, **attributes)
          object.attributes[:mode] ||= "pat" if attributes[:direction] == :source
          object.attributes[:ip] ||= []
          object.lines.concat(rows)
          rows.drop(1).each { |line| nat_pool_command(object, tokens(line), line) }
        rescue ArgumentError => error
          diagnose(:invalid_nat_pool_header, error.message, rows.first)
          consume(rows)
        end

        def nat_pool_header(words)
          unless (3..4).cover?(words.size) && !words[2].empty? && (words.size == 3 || /\A\d+\z/.match?(words[3]))
            raise ArgumentError, "NAT pool header requires a name and an optional numeric ID"
          end
          attributes = { name: words[2], direction: words[0] == "nat" ? :source : :destination }
          attributes[:id] = Integer(words[3], 10).to_s if words.size == 4
          attributes
        end

        # 未建模的分配条件使整个池不可用于 NAT 装配；原文和已知地址仍可审阅。
        def nat_pool_command(object, fields, line)
          case fields.first
          when nil then nil
          when "description" then object.attributes[:description] = fields.drop(1).join(" ")
          when "section" then nat_pool_section(object, fields, line)
          when "mode"
            mode = fields.drop(1).join(" ")
            unless object.attributes[:direction] == :source && supported_nat_pool_mode?(mode)
              raise ArgumentError, "NAT pool mode #{mode.inspect} is not modeled for this direction"
            end
            object.attributes[:mode] = mode
          when "smart-nopat"
            raise ArgumentError, "Smart NAT allocation is not modeled"
          else
            raise ArgumentError, "Unsupported NAT pool command"
          end
          consume(line)
          true
        rescue ArgumentError => error
          object.state[:invalid] = true
          diagnose(:invalid_nat_pool, "NAT pool #{object.attributes[:name]}: #{error.message}", line)
          consume(line)
          true
        end

        def supported_nat_pool_mode?(mode)
          mode.nil? || [ "pat", "no-pat global" ].include?(mode)
        end

        # section 编号不能被丢弃；同编号的冲突和自动编号混用均不推定设备效果。
        def nat_pool_section(object, fields, line)
          id, addresses = member_fields(fields)
          raise ArgumentError, "NAT section requires one or two IPv4 addresses" unless (1..2).cover?(addresses.size)
          first, last = addresses.map { |address| NetworkSyntax.ipv4(address) }
          last ||= first
          raise ArgumentError, "NAT section is reversed" if IPAddr.to_i(first) > IPAddr.to_i(last)

          entry = first == last ? first : "#{first} #{last}"
          previous = object.state.dig(:members, id) unless id.nil?
          raise ArgumentError, "NAT section #{id} has conflicting ranges" if previous && previous != entry

          object.attributes[:ip] = store_member(object, id, entry, line)
        end

        def ipv4_address?(value)
          /\A(?:\d{1,3}\.){3}\d{1,3}\z/.match?(value) && IPAddr.new(value).ipv4?
        rescue ArgumentError
          false
        end

        # 编号属于当前对象；先校验完整成员，再替换叶子或引用并重建两类投影。
        def address_command(object, fields, line)
          return unless fields[0] == "address"

          id, rest = member_fields(fields)
          entry = if rest[0] == "range" && rest.size == 3
                    first, last = rest.drop(1).map { |value| NetworkSyntax.ipv4(value) }
                    raise ArgumentError, "Address range is reversed" if IPAddr.to_i(first) > IPAddr.to_i(last)
                    { type: "iprange", value: "#{first}-#{last}" }
          elsif rest[0] == "address-set" && rest.size == 2 && !rest[1].empty?
                    unless @set_types[[ "address-set", object.attributes[:name] ]] == "group"
                      raise ArgumentError, "Only an address group can reference another address set"
                    end
                    rest[1]
          elsif rest.size == 3 && rest[1] == "mask"
                    address_leaf(NetworkSyntax.ipv4(rest[0]), rest[2])
          else
                    raise ArgumentError, "Unsupported address member"
          end
          entries = store_member(object, id, entry, line)
          object.attributes[:member] = entries.grep(Hash)
          object.attributes[:references] = entries.grep(String).uniq
          true
        rescue ArgumentError => error
          (object.attributes[:unresolved] ||= []) << line.text.strip
          diagnose(:invalid_address, "Address #{object.attributes[:name]}: #{error.message}", line)
          true
        end

        # 服务对象与组使用同一编号更新规则，引用不会累加被同编号替换的旧服务。
        def service_member(object, fields, line, type:)
          return unless fields[0] == "service"

          id, rest = member_fields(fields)
          if (index = rest.drop(2).index("description"))
            index += 2
            raise ArgumentError, "Service member description is empty" if rest.drop(index + 1).join(" ").empty?
            rest = rest.take(index)
          end
          entry = if type == :service && rest.first == "protocol"
                    ServiceTerms.new(rest.drop(1)).terms
          elsif type == :service_group && rest.size == 2 && rest.first == "service-set" && !rest.last.empty?
                    rest.last
          else
                    raise ArgumentError, "Service member does not match its object or group type"
          end
          entries = store_member(object, id, entry, line)
          if type == :service
            object.attributes[:terms] = entries.flatten
          else
            object.attributes[:members] = entries.uniq.to_h { |name| [ name, nil ] }
          end
          true
        rescue ArgumentError => error
          diagnose(:invalid_service, "Service #{object.attributes[:name]}: #{error.message}", line)
          true
        end

        def member_fields(fields)
          rest = fields.drop(1)
          id = Integer(rest.shift, 10) if rest.first&.match?(/\A\d+\z/)
          [ id, rest ]
        end

        # 未编号条目可累加；混用显式编号时，不能猜测设备自动分配的编号。
        def store_member(object, id, entry, line)
          members = (object.state[:members] ||= {})
          explicit = !id.nil?
          if members.keys.any? { |key| key.is_a?(Integer) != explicit }
            raise ArgumentError, "Mixed explicit and automatic member IDs are not modeled"
          end
          members[id || [ :automatic, line.index ]] = entry
          members.values
        end

        # 时间条件先在副本中校验；未知组合保留到对象中，不能覆盖成另一种已知窗口。
        def schedule_command(object, fields, line)
          return if fields.empty? || fields.first == "description"

          attributes = object.attributes.deep_dup
          case fields.first
          when "absolute-range"
            unless fields.size == 6 && fields[3] == "to"
              raise ArgumentError, "Absolute range requires two complete date/time values"
            end
            raise ArgumentError, "Combined absolute and periodic ranges are not modeled" if attributes[:kind] == :weekly
            interval = { start_at: fields[1, 2].join(" "), end_at: fields[4, 2].join(" ") }
            if attributes[:start_at] && attributes.slice(:start_at, :end_at) != interval
              raise ArgumentError, "Multiple absolute ranges are not modeled"
            end
            attributes.merge!(interval).merge!(kind: :once)
          when "period-range"
            unless fields.size >= 5 && fields[2] == "to"
              raise ArgumentError, "Periodic range requires two clocks and weekdays"
            end
            raise ArgumentError, "Combined absolute and periodic ranges are not modeled" if attributes[:start_at]
            clocks = fields.values_at(1, 3)
            unless clocks.all? { |value| /\A(?:[01]?\d|2[0-3]):[0-5]\d\z/.match?(value) }
              raise ArgumentError, "Periodic clocks require minute precision; second precision is not modeled"
            end
            if clocks.map { |clock| clock.split(":").map(&:to_i) }.then { |first, last| (first <=> last).positive? }
              raise ArgumentError, "Periodic range is reversed"
            end
            attributes[:kind] = :weekly
            periods = (attributes[:periods] ||= {})
            fields.drop(4).each { |day| (periods[day] ||= []) << clocks }
          else
            raise ArgumentError, "Unsupported schedule command"
          end
          schedule = Algosec::Elements::Schedule.new(**context, **attributes)
          if schedule.start_at && schedule.end_at && schedule.end_at < schedule.start_at
            raise ArgumentError, "Schedule end precedes start"
          end
          object.attributes.replace(attributes)
          true
        rescue ArgumentError => error
          (object.attributes[:unparsed_commands] ||= []) << line.text.strip
          diagnose(:invalid_schedule, "Schedule #{object.attributes[:name]}: #{error.message}", line)
          true
        end

        # 命名引用可有多个；内联项保留完整源端口，供安全策略和 NAT 共用。
        def service_refs(words, line)
          raise ArgumentError, "Service reference is missing" if words.empty?
          return words unless words.first == "protocol"

          ServiceTerms.new(words.drop(1)).terms.map do |term|
            key = "#{term.fetch(:protocol)}/#{term.fetch(:destination_port)}:source/#{term.fetch(:source_port)}"
            [ key, Algosec::Elements::ServiceObject.new(**context, name: key, **term) ]
          end
        rescue ArgumentError => error
          diagnose(:invalid_service, error.message, line)
        end

        def route_command(words, line)
          if words.first == "default-preference"
            raise ArgumentError, "Default preference requires one value" unless words.size == 2
            @route_pref = NetworkSyntax.preference(words.last)
            consume(line)
          else
            attributes = NetworkSyntax.route_fields(words, preference: @route_pref)
            capture(draft(:route, [ :static, line.index ], **attributes), line)
          end
        rescue ArgumentError => error
          consume(line)
          diagnose(:invalid_route, error.message, line)
        end

        def address_expression(words)
          if %w[address-set address-group].include?(words[0]) && words.size == 2
            words[1]
          elsif words[0] == "range" && words.size == 3 && words.drop(1).all? { |value| ipv4_address?(value) }
            return if IPAddr.parse(words[1]).min > IPAddr.parse(words[2]).min
            words[1, 2].join("-")
          elsif ipv4_address?(words[0].to_s) && ((1..2).cover?(words.size) || (words.size == 3 && words[1] == "mask"))
            ip_parts(words[0], (words[1] == "mask") ? words[2] : words[1]).join("/")
          elsif words == [ "any" ]
            "any"
          end
        end

        def rule_value(values)
          raise ArgumentError, "Huawei rule field requires one value" unless values.one?
          values.first
        end

        def rule_zones(values)
          raise ArgumentError, "Huawei rule zone is missing" if values.empty?
          values
        end

        def policy(rows)
          name = tokens(rows.first)[2]
          object = draft(:rule, name, name: name)
          # 重开同名规则追加成员时保留首次位置，不把后续更新当成规则移动。
          object.attributes[:rule_number] ||= @drafts[:rule].size - 1
          object.lines.concat(rows)
          rows.drop(1).each do |line|
            fields = tokens(line)
            next if fields == [ "rule", "name", name ]
            next if map_field(:rule, object, fields[0], fields.drop(1), line)
            recognized = case fields[0]
            when "source-address", "destination-address"
                           dimension = (fields[0] == "source-address") ? :sources : :destinations
                           object.state[dimension] ||= []
                           expression = address_expression(fields.drop(1))
                           if expression
                             if %w[address-set address-group].include?(fields[1]) || expression == "any"
                               add_members(object, dimension, [ expression ], addresses: true)
                             else
                               object.state[dimension] << literal_reference(expression, line)
                             end
                           end
            when "service"
                           refs = service_refs(fields.drop(1), line)
                           (object.state[:services] ||= []).concat(refs) if refs
                           true
            when "description" then object.attributes[:description] = fields.drop(1).join(" ")
            when "disable" then object.attributes[:status] = "disable" if fields.one?
            end
            consume(line) if recognized
          end
          %i[sources destinations].each { |dimension| add_members(object, dimension, [ "any" ], addresses: true) unless object.state.key?(dimension) }
          add_members(object, :services, [ "any" ]) unless object.state.key?(:services)
          object.attributes[:from_zones] ||= [ "any" ]
          object.attributes[:to_zones] ||= [ "any" ]
        end

        def nat_policy(rows)
          attributes = { name: tokens(rows.first)[2], rule_set: "nat-policy", references: [] }
          actions, valid = [], true
          rows.drop(1).each do |line|
            next if line.text.blank?
            words = tokens(line)
            next if words == [ "rule", "name", attributes[:name] ]
            recognized = case words[0]
            when "source-zone" then nat_selector(attributes, :from_zone, words.drop(1))
            when "destination-zone" then nat_selector(attributes, :to_zone, words.drop(1))
            when "egress-interface" then nat_selector(attributes, :interface, words.drop(1))
            when "source-address", "destination-address"
                           nat_address(attributes, words, line)
            when "service" then nat_services(attributes, words.drop(1), line)
            when "description" then attributes[:description] = words.drop(1).join(" ")
            when "disable"
                           raise ArgumentError, "NAT disable has unsupported fields" unless words.size == 1
                           attributes[:extra_conf] = { "disabled" => true }
            when "action"
                           actions << [ Nat::Action.new(words.drop(1)), line ]
                           true
            end
            valid &&= !!recognized
            consume(line) if recognized
          rescue ArgumentError => error
            code = words[0] == "action" ? :unsupported_nat_action : :unsupported_nat_condition
            diagnose(code, error.message, line)
            consume(line)
            valid = false
          end
          return unless valid
          if actions.empty?
            diagnose(:unsupported_nat_action, "NAT rule #{attributes[:name]} has no supported translation action", rows.first)
            return
          end
          directions = actions.map { |action, _line| action.direction }
          if directions.uniq.size != directions.size
            diagnose(:duplicate_nat_action, "NAT rule #{attributes[:name]} repeats an action direction", rows.first)
            return
          end
          %i[source_set destination_set].each { |key| attributes[key] ||= all_addresses }
          # 原生匹配条件与 Easy-IP 推导出的出口信息分开保存。
          attributes[:extra_conf] ||= {}
          attributes[:extra_conf]["match"] = { "to_zone" => attributes[:to_zone], "interface" => attributes[:interface] }
          if attributes[:interface]
            interface = nat_interface(attributes, rows.first)
            return unless interface
            attributes[:to_zone] ||= interface.zone
            attributes[:vrf] = interface.vrf
          end
          # 先装配目的转换，源 Easy-IP 才能用转换后的目标确定出口。
          actions.sort_by { |action, _line| action.direction == :destination ? 0 : 1 }.each do |action, line|
            attributes = nat_policy_action(attributes, action, line)
            return unless attributes
          end
          attributes[:direction] = directions.one? ? directions.first : :bidirectional
          attributes.delete(:pool_name) unless directions.one?
          # 同条规则的两个动作共同命中；目的和双向策略先于纯源策略。
          attributes[:nat_order] = [ directions.include?(:destination) ? 0 : 1, actions.map { |_action, line| line.index }.max ]
          emit(:dynamic_nat, attributes, rows)
        end

        # 当前公共 NAT 模型使用单区域、单接口；多值不能被末项悄悄覆盖。
        def nat_selector(attributes, field, values)
          values = [ NetworkSyntax.interface_name(values) ] if field == :interface
          unless values.one? && (!attributes.key?(field) || attributes[field] == values.first)
            raise ArgumentError, "Huawei NAT #{field} requires one unambiguous value"
          end
          if field != :interface && values.first != "any" && !nat_zone(values.first)
            raise ArgumentError, "Huawei NAT zone #{values.first} is missing"
          end
          attributes[field] = values.first
        end

        def nat_zone(name)
          return if name.nil? || name == "any"
          candidates = @catalog.select { |element| element.is_a?(Algosec::Elements::Zone) && element.name.casecmp?(name) }
          raise ArgumentError, "Huawei NAT zone #{name} is ambiguous" if candidates.size > 1
          candidates.first
        end

        def nat_address(attributes, words, line)
          expression = address_expression(words.drop(1))
          raise ArgumentError, "Unsupported NAT address condition" unless expression
          set = lookup_address_set(expression, line)
          return unless set

          key = words[0] == "source-address" ? :source_set : :destination_set
          attributes[key] = (attributes[key] || Set.new) | set
          if %w[address-set address-group].include?(words[1])
            object = find(:address, expression) || find(:address_group, expression)
            attributes[:references] |= [ object ] if object
          end
          true
        end

        # 服务范围供快速筛选，原对象保留源端口、嵌套引用和条件元数据。
        def nat_services(attributes, words, line)
          refs = service_refs(words, line)
          return unless refs
          objects = refs.map do |ref|
            object = ref.is_a?(Array) ? ref.last : service(ref)
            diagnose(:missing_reference, "NAT service #{ref}", line) unless object
            object
          end
          return if objects.any?(&:nil?)
          projections = objects.map(&:service_projection)
          unless projections.all? { |projection| projection[:resolution]["complete"] }
            return diagnose(:missing_reference, "NAT service contains unresolved members", line)
          end
          attributes[:service_set] = projections.reduce(attributes[:service_set] || Set.new) do |set, projection|
            set | Set.new(*projection[:range].map { |first, last| first..last })
          end
          attributes[:references] |= objects
          true
        end

        # 动作逐项装配到同一候选；保留两个转换目标，不发射半条双向策略。
        def nat_policy_action(conditions, action, line)
          attributes = conditions.merge(direction: action.direction)
          case action.target
          when "address-group"
            pool = find(:nat_pool, action.value)
            return diagnose(:missing_reference, "NAT pool #{action.value}", line) unless pool
            if @drafts[:nat_pool].fetch(pool.name).state[:invalid] || pool.direction != action.direction || !supported_nat_pool_mode?(pool.mode) || pool.set.empty?
              return diagnose(:unsupported_nat_pool, "NAT pool #{pool.name} has unresolved conditions, a conflicting direction, mode or empty range", line)
            end
            translated = pool.set
            attributes[:pool_name] = pool.name
          when "address"
            translated = IPAddr.parse(action.value)
          when "easy-ip"
            interface = easy_ip_interface(attributes, line)
            return unless interface
            translated = IPAddr.parse(interface.host)
            attributes.merge!(interface: interface.name, to_zone: attributes[:to_zone] || interface.zone, vrf: interface.vrf)
          end
          if action.direction == :source
            attributes[:extra_conf]["source_mode"] = action.target
            attributes[:source_pool] = pool
            attributes[:translated_source_set] = translated
          else
            attributes[:destination_pool] = pool
            attributes[:translated_destination_set] = translated
            if action.port
              service = nat_translated_service(attributes, action.port, line)
              return unless service
              attributes[:translated_destination_port] = action.port
              attributes[:translated_service] = service
              attributes[:translated_service_set] = service.set
            end
          end
          attributes
        end

        # 端口转换沿用完整匹配项的协议和源端口，不能固定成 TCP 或补成任意协议。
        def nat_translated_service(attributes, port, line)
          services = attributes[:references].select { |object| object.is_a?(Algosec::Elements::ServiceObject) || object.is_a?(Algosec::Elements::ServiceGroup) }
          terms = services.flat_map { |service| service.service_projection[:member] }
          unless terms.any? && terms.all? { |term| ServiceTerms::PORT_PROTOCOLS.include?(IPAddr.protocol_number(term[:protocol])) }
            return diagnose(:unsupported_nat_service, "NAT destination port requires explicit transport services", line)
          end
          Algosec::Elements::ServiceObject.new(**context, name: "#{attributes[:name]}:translated",
            terms: terms.map { |term| term.merge(destination_port: port) })
        end

        def nat_interface(attributes, line)
          interface = find(:interface, attributes[:interface])
          return diagnose(:missing_interface, "NAT interface #{attributes[:interface]} is missing", line) unless interface
          zone = attributes[:to_zone]
          if zone && zone != "any" && !interface.zone&.casecmp?(zone)
            return diagnose(:conflicting_nat_zone, "NAT interface #{interface.name} is outside destination zone #{zone}", line)
          end
          interface
        end

        # Easy-IP 使用出口主地址；区域只有一个接口或整段条件有唯一路由时才推导。
        def easy_ip_interface(attributes, line)
          if attributes[:interface]
            interface = nat_interface(attributes, line)
          else
            zone = nat_zone(attributes[:to_zone])
            members = zone&.interfaces&.values || []
            destination = attributes[:translated_destination_set] || attributes[:destination_set]
            interface = members.one? ? members.first : egress_interface(attributes[:source_set], destination, vrf: zone&.vrf)
            if interface && attributes[:to_zone] && attributes[:to_zone] != "any" && !interface.zone&.casecmp?(attributes[:to_zone])
              return diagnose(:conflicting_nat_zone, "Easy-IP route leaves a different zone", line)
            end
          end
          return diagnose(:missing_interface, "Easy-IP needs one egress interface with a known primary IP", line) unless interface&.host
          interface
        end

        def nat_server(line)
          server = Nat::Server.new(tokens(line).drop(2)) { |name| find(:interface, name) }
          if @server_names[server.name]
            return diagnose(:duplicate_nat_server, "Huawei NAT server #{server.name} is repeated", line)
          end
          @server_names[server.name] = true
          if server.unresolved_reverse?
            diagnose(:unsupported_nat_server_reverse, "Huawei protocol-specific NAT server reverse conditions need version evidence", line)
          end
          emit(server.type, server.attributes, [ line ])
        rescue Nat::Server::Error => error
          diagnose(error.code, error.message, line)
        ensure
          consume(line)
        end
      end
    end
  end
end
