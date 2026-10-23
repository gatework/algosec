# frozen_string_literal: true

require_relative "../../config/parser"

module Algosec
  module Vendors
    module Fortinet
      # 解析 FortiOS 分层配置，包括 vdom、对象、策略和 NAT。
      class Parser < Algosec::Config::Parser
        VENDOR = :fortinet

        field :route, "device", to: :destination_interface, convert: :first
        field :route, "output-device", to: :destination_interface, convert: :first
        field :route, "input-device", to: :source_interface, convert: :first
        field :route, "gateway", to: :next_hop, convert: :first
        field :route, "distance", to: :distance, convert: :first
        field :route, "priority", to: :priority, convert: :first
        field :address, "associated-interface", to: :zone, convert: :join
        field :address, "comment", to: :description, convert: :join
        field :rule, "action", to: :action, convert: :first
        field :rule, "status", to: :status, convert: :first
        field :rule, "name", to: :name, convert: :first
        field :rule, "comments", to: :description, convert: :join

        stage :network, using: :parse_network
        stage :finish_network, using: :finish_network
        stage :objects, using: :parse_objects
        stage :emit_objects, using: :emit_objects
        stage :policies, using: :parse_policies
        stage :emit_rules, using: :emit_rules
        stage :rule_references, using: :resolve_references
        stage :policy_nat, using: :policy_nat
        Node = Struct.new(:words, :line, :children, :closing) do
          def lines = [ line, *children.flat_map { |child| child.is_a?(Node) ? child.lines : child }, closing ].compact

          def source_lines = lines.reject { |row| row.equal?(closing) }
        end
        SECTIONS = {
          %w[system interface] => :interface, %w[system zone] => :zone,
          %w[router static] => :route, %w[router policy] => :route,
          %w[firewall address] => :address, %w[firewall addrgrp] => :address_group,
          %w[firewall vipgrp] => :address_group, %w[firewall service custom] => :service,
          %w[firewall service group] => :service_group, %w[firewall schedule recurring] => :schedule,
          %w[firewall schedule onetime] => :schedule, %w[firewall ippool] => :nat_pool,
          %w[firewall vip] => :vip, %w[firewall policy] => :rule
        }.freeze

        # 将保存设置中的 VDOM 归一到构造参数，显式参数由公共入口优先覆盖。
        def self.options(settings)
          { vdom: settings[:vdom] || settings["vdom"] || "root" }
        end

        # 保存目标 vdom，其他原文和装配选项交给公共 Parser。
        def initialize(vdom: "root", **options)
          super(**options)
          @vdom = vdom.to_s.freeze
        end

        def parsing_settings = { "vdom" => @vdom }.freeze

        private

        # FortiOS 的 VDOM 在公共网络模型中统一映射为 VRF。
        def finish_network
          @drafts[:interface].each_value do |object|
            object.attributes[:vrf] = @vdom
            next if object.attributes[:zone]
            # 未加入显式区域的接口，本身就是 FortiOS 策略的匹配边界。
            name = object.attributes.fetch(:name)
            bind_zone(name, name, object.lines.first, record_zone: false)
          end
          super
        end

        def prepare_route(object, target)
          object.attributes[:vrf] = @vdom
        end

        def prepare_zone(object, members)
          object.attributes[:vrf] = @vdom
        end

        # 先解析网络和普通对象，再解析 VIP、策略及策略关联的 NAT。
        def parse_network
          @sections = collect_sections(tree)
          @sections.select { |node| %i[interface zone route].include?(SECTIONS[node.words.drop(1)]) }.each { |node| parse_section(node) }
        end

        # 普通对象先于引用它们的 VIP 和策略完成装配。
        def parse_objects
          @sections.reject { |node| %i[interface zone route rule vip].include?(SECTIONS[node.words.drop(1)]) }.each { |node| parse_section(node) }
        end

        # VIP 可能同时生成地址和 NAT，因此必须先于策略。
        def parse_policies
          @drafts[:nat_pool].each_value { |object| emit_draft(:nat_pool, object) }
          @sections.select { |node| SECTIONS[node.words.drop(1)] == :vip }.each { |node| parse_section(node) }
          @sections.select { |node| SECTIONS[node.words.drop(1)] == :rule }.each { |node| parse_section(node) }
        end

        # 把 config/edit 层级转换为带原文行的树，保留块结束位置供诊断使用。
        def tree
          root = Node.new([], nil, [], nil)
          stack = [ root ]
          @lines.each do |line|
            next if line.text.strip.empty?
            words = tokens(line)
            if %w[config edit].include?(words[0])
              node = Node.new(words, line, [], nil)
              stack.last.children << node
              stack << node
            elsif words == [ "next" ] || words == [ "end" ]
              expected = (words[0] == "next") ? "edit" : "config"
              unless stack.last.words[0] == expected
                raise Algosec::Config::ParseError.new("Unexpected #{words[0]}; missing #{(expected == "config") ? "next" : "end"}", line_number: line.number)
              end
              stack.pop.closing = line
            else
              stack.last.children << line
            end
          end
          if stack.size > 1
            raise Algosec::Config::ParseError.new("Unclosed #{stack.last.words.join(" ")}; missing #{(stack.last.words[0] == "edit") ? "next" : "end"}", line_number: stack.last.line.number)
          end
          root.children
        end

        def collect_sections(nodes)
          nodes.flat_map do |node|
            next [] unless node.is_a?(Node)
            if node.words == %w[config vdom]
              consume(node.line, node.closing)
              node.children.flat_map do |domain|
                next [] unless domain.is_a?(Node)
                consume(domain.line, domain.closing)
                if domain.words[1] == @vdom
                  collect_sections(domain.children)
                else
                  consume(domain.lines)
                  []
                end
              end
            elsif SECTIONS.key?(node.words.drop(1))
              [ node ]
            else
              []
            end
          end
        end

        def parse_section(section)
          type = SECTIONS.fetch(section.words.drop(1))
          consume(section.line, section.closing)
          section.children.each do |entry|
            next unless entry.is_a?(Node) && entry.words[0] == "edit"
            fields = {}
            entry.children.grep(Line).each do |line|
              words = tokens(line)
              fields[words[1]] = [ words.drop(2), line ] if words[0] == "set"
            end
            if type == :interface && (fields.dig("vdom", 0, 0) || "root") != @vdom
              consume(entry.lines)
              next
            end
            consume(entry.line, entry.closing)
            name = entry.words[1]
            case type
            when :interface
              object = draft(:interface, name, name: name, vrf: @vdom)
              entry_fields(fields, %w[vdom ip alias type allowaccess]) do |key, value, line|
                if key == "ip"
                  ip, mask = ip_parts(value[0], value[1])
                  object.attributes.merge!(ipaddr: IPAddr.host_cidr(ip, mask), mode: :layer3)
                  connected_route(object, ip, mask, line, next_hop: ip)
                end
              end
            when :zone
              object = draft(:zone, name, name: name)
              entry_fields(fields, %w[interface]) { |_key, value, line| value.each { |member| bind_zone(member, name, line) } }
            when :route
              object = draft(:route, [ section.words.last, name ], kind: section.words.last.to_sym, subnet: "0.0.0.0/0")
              entry_fields(fields, %w[dst src device output-device input-device gateway distance priority]) do |key, value, _line|
                if key == "dst"
                  object.attributes[:subnet] = IPAddr.network_cidr(value[0], value[1])
                elsif key == "src"
                  object.attributes[:source] = ip_parts(value[0], value[1]).join("/")
                else
                  map_field(:route, object, key, value, _line)
                end
              end
            when :address
              kind = fields.dig("type", 0, 0) || "subnet"
              object = draft(:address, name, name: name)
              object.attributes[:member] = case kind
              when "subnet" then [ address_leaf(*(fields.dig("subnet", 0) || [ WILDCARD_IPV4, 0 ])) ]
              when "iprange" then [ { type: "iprange", value: "#{fields.dig('start-ip', 0, 0)}-#{fields.dig('end-ip', 0, 0)}" } ]
              when "fqdn" then [ { type: "domain", value: fields.dig("fqdn", 0, 0) } ]
              else []
              end
              entry_fields(fields, %w[subnet type start-ip end-ip fqdn associated-interface comment]) do |key, value, _line|
                if key == "subnet"
                  object.attributes[:member] = [ address_leaf(value[0], value[1]) ]
                elsif %w[associated-interface comment].include?(key)
                  map_field(:address, object, key, value, _line)
                end
              end
              unless %w[subnet iprange fqdn].include?(kind)
                object.attributes[:unresolved] = [ "unsupported_address_type: #{kind}" ]
                diagnose(:unsupported_address_type, "Address #{name} has type #{kind}", entry.line)
              end
            when :address_group, :service_group
              object = draft(type, name, name: name)
              entry_fields(fields, %w[member comment]) do |key, value, _line|
                if key == "member"
                  value.each { |member| (object.attributes[:members] ||= {})[member] = nil }
                else
                  object.attributes[:description] = value.join(" ")
                end
              end
            when :service
              object = draft(:service, name, name: name)
              entry_fields(fields, %w[tcp-portrange udp-portrange protocol comment]) do |key, value, line|
                if key == "protocol"
                  diagnose(:unsupported_protocol, "Service protocol #{value.join(" ")}", line) unless value == [ "TCP/UDP/SCTP" ]
                  next
                end
                if key == "comment"
                  object.attributes[:description] = value.join(" ")
                  next
                end
                value.each do |ports|
                  destination_port, source_port = ports.split(":", 2)
                  (object.attributes[:terms] ||= []) << { protocol: key.split("-").first,
                                                          source_port: source_port, destination_port: destination_port }
                end
              end
            when :schedule
              recurring = section.words.last == "recurring"
              object = draft(:schedule, name, **schedule_attributes(name: name, kind: recurring ? :weekly : :once))
              values = fields.transform_values(&:first)
              if recurring
                object.attributes.merge!(days: values["day"], periods: [ [ values.dig("start", 0) || "00:00", values.dig("end", 0) || "23:59" ] ])
                # FortiOS 的结束时间不晚于开始时间时跨到次日，不能投影为空或单分钟窗口。
                windows = begin
                  Algosec::Elements::Schedule.new(**context, **object.attributes).weekly_windows.values.flatten
                rescue ArgumentError => error
                  raise Algosec::Config::ParseError.new("schedule: #{error.message}", line_number: entry.line.number)
                end
                if windows.any? { |window| window.begin >= window.end }
                  object.attributes[:unparsed_commands] = entry.source_lines.map { |line| line.text.strip }
                  diagnose(:unsupported_schedule, "Schedule #{name} crosses midnight or spans a full day", entry.line)
                end
              else
                object.attributes.merge!(start_at: values["start"]&.join(" "), end_at: values["end"]&.join(" "))
              end
              entry_fields(fields, %w[start end day]) { }
            when :nat_pool
              mode = fields.dig("type", 0, 0) || "overload"
              interface = fields.dig("associated-interface", 0, 0)
              arp_reply = fields.dig("arp-reply", 0, 0) != "disable"
              object = draft(:nat_pool, name, name: name, direction: :source, mode: mode,
                             interface: interface, arp_reply: arp_reply,
                             ip: "#{fields.dig("startip", 0, 0)}-#{fields.dig("endip", 0, 0)}")
              entry_fields(fields, %w[startip endip type associated-interface arp-reply]) do |key, value, line|
                diagnose(:unsupported_nat_pool_mode, "IP pool #{name} uses unsupported type #{value.first}", line) if key == "type" && value != [ "overload" ]
                if key == "arp-reply" && !%w[enable disable].include?(value.first)
                  diagnose(:unsupported_nat_pool_arp_reply, "IP pool #{name} has invalid arp-reply value #{value.first}", line)
                end
              end
            when :vip
              vip(entry, name, fields)
            when :rule
              object = rule(entry, name, fields)
            end
            object&.lines&.concat(entry.source_lines)
          end
        end

        def entry_fields(fields, keys)
          fields.each do |key, (value, line)|
            next unless keys.include?(key)
            yield(key, value, line)
            consume(line)
          end
        end

        def consume_vip_fields(fields)
          entry_fields(fields, %w[extip extintf mappedip nat-source-vip portforward type extport mappedport protocol]) { }
        end

        def vip(entry, name, fields)
          values = fields.transform_values { |pair| pair.first.first }
          source_nat_enabled = values.fetch("nat-source-vip", "disable")
          unless %w[enable disable].include?(source_nat_enabled)
            diagnose(:unsupported_vip_source_nat, "VIP #{name} has invalid nat-source-vip value #{source_nat_enabled}", fields.fetch("nat-source-vip").last)
            consume_vip_fields(fields)
            return
          end
          mapped = values["extip"]
          reals = Array(fields.dig("mappedip", 0)).dup
          port = values["mappedport"]
          entry.children.grep(Node).select { |child| child.words == %w[config realservers] }.each do |block|
            consume(block.line, block.closing)
            block.children.grep(Node).each do |server|
              consume(server.line, server.closing)
              server.children.grep(Line).each do |line|
                words = tokens(line)
                if words[0, 2] == %w[set ip]
                  reals << words[2]
                elsif words[0, 2] == %w[set port]
                  port = words[2]
                else
                  next
                end
                consume(line)
              end
            end
          end
          interface = values["extintf"]
          if mapped == WILDCARD_IPV4
            diagnose(:unsupported_vip_external_ip, "VIP #{name} uses 0.0.0.0, whose meaning depends on FortiOS version and interface scope", entry.line)
            consume_vip_fields(fields)
            return
          end
          if mapped.to_s.empty? || reals.empty?
            diagnose(:incomplete_vip_mapping, "VIP #{name} requires extip and mappedip", entry.line)
            consume_vip_fields(fields)
            return
          end
          real_set = Set.new(*reals.flat_map { |expression| IPAddr.parse(expression).ranges })
          zone = find(:interface, interface)&.zone || interface
          port_forward = values["portforward"] == "enable"
          load_balance = values["type"] == "server-load-balance"
          if load_balance
            diagnose(:unsupported_vip_load_balance, "VIP #{name} uses unmodeled backend selection and port semantics", entry.line)
          end
          dynamic = port_forward || load_balance
          if dynamic
            if source_nat_enabled == "enable"
              diagnose(:unsupported_vip_source_nat, "VIP #{name} combines source NAT with a dynamic destination mapping", entry.line)
            end
            if port_forward && [ values["extport"], port ].any? { |value| value.to_s.empty? }
              diagnose(:incomplete_vip_port_forward, "VIP #{name} requires extport and mappedport when portforward is enabled", entry.line)
            else
              if port_forward && !load_balance
                port_mapping, port = vip_port_mapping(values, port, entry)
                consume(fields.fetch("portmapping-type").last) if fields.key?("portmapping-type")
              end
              port_mapping = :unknown if load_balance
              emit(:dynamic_nat, { name: name, direction: :destination, interface: interface, from_zone: zone,
                                   to_zone: zone_for(real_set), source_set: all_addresses, destination_ip: mapped,
                                   destination_set: IPAddr.parse(mapped), destination_port: values["extport"],
                                   translated_destination_set: real_set, translated_destination_port: port,
                                   destination_port_mapping: port_mapping, protocol: values["protocol"] || "tcp" }, entry.source_lines)
            end
          else
            emit(:static_nat, { name: name, mapped_ip: mapped, real_ip: reals.join(" "), mapped_set: IPAddr.parse(mapped),
                                real_set: real_set, interface: interface, mapped_zone: zone, real_zone: zone_for(real_set),
                                source_nat_enabled: source_nat_enabled == "enable" }, entry.source_lines)
          end
          first, last = mapped.split("-", 2)
          emit(:address, { name: name, member: [ { type: "iprange", value: "#{first}-#{last || first}" } ] }, entry.source_lines)
          consume_vip_fields(fields)
          nil
        end

        # 1-to-1 的单个 mappedport 是目标起点；m-to-n 保留池选择，不推导逐端口偏移。
        def vip_port_mapping(values, port, entry)
          mode = values.fetch("portmapping-type", "1-to-1")
          return [ :pool, port ] if mode == "m-to-n"
          before, after = IPAddr.ports(values.fetch("extport")), IPAddr.ports(port)
          if mode == "1-to-1" && before.size == 1 && after.size == 1 &&
             (after.cardinality == 1 || before.cardinality == after.cardinality) && after.min + before.cardinality - 1 <= IPAddr::PORT_MAX
            last = after.min + before.cardinality - 1
            return [ :offset, before.cardinality == 1 ? after.min.to_s : "#{after.min}-#{last}" ]
          end
          diagnose(:unsupported_vip_port_mapping, "VIP #{entry.words.last} has an invalid or unsupported port mapping", entry.line)
          [ :unknown, port ]
        end

        def context = super.merge(scope: Algosec::Elements::Scope.new(device_id: @reader.device_id, virtual_system: @vdom))

        def rule(entry, id, fields)
          object = draft(:rule, id, native_rule_id: id, rule_set: @vdom, rule_number: @drafts[:rule].size, action: "deny")
          entry_fields(fields, %w[srcintf dstintf srcaddr dstaddr action schedule service status nat poolname name comments]) do |key, values, line|
            next if map_field(:rule, object, key, values, line)
            case key
            when "srcintf", "dstintf"
              rule_interfaces(object, key, values, line)
            when "srcaddr", "dstaddr"
              add_members(object, (key == "srcaddr") ? :sources : :destinations, values, addresses: true)
            when "service" then add_members(object, :services, values)
            when "schedule" then object.attributes[:schedule_name] = values.first unless values.first == "always"
            when "nat", "poolname"
              object.state[key.to_sym] = values.first
              object.attributes[:nat] = values.first == "enable" if key == "nat"
            end
          end
          object
        end

        # 只有接口集合覆盖整个区域时才能约为区域；部分覆盖仍保留未知条件。
        def rule_interfaces(object, field, names, line)
          key = field == "srcintf" ? :from_zones : :to_zones
          if names == [ "any" ]
            object.attributes[key] = [ "any" ]
            return
          end
          zones = names.filter_map { |name| find(:zone, name)&.name }
          interfaces = names.filter_map { |name| find(:interface, name) }
          if field == "dstintf"
            object.attributes[:dst_interfaces] = interfaces.map(&:name)
          elsif interfaces.one?
            object.attributes[:from_interface] = interfaces.first.name
          end
          unknown = names.reject { |name| find(:zone, name) || find(:interface, name) }
          interfaces.group_by(&:zone).each do |zone_name, members|
            next if zones.include?(zone_name)
            zone = find(:zone, zone_name)
            zones << zone_name if zone_name
            unless zone && (zone.interfaces.values.map(&:name) - members.map(&:name)).empty?
              preserve_interface_condition(object, line)
            end
          end
          unless unknown.empty?
            diagnose(:missing_interface, "Unknown policy interfaces: #{unknown.join(', ')}", line)
            preserve_interface_condition(object, line)
            zones << "any"
          end
          object.attributes[key] = zones.uniq
        end

        def preserve_interface_condition(object, line)
          conditions = object.attributes[:conditions] ||= {}
          (conditions["unparsed_commands"] ||= []) << line.text.strip
        end

        def policy_nat
          @drafts[:rule].each_value do |object|
            next unless object.state[:nat] == "enable" && object.attributes[:status] != "disable"
            rule = @catalog.detect { |element| element.is_a?(Algosec::Elements::SecurityRule) && element.native_rule_id == object.attributes[:native_rule_id] }
            interface = nil
            pool_name = object.state[:poolname]
            pool = find(:nat_pool, pool_name) if pool_name
            if pool_name
              diagnose(:missing_reference, "NAT pool #{pool_name}", object.lines.first) unless pool
              translated = pool&.set
            else
              interface = egress_interface(rule.sources.set, rule.destinations.set, vrf: @vdom)
              allowed = rule.dst_interfaces.empty? || rule.dst_interfaces.include?(interface&.name)
              allowed &&= rule.to_zones.nil? || rule.to_zones.include?("any") || rule.to_zones.include?(interface&.zone)
              translated = IPAddr.parse(interface.host) if allowed && interface&.host
              diagnose(:missing_reference, "NAT policy #{rule.rule_id}: no unique egress address", object.lines.first) unless translated
            end
            emit(:dynamic_nat, { policy_id: rule.native_rule_id, direction: :source, match_rule: rule,
                                 from_zone: rule.from_zones&.one? ? rule.from_zones.first : nil,
                                 to_zone: rule.to_zones&.one? ? rule.to_zones.first : interface&.zone,
                                 interface: interface&.name, vrf: @vdom,
                                 source_set: rule.sources.set, destination_set: rule.destinations.set,
                                 service_set: rule.services.set, protocol: "any",
                                 source_pool: pool, translated_source_set: translated }, object.lines)
          end
        end
      end
    end
  end
end
