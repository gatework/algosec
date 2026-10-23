# frozen_string_literal: true

require_relative "../../config/parser"
require_relative "fields"

module Algosec
  module Vendors
    module Topsec
      # 解析 Topsec 的网络对象、策略和 NAT 定义。
      class Parser < Algosec::Config::Parser
        VENDOR = :topsec
        POLICY_FIELDS = %w[action srcarea dstarea srcvlan dstvlan src dst service schedule enable log].freeze
        NAT_FIELDS = %w[srcarea dstarea srcvlan dstvlan orig-src orig-dst orig-service trans-src trans-dst trans-service].freeze

        stage :network
        line_rule :network, :network, prefix: %w[network], using: :network
        line_rule :network, :area, prefix: %w[ID], using: :network
        stage :vlan_zones, using: :bind_vlan_zones
        stage :finish_network, using: :finish_network
        stage :objects
        line_rule :objects, :definition, prefix: %w[ID], using: :definition
        stage :emit_objects, using: :emit_objects
        stage :object_references, using: :resolve_references
        stage :policies, using: :parse_policies
        stage :emit_rules, using: :emit_rules

        private

        def any_address?(name, dimension: nil) = /\Aany\z/i.match?(name)

        def any_nat_address?(name) = /\Aany\z/i.match?(name)

        # 先关联网络和区域，再发射对象、策略和 NAT 定义。
        def bind_vlan_zones
          @drafts[:interface].each_value do |object|
            next if object.attributes[:mode] == :layer3
            Array(object.attributes[:vlans]).each do |vlan|
              child = @drafts[:interface]["vlan.#{vlan.rjust(4, "0")}"]
              child.attributes[:zone] ||= object.attributes[:zone] if child
            end
          end
        end

        # 策略与 NAT 共用 keyword/value 语法，保留各自业务装配。
        def parse_policies
          pending.each do |line|
            words = tokens(line)
            next unless words[0] == "ID" && words[3, 2] == %w[policy add]
            if words[2] == "firewall"
              policy(line, words[1], Fields.parse(words.drop(5)))
            elsif words[2] == "nat"
              nat(line, words[1], Fields.parse(words.drop(5)))
            end
          end
        end

        def network(line, words)
          if words[0, 2] == %w[network interface]
            name, rest = words[2], words.drop(3)
            object = draft(:interface, name, name: name)
            if rest[0, 2] == %w[ip add] && rest[3] == "mask"
              ip, mask = ip_parts(rest[2], rest[4])
              object.attributes.merge!(ipaddr: IPAddr.host_cidr(ip, mask), mode: :layer3)
              connected_route(object, ip, mask, line, next_hop: ip)
            elsif rest[0, 2] == %w[switchport mode]
              object.attributes[:access_mode] = rest[2] unless object.attributes[:mode] == :layer3
            elsif rest[0, 2] == %w[switchport access-vlan]
              (object.attributes[:vlans] ||= []) << rest[2] if object.attributes[:mode] != :layer3 && object.attributes.fetch(:access_mode, "access") == "access"
            elsif rest[0, 3] == %w[switchport trunk allowed-vlan]
              object.attributes[:vlans] = rest[3].split(",") if object.attributes[:access_mode] == "trunk" && object.attributes[:mode] != :layer3
            else
              return
            end
            capture(object, line)
          elsif words[0, 3] == %w[network route add]
            fields = Fields.parse(words.drop(3))
            ip, mask = ip_parts(fields.fetch("dst"))
            capture(draft(:route, fields.fetch("id"), subnet: IPAddr.network_cidr(ip, mask),
                          next_hop: fields["gw"], destination_interface: fields["dev"], distance: fields["metric"] || 10), line)
          elsif words[0] == "ID" && words[2, 4] == %w[define area add name]
            fields = Fields.parse(words.drop(5))
            name = fields.fetch("name")
            fields.fetch("attribute").split.each { |interface| bind_zone(interface, name, line) }
            capture(draft(:zone, name, name: name), line)
          end
        end

        def link_interface_members(interfaces)
          @drafts[:interface].each_value do |object|
            next if object.attributes[:mode] == :layer3
            interface = interfaces.fetch(object.attributes[:name])
            Array(object.attributes[:vlans]).each do |vlan|
              child = interfaces["vlan.#{vlan.rjust(4, "0")}"]
              child ? interface.add_vlan(child) : diagnose(:missing_interface, "VLAN #{vlan}", object.lines.first)
            end
          end
        end

        def definition(line, words)
          return unless words[0] == "ID" && words[2] == "define" && words[4, 2] == %w[add name]
          kind, name, rest = words[3], words[6], words.drop(7)
          fields = Fields.parse(rest)
          case kind
          when "host", "subnet", "range"
            object = draft(:address, name, name: name)
            members = object.attributes[:member] ||= []
            if kind == "host"
              fields.fetch("ipaddr").split.each { |ip| members << address_leaf("#{ip}/32") }
            elsif kind == "subnet"
              members << address_leaf(ip_parts(fields.fetch("ipaddr"), fields.fetch("mask")).join("/"))
            else
              members << { type: "iprange", value: "#{fields.fetch("ip1")} #{fields.fetch("ip2")}" }
            end
          when "group_address", "group_service"
            type = (kind == "group_address") ? :address_group : :service_group
            object = draft(type, name, name: name)
            fields.fetch("member").split.each { |member| (object.attributes[:members] ||= {})[member] = nil }
          when "service"
            protocol = { "6" => "tcp", "17" => "udp" }.fetch(fields.fetch("protocol"), fields["protocol"])
            port = fields.key?("port2") ? "#{fields.fetch("port")}-#{fields["port2"]}" : fields.fetch("port")
            object = draft(:service, name, name: name, protocol: protocol, destination_port: port)
          when "schedule"
            attributes = schedule_attributes(name: name)
            if fields["cyctype"] == "weekcyc"
              days = fields.fetch("week").chars.map { |day| %w[sun mon tue wed thu fri sat sun].fetch(Integer(day, 10)) }
              attributes.merge!(kind: :weekly, days: days, periods: [ [ fields.fetch("start"), fields.fetch("end") ] ])
            else
              attributes[:start_at] = "#{fields.fetch("sdate")} #{fields.fetch("stime")}"
              attributes[:end_at] = "#{fields.fetch("edate")} #{fields.fetch("etime")}"
            end
            object = draft(:schedule, name, **attributes)
          else
            return
          end
          capture(object, line)
        end

        def policy(line, id, fields)
          object = draft(:rule, id, native_rule_id: id, rule_number: @drafts[:rule].size,
                         action: fields["action"],
                         status: { "no" => "disable", "yes" => "enable" }.fetch(fields.fetch("enable", "yes")) { fields["enable"] }, schedule_name: fields["schedule"], log: fields["log"])
          [ [ "src", :sources, :from_zones, :from_vlans ], [ "dst", :destinations, :to_zones, :to_vlans ] ].each do |side, dimension, zones_key, vlans_key|
            object.attributes[zones_key] = fields["#{side}area"].split if fields["#{side}area"]
            vlans = fields["#{side}vlan"]&.split
            (object.attributes[:conditions] ||= {})[vlans_key.to_s] = vlans.to_h { |vlan| [ vlan, nil ] } if vlans
            if fields[side]
              add_members(object, dimension, fields[side].split, addresses: true)
            elsif vlans
              vlans.each do |name|
                interface = find(:interface, name)
                if interface&.host
                  (object.state[dimension] ||= []) << literal_reference(interface.ipaddr, line)
                else
                  (object.state[dimension] ||= []) << name
                  diagnose(:missing_interface, "VLAN #{name} has no address", line)
                end
              end
            else
              add_members(object, dimension, [ "any" ], addresses: true)
            end
          end
          add_members(object, :services, fields.fetch("service", "ANY").split)
          unsupported = fields.keys - POLICY_FIELDS
          unless unsupported.empty?
            ((object.attributes[:conditions] ||= {})["unparsed_commands"] ||= []) << line.text
            diagnose(:unsupported_rule_condition, "Policy #{id} has unsupported fields: #{unsupported.sort.join(', ')}", line)
          end
          capture(object, line)
        end

        # 匹配范围与转换目标全部解析后再发射，避免留下可被误用的部分 NAT。
        def nat(line, id, fields)
          consume(line)
          return unless valid_nat_fields?(fields, id, line)

          source, src_zones = nat_match(fields, "src", line)
          destination, dst_zones = nat_match(fields, "dst", line)
          return unless source && destination
          if src_zones.empty? || dst_zones.empty?
            return diagnose(:missing_nat_context, "NAT #{id} requires both source and destination areas", line)
          end

          attributes = nat_translation(fields, line)
          return unless attributes

          attributes.merge!(id: id, source_set: source, destination_set: destination)
          src_zones.product(dst_zones).each do |from, to|
            emit(:dynamic_nat, attributes.merge(from_zone: from, to_zone: to), [ line ])
          end
        end

        # 字段校验只解释当前支持的语义，未建模动作继续保持不完整状态。
        def valid_nat_fields?(fields, id, line)
          unsupported = fields.keys - NAT_FIELDS
          unless unsupported.empty?
            diagnose(:unsupported_nat_condition, "NAT #{id} has unsupported fields: #{unsupported.sort.join(", ")}", line)
            return false
          end
          unless fields["trans-src"].present? || fields["trans-dst"].present?
            diagnose(:invalid_nat, "NAT #{id} requires trans-src or trans-dst", line)
            return false
          end
          if fields["trans-service"].present? && !fields["trans-dst"].present?
            diagnose(:unsupported_nat_condition, "NAT #{id} source-only service translation is not modeled", line)
            return false
          end
          missing_values = NAT_FIELDS.select { |field| fields.key?(field) && fields[field].blank? }
          unless missing_values.empty?
            diagnose(:invalid_nat, "NAT #{id} has empty fields: #{missing_values.join(", ")}", line)
            return false
          end
          true
        end

        # 显式区域与 VLAN 决定作用域；仅在未声明时才按原始地址推导区域。
        def nat_match(fields, side, line)
          zones = fields.fetch("#{side}area", "").split
          zones.concat(fields.fetch("#{side}vlan", "").split.map do |vlan|
            find(:interface, vlan)&.zone || diagnose(:missing_zone, "VLAN #{vlan}", line)
          end)
          return if zones.any?(&:nil?)

          values = fields["orig-#{side}"]
          sets = values ? nat_address_sets(values, line) : [ all_addresses ]
          return unless sets

          if values && !fields.key?("#{side}area") && !fields.key?("#{side}vlan")
            inferred = sets.map { |set| zone_for(set) }
            if inferred.any?(&:nil?)
              return diagnose(:missing_nat_context, "NAT #{side} addresses do not have a complete area mapping", line)
            end
            zones.concat(inferred)
          end
          [ Set.new(*sets.flat_map(&:ranges)), zones.uniq ]
        end

        # 原始服务对象保留完整条件；转换目标按对象列表求并集，不把缺失成员当空集。
        def nat_translation(fields, line)
          attributes = {}
          if fields["orig-service"]
            names = fields["orig-service"].split
            sets = names.map { |name| nat_service_set(name, line) }
            return if sets.any?(&:nil?)

            attributes[:service_set] = Set.new(*sets.flat_map(&:ranges))
            attributes[:references] = names.filter_map { |name| service(name) }
          end
          if fields["trans-src"]
            sets = nat_address_sets(fields["trans-src"], line, interfaces: true)
            return unless sets

            attributes[:translated_source_set] = Set.new(*sets.flat_map(&:ranges))
            attributes[:direction] = :source
          end
          if fields["trans-dst"]
            sets = nat_address_sets(fields["trans-dst"], line)
            return unless sets

            attributes[:translated_destination_set] = Set.new(*sets.flat_map(&:ranges))
            attributes[:direction] = fields["trans-src"] ? :bidirectional : :destination
          end
          if fields["trans-service"]
            attributes[:translated_service_set] = nat_service_set(fields["trans-service"].strip, line)
            return unless attributes[:translated_service_set]
          end
          attributes
        end

        # NAT 不接受服务组的部分投影；先检查包括嵌套组在内的全部引用。
        def nat_service_set(name, line)
          object = service(name)
          if object.is_a?(Algosec::Elements::ServiceGroup) && !object.resolved?
            return diagnose(:unresolved_service, "NAT service #{name} has unresolved members", line)
          end
          lookup_service_set(name, line)
        end

        # 保留各对象范围供区域推导；源转换可使用接口的 IPv4 主地址。
        def nat_address_sets(value, line, interfaces: false)
          sets = value.split.map do |name|
            interface = find(:interface, name) if interfaces
            if interface
              if interface.host
                IPAddr.parse(interface.host)
              else
                diagnose(:missing_interface, "NAT interface #{name} has no IPv4 address", line)
              end
            else
              lookup_address_set(name, line)
            end
          end
          sets unless sets.any?(&:nil?)
        end
      end
    end
  end
end
