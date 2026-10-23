# frozen_string_literal: true

require_relative "../../config/parser"

module Algosec
  module Vendors
    module Neteye
      # 解析 Neteye 网络对象、接口、策略和 NAT。
      class Parser < Algosec::Config::Parser
        VENDOR = :neteye

        stage :scan_document, using: :scan_document
        stage :emit_objects, using: :emit_objects
        stage :object_references, using: :resolve_references
        stage :resolve_route_sources, using: :resolve_route_sources
        stage :finish_network, using: :finish_network
        stage :parse_policies, using: :parse_policies
        stage :emit_rules, using: :emit_rules
        stage :rule_references, using: :resolve_references
        stage :parse_nat, using: :parse_nat
        HEADERS = /\A(?:interface ethernet \S+\z|vlan \d+\z|zone \S+\z|policy route \S+\z)/

        private

        # 收集块式配置，将需要网络或对象引用的命令留给后续阶段。
        def scan_document
          index = 0
          @nat_rows = Hash.new { |hash, key| hash[key] = [] }
          @policies = []
          while index < @lines.size
            line = @lines[index]
            words = tokens(line)
            if HEADERS.match?(line.text.strip)
              rows, index = block_at(index, terminator: /\A#\z/, stop: HEADERS)
              network_block(words, rows)
              next
            elsif words[0] == "object"
              object_command(words, line)
            elsif words[0] == "route"
              capture(draft(:route, line.index, **route_attributes(words.drop(1))), line)
            elsif words[0] == "policy" && %w[mip snat dnat].include?(words[1])
              @nat_rows[words[1, 2]] << line
            elsif words[0, 2] == %w[policy access]
              @policies << line
            elsif words == [ "#" ]
              consume(line)
            end
            index += 1
          end
        end

        # 将策略路由的源地址引用转换为已解析集合。
        def resolve_route_sources
          @drafts[:route].each_value do |object|
            if object.state[:source]
              object.attributes[:source_set] = match_address(object.state[:source], object.lines.first)
            end
          end
        end

        # 先发射地址池，再装配策略所需的对象引用。
        def parse_policies
          @policies.each { |line| policy(tokens(line).drop(2), line) }
        end

        # 引用和规则就绪后生成 NAT，保留原配置的转换顺序。
        def parse_nat
          @nat_rows.each { |(kind, id), rows| nat(kind, id, rows) }
        end

        def network_block(words, rows)
          if words[0] == "policy"
            object = draft(:route, [ :policy, words[2] ], name: words[2], kind: :policy)
          elsif words[0] == "zone"
            object = draft(:zone, words[1], name: words[1])
          else
            name = (words[0] == "vlan") ? "vlan#{words[1]}" : words[2]
            object = draft(:interface, name, name: name)
          end
          object.lines.concat(rows)
          rows.drop(1).each do |line|
            fields = tokens(line)
            if words[0] == "policy"
              if fields[0, 2] == %w[matching sip]
                object.state[:source] = fields.drop(2)
              elsif fields[0] == "route"
                object.attributes.merge!(route_attributes(fields.drop(1)))
              else
                next
              end
            elsif words[0] == "zone"
              if fields[0] == "zone" && fields[2] == "based-layer3"
                bind_zone(fields[3], words[1], line)
              elsif fields[0] == "zone" && fields[2, 2] == %w[based-layer2 vlan]
                bind_zone(fields[5] || "vlan#{fields[4]}", words[1], line)
              else
                next
              end
            elsif fields[0, 2] == %w[ip address]
              ip, mask = ip_parts(fields[2], fields[3])
              object.attributes.merge!(ipaddr: IPAddr.host_cidr(ip, mask), mode: :layer3)
              route = connected_route(object, ip, mask, line, next_hop: ip)
              route.lines.unshift(rows.first)
            elsif fields[0, 3] == %w[port access vlan]
              (object.state[:vlans] ||= []) << "vlan#{fields[3]}"
            elsif fields[0] == "description"
              object.attributes[:description] = fields.drop(1).join(" ")
            else
              next
            end
            consume(line)
          end
        end

        def link_interface_members(interfaces)
          @drafts[:interface].each_value do |object|
            Array(object.state[:vlans]).each do |name|
              child = interfaces[name]
              child ? interfaces.fetch(object.attributes[:name]).add_vlan(child) : diagnose(:missing_interface, "VLAN #{name}", object.lines.first)
            end
          end
        end

        def route_attributes(words)
          network, mask = words.shift(2)
          attributes = { subnet: IPAddr.network_cidr(network, mask) }
          attributes[:destination_interface] = words.slice!(0, 2).last if words[0] == "interface"
          attributes[:next_hop] = words.slice!(0, 2).last if words[0] == "gateway"
          attributes[:distance] = words[0] if words[0]&.match?(/\A\d+\z/)
          attributes
        end

        def object_command(words, line)
          name = words[2]
          case words[1]
          when "ipaddr"
            object = draft(:address, name, name: name)
            if words[3] == "subnet"
              (object.attributes[:member] ||= []) << address_leaf(ip_parts(words[4], words[5]).join("/"))
            elsif words[3]&.match?(/\A\d+\./)
              words[3].split(",").each do |expression|
                (object.attributes[:member] ||= []) << (expression.include?("-") ? { type: "iprange", value: expression } : address_leaf(expression))
              end
            else
              return
            end
          when "group"
            return unless words[3] == "type" && %w[ipaddr service].include?(words[4])
            type = (words[4] == "ipaddr") ? :address_group : :service_group
            object = draft(type, name, name: name)
            words.fetch(5, "").split(",").each { |member| (object.attributes[:members] ||= {})[member] = nil }
          when "service"
            object = draft(:service, name, name: name)
            rest = words.drop(3)
            if rest[0] == "description"
              object.attributes[:description] = rest.drop(1).join(" ")
            else
              protocol = rest.shift
              protocol = rest.shift if protocol == "other"
              destination = (rest[0] == "any") ? NONZERO_SERVICE_PORTS : rest[1] || "0"
              source_port = rest[0] unless rest[0] == "any"
              (object.attributes[:terms] ||= []) << { protocol: protocol, source_port: source_port, destination_port: destination }
            end
          else
            return
          end
          capture(object, line)
        end

        def take_address(words, line)
          if %w[object group].include?(words[0])
            [ words.shift(2).last ]
          elsif words[0] == "any"
            [ address_reference(words.shift) ]
          else
            words.shift.split(",").map { |expression| literal_reference(expression, line) }
          end
        end

        def service_references(words)
          case words[0]
          when "protocol-object", "protocol-group" then [ words[1] ]
          when "any" then [ literal_service("any") ]
          when "icmp" then [ literal_service("icmp", NONZERO_SERVICE_PORTS) ]
          when "other" then [ literal_service(words[1], "0") ]
          when "tcp", "udp" then [ literal_service(words[0], words[2], source_port: words[1]) ]
          else raise Algosec::Config::ParseError, "Unknown policy protocol #{words[0]}"
          end
        end

        def policy(words, line)
          id = words.shift
          if %w[sourceip desip protocol].include?(words[0])
            object = @drafts[:rule][id]
            unless object
              consume(line)
              return diagnose(:missing_reference, "Policy #{id} has no declaration", line)
            end
            command = words.shift
            if command == "protocol"
              (object.state[:services] ||= []).concat(service_references(words))
            else
              dimension = (command == "sourceip") ? :sources : :destinations
              if words[0] == "address"
                words.shift
                refs = take_address(words, line)
              elsif %w[object group].include?(words[0])
                refs = take_address(words, line)
              else
                refs = [ literal_reference(ip_parts(words[0], words[1]).join("/"), line) ]
              end
              (object.state[dimension] ||= []).concat(refs)
            end
          else
            from = words.shift
            sources = take_address(words, line)
            to = words.shift
            destinations = take_address(words, line)
            index = words.index { |word| %w[permit deny].include?(word) }
            return unless index
            action, status, priority = words[index, 3]
            object = draft(:rule, id, native_rule_id: id, from_zones: [ from ], to_zones: [ to ],
                           action: action, status: status, rule_number: priority)
            object.state.merge!(sources: sources, destinations: destinations, services: service_references(words.first(index)))
          end
          capture(object, line)
        end

        def match_address(words, line)
          return lookup_address_set(words[1], line) if %w[object group].include?(words[0])
          return IPAddr.subnet(words[1], words[2]) if words[0] == "netmask"
          return IPAddr.subnet(words[0], words[2]) if words[1] == "mask"
          return IPAddr.between(words[0], words[1] || words[0]) if words[0]&.match?(/\A\d+\./)
          lookup_address_set(words[0], line)
        end

        def nat_endpoint(words, line)
          if words[0] == "interface"
            words.shift
            name = words.shift
            return diagnose(:invalid_nat, "NAT interface endpoint is missing its name", line) unless name
            interface = find(:interface, name)
            diagnose(:missing_interface, "NAT interface #{name} has no IP", line) unless interface&.host
            return [ interface&.host && IPAddr.parse(interface.host), name ]
          end
          if %w[object group].include?(words[0])
            kind = words.shift
            name = words.shift
            return diagnose(:invalid_nat, "NAT #{kind} endpoint is missing its name", line) unless name
            return [ lookup_address_set(name, line), nil ]
          end
          words.shift if words[0] == "iplist"
          if words[0] == "netmask"
            words.shift
            address, mask = words.shift(2)
            return diagnose(:invalid_nat, "NAT netmask endpoint requires an address and mask", line) unless address && mask
            return [ IPAddr.subnet(address, mask), nil ]
          end
          expression = words.shift
          return diagnose(:invalid_nat, "NAT address endpoint is missing", line) unless expression
          ranges = expression.split(",").flat_map { |segment| IPAddr.parse(segment).ranges }
          [ Set.new(*ranges), nil ]
        rescue Algosec::Config::ParseError, IPAddr::Error, ArgumentError => error
          diagnose(:invalid_nat, "Invalid NAT address endpoint: #{error.message}", line)
        end

        def nat(kind, id, rows)
          declaration = rows.find { |line| tokens(line)[3] != "matching" }
          unless declaration
            return diagnose(:missing_reference, "NAT #{id} has no declaration", rows.first)
          end
          words = tokens(declaration).drop(3)
          if kind == "mip"
            real, mapped, status, *extra = words
            unless real && mapped && extra.empty? && [ nil, "enable", "disable" ].include?(status)
              consume(rows)
              return diagnose(:invalid_nat, "MIP requires real and mapped addresses with an optional enable status", declaration)
            end
            if status == "disable"
              consume(rows)
              return diagnose(:unsupported_nat_status, "MIP #{id} is disabled; status is not represented by Elements", declaration)
            end
            begin
              attributes = { id: id, real_ip: real, mapped_ip: mapped,
                             real_set: IPAddr.parse(real), mapped_set: IPAddr.parse(mapped) }
            rescue IPAddr::Error, ArgumentError => error
              consume(rows)
              return diagnose(:invalid_nat, "Invalid MIP address: #{error.message}", declaration)
            end
          else
            before, = nat_endpoint(words, declaration)
            unless before
              consume(rows)
              return
            end
            protocol = words.shift if %w[tcp udp].include?(words[0])
            before_port = words.shift if protocol
            if protocol && !valid_nat_port?(before_port)
              consume(rows)
              return diagnose(:invalid_nat, "NAT #{protocol} source port is missing or invalid", declaration)
            end
            after, interface = nat_endpoint(words, declaration)
            unless after
              consume(rows)
              return
            end
            after_port = words.shift if protocol && words.first&.match?(/\A\d+\z/)
            status = words.shift if %w[enable disable].include?(words.first)
            if !words.empty?
              consume(rows)
              return diagnose(:invalid_nat, "Unexpected NAT declaration fields: #{words.join(" ")}", declaration)
            end
            if status == "disable"
              consume(rows)
              return diagnose(:unsupported_nat_status, "NAT #{id} is disabled; status is not represented by Elements", declaration)
            end
            if (before_port && !valid_nat_port?(before_port)) || (after_port && !valid_nat_port?(after_port))
              consume(rows)
              return diagnose(:invalid_nat, "NAT port must be between 0 and 65535", declaration)
            end
            attributes = { id: id, direction: (kind == "snat") ? :source : :destination, interface: interface }
            if kind == "snat"
              attributes[:source_set] = before
              attributes[:translated_source_set] = after
            else
              attributes[:destination_set] = before
              attributes[:translated_destination_set] = after
              if protocol
                attributes.merge!(protocol: protocol, destination_port: before_port, translated_destination_port: after_port,
                                  service_set: IPAddr.service("#{protocol}/#{before_port}"),
                                  translated_service_set: after_port && IPAddr.service("#{protocol}/#{after_port}"))
              end
            end
          end
          match_rule = Algosec::Elements::SecurityRule.new(**context, native_rule_id: id, config: config_text(rows))
          matches = rows.reject { |line| line.equal?(declaration) }
          matches.each do |line|
            fields = tokens(line).drop(4)
            if fields[0] == "dip"
              set = match_address(fields.drop(1), line)
              if set
                address = Algosec::Elements::AddressObject.new(**context, name: "NAT #{id} destination", member: set.map { |range| { type: "iprange", value: "#{IPAddr.from_i(range.begin)}-#{IPAddr.from_i(range.end)}" } })
                match_rule.destinations.add(line.number.to_s, address)
              end
            elsif fields[0] == "protocol"
              protocol = (fields[1] == "other") ? fields[2] : fields[1]
              port = if fields[2] == "port"
                       fields.drop(3).join("-")
              else
                       (protocol == "icmp") ? NONZERO_SERVICE_PORTS : "0"
              end
              name, srv = literal_service(protocol, port)
              match_rule.services.add(name, srv)
            else
              next
            end
            consume(line)
          end
          attributes[:match_rule] = match_rule if kind == "mip" || !matches.empty?
          if !matches.empty? && kind != "mip"
            attributes[(kind == "snat") ? :destination_set : :source_set] = (kind == "snat") ? match_rule.destinations.set : match_rule.sources.set
          end
          emit((kind == "mip") ? :static_nat : :dynamic_nat, attributes, rows)
          consume(declaration)
        end

        def valid_nat_port?(value)
          value&.match?(/\A\d+\z/) && value.to_i.between?(0, IPAddr::PORT_MAX)
        end
      end
    end
  end
end
