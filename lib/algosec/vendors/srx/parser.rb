# frozen_string_literal: true

require_relative "../../config/parser"

module Algosec
  module Vendors
    module Srx
      # 解析 Junos set 配置、接口、地址簿、应用、策略和 NAT。
      class Parser < Algosec::Config::Parser
        VENDOR = :srx

        field :service, "protocol", to: :protocol
        field :service, "source-port", to: :source_port
        field :service, "destination-port", to: :destination_port
        field :service, "uuid", to: :uuid
        field :service, "inactivity-timeout", to: :timeout

        stage :network
        line_rule :network, :set, prefix: %w[set], using: :parse_network
        stage :expand_route_paths, using: :expand_route_paths
        stage :finish_network, using: :finish_network
        stage :objects
        line_rule :objects, :set, prefix: %w[set], using: :parse_object
        line_rule :objects, :deactivate, prefix: %w[deactivate], using: :parse_object
        stage :build_services, using: :build_services
        stage :emit_objects, using: :emit_objects
        stage :build_nat, using: :build_nat
        stage :rules
        line_rule :rules, :set, prefix: %w[set], using: :parse_rule
        line_rule :rules, :deactivate, prefix: %w[deactivate], using: :parse_rule
        stage :emit_rules, using: :emit_rules

        private

        # any 是原生任意服务关键字，不依赖外部预定义服务目录。
        def service(name)
          super || (literal_service("any").last if name == "any")
        end

        def any_address?(name, dimension: nil) = /\A(?:any|any-ipv4)\z/i.match?(name)

        def address_reference_scope(zone) = { zone: zone }

        # 旧引用语法不能区分同名地址簿和区域时保留全部对象，拒绝猜测成员。
        def resolve_references
          super
        rescue Algosec::Elements::Catalog::AmbiguousReference => error
          diagnose(:ambiguous_reference, error.message)
        end

        def route_interface?(interface, attributes)
          interface.vrf == (attributes[:vrf] || "default")
        end

        def prepare_route(object, target)
          object.attributes[:vrf] = target.vrf if object.state[:connected] && target
        end

        def prepare_zone(object, members)
          object.attributes[:vrf] ||= members.first&.vrf || "default"
        end

        def parse_network(line, words)
          if words[0, 2] == %w[set interfaces] && words[3] == "unit" && words[5] == "family"
            name = "#{words[2]}.#{words[4]}"
            return unless %w[inet bridge ethernet-switching].include?(words[6])
            object = draft(:interface, name, name: name)
            capture(object, line)
            if words[6, 2] == %w[inet address]
              ip, mask = ip_parts(words.fetch(8))
              object.attributes.merge!(ipaddr: IPAddr.host_cidr(ip, mask), mode: :layer3)
              # /31 点对点和 /32 主机接口同样声明可达范围，不能按主机数量过滤。
              connected_route(object, ip, mask, line, next_hop: ip)
            end
          elsif words[0, 2] == %w[set routing-instances] && words[3] == "interface"
            capture(draft(:interface, words[4], name: words[4], vrf: words[2]), line)
          elsif words[0, 4] == %w[set security zones security-zone] && words[5] == "interfaces"
            bind_zone(words[6], words[4], line)
          else
            instance = "default"
            rest = words.drop(1)
            if rest[0] == "routing-instances"
              instance, rest = rest[1], rest.drop(2)
            end
            return unless words[0] == "set" && rest[0, 3] == %w[routing-options static route]
            return unless %w[next-hop preference].include?(rest[4])
            network, mask = ip_parts(rest.fetch(3))
            object = draft(:route, [ instance, network, mask ], subnet: IPAddr.network_cidr(network, mask), vrf: instance)
            if rest[4] == "next-hop"
              (object.state[:next_hops] ||= []).concat(rest.drop(5).reject { |word| %w[[ ]].include?(word) })
            else
              object.attributes[:distance] = rest[5]
            end
            capture(object, line)
          end
        end

        # Junos 按子网分多行配置下一跳；发射前展开路径，避免最后一条覆盖前面的路径。
        def expand_route_paths
          @drafts[:route] = @drafts[:route].each_with_object({}) do |(key, object), expanded|
            hops = Array(object.state[:next_hops]).uniq
            if hops.empty?
              expanded[key] = object
            else
              hops.each do |hop|
                expanded[[ key, hop ]] = Draft.new(object.attributes.merge(next_hop: hop), object.lines.dup, object.state.dup)
              end
            end
          end
        end

        def parse_object(line, words)
          if words[0, 4] == %w[set security zones security-zone] && words[5] == "address-book"
            address_command(words[4], words.drop(6), line)
          elsif words[0, 3] == %w[set security address-book]
            address_command(words[3], words.drop(4), line, address_book: words[3])
          elsif words[0, 3] == %w[set applications application]
            name = words[3]
            rest = words.drop(4)
            term = (rest[0] == "term") ? rest.slice!(0, 2).last : " "
            return unless @syntax.key?([ :field, :service, rest[0] ]) || rest[0, 2] == %w[alg ftp]
            object = draft(:srx_service, [ name, term ], name: name, term: term)
            if rest[0, 2] == %w[alg ftp]
              diagnose(:unsupported_application_condition, "Application #{name} uses FTP ALG", line)
            else
              return unless map_field(:service, object, rest[0], rest.drop(1), line)
            end
            capture(object, line)
          elsif words[0, 3] == %w[set applications application-set] && %w[application application-set].include?(words[4])
            object = draft(:service_group, words[3], name: words[3])
            (object.attributes[:members] ||= {})[words[5]] = nil
            capture(object, line)
          elsif words[0, 3] == %w[set schedulers scheduler] && words[4] == "start-date" && words[6] == "stop-date"
            capture(draft(:schedule, words[3], **schedule_attributes(name: words[3], start_at: words[5], end_at: words[7])), line)
          elsif %w[set deactivate].include?(words[0]) && words[1, 2] == %w[security nat]
            nat_command(words.drop(3), line, disabled: words[0] == "deactivate")
          end
        end

        def address_command(zone, words, line, address_book: nil)
          scope = Algosec::Elements::Scope.new(device_id: @reader.device_id, address_book: address_book, zone: address_book ? nil : zone)
          if words[0] == "address" && words.size == 3
            ip, mask = ip_parts(words[2])
            capture(draft(:address, [ scope, words[1] ], name: words[1], zone: zone, scope: scope, member: [ address_leaf(ip, mask) ]), line)
          elsif words[0] == "address" && words.size == 6 && words[2] == "range-address" && words[4] == "to"
            member = { type: "iprange", value: "#{words[3]}-#{words[5]}" }
            capture(draft(:address, [ scope, words[1] ], name: words[1], zone: zone, scope: scope, member: [ member ]), line)
          elsif words[0] == "address-set" && %w[address address-set].include?(words[2])
            object = draft(:address_group, [ scope, words[1] ], name: words[1], zone: zone, scope: scope)
            (object.attributes[:members] ||= {})[words[3]] = nil
            capture(object, line)
          end
        end

        def build_services
          @drafts[:srx_service].each_value do |object|
            attributes = object.attributes
            unless attributes[:protocol]
              diagnose(:incomplete_service, "Application #{attributes[:name]} has no protocol", object.lines.first)
              next
            end
            attributes[:destination_port] ||= ANY_SERVICE_PORTS
            service = draft(:service, attributes[:name], name: attributes[:name])
            (service.attributes[:terms] ||= []) << attributes.except(:name)
            service.lines.concat(object.lines)
          rescue ArgumentError => error
            raise Algosec::Config::ParseError.new(error.message, line_number: object.lines.first.number)
          end
        end

        def nat_command(words, line, disabled:)
          direction = words[0]&.to_sym
          return unless %i[source destination static].include?(direction)
          if words[1] == "pool" && words[3] == "address" && direction != :static && !disabled
            previous = @drafts[:nat_pool][words[2]]
            if previous && previous.attributes[:direction] != direction
              previous.state[:ambiguous] = true
              capture(previous, line)
              return diagnose(:ambiguous_nat_pool, "Pool #{words[2]} is defined for both source and destination NAT", line)
            end
            object = draft(:nat_pool, words[2], name: words[2], direction: direction)
            case words.drop(4)
            in [ "port", port ] if /\A[0-9]+\z/.match?(port)
              if object.attributes[:port] && object.attributes[:port] != port
                diagnose(:ambiguous_nat_pool, "Pool #{words[2]} has conflicting translated ports", line)
              else
                object.attributes[:port] = port
              end
            in [ "port", * ]
              diagnose(:incomplete_nat_pool, "Pool #{words[2]} has an invalid port statement", line)
            in [ address ]
              (object.attributes[:ip] ||= []) << address unless object.attributes.fetch(:ip, []).include?(address)
            in [ first, "to", last ]
              address = "#{first} #{last}"
              (object.attributes[:ip] ||= []) << address unless object.attributes.fetch(:ip, []).include?(address)
            else
              diagnose(:incomplete_nat_pool, "Pool #{words[2]} has an invalid address or port statement", line)
            end
            capture(object, line)
          elsif words[1] == "rule-set"
            group = draft(:srx_nat_context, [ direction, words[2] ])
            if %w[from to].include?(words[3]) && %w[zone interface].include?(words[4])
              if words[4] == "interface"
                # 接口限定还决定规则集优先级，不能约成整个安全区域。
                group.state[:unsupported_context] = true
                diagnose(:unsupported_nat_context, "NAT rule-set #{words[2]} requires #{words[3]} interface matching", line)
              else
                key = (words[3] == "from") ? :from_zone : :to_zone
                group.attributes[key] = words[5]
              end
              capture(group, line)
            elsif words[3] == "rule"
              object = draft(:srx_nat_rule, [ direction, words[2], words[4] ], name: words[4], rule_set: words[2])
              object.state[:direction] = direction
              object.state[:context] = group
              rest = words.drop(5)
              if disabled
                object.state[:disabled] = true
              elsif rest[0] == "match" && %w[source-address destination-address].include?(rest[1])
                key = (rest[1] == "source-address") ? :source_set : :destination_set
                object.attributes[key] = (object.attributes[key] || Set.new) | IPAddr.parse(rest[2])
                object.state[:mapped_ip] = rest[2] if direction == :static && key == :destination_set
              elsif rest[0, 2] == %w[match destination-port]
                object.attributes[:destination_port] = rest[2]
              elsif rest[0] == "then"
                if rest[1, 2] == %w[static-nat prefix]
                  object.state[:real_ip] = rest[3]
                elsif %w[source-nat destination-nat].include?(rest[1]) && %w[pool interface].include?(rest[2])
                  object.state[:target] = rest.drop(2)
                else
                  return
                end
              else
                return
              end
              capture(object, line)
            end
          end
        end

        def build_nat
          @drafts[:nat_pool].each_value do |object|
            next if object.state[:ambiguous]
            unless object.attributes[:ip]
              diagnose(:incomplete_nat, "Pool #{object.attributes[:name]} has no address", object.lines.first)
              next
            end
            if object.attributes[:direction] == :destination
              zones = object.attributes[:ip].map { |address| zone_for(nat_pool_set(address)) }.uniq
              object.attributes[:zone] = zones.first if zones.one?
              if zones.size > 1
                diagnose(:ambiguous_nat_pool_zone, "Destination pool #{object.attributes[:name]} spans unknown or multiple zones", object.lines.first)
              end
            end
            emit_draft(:nat_pool, object)
          end
          @drafts[:srx_nat_rule].each_value do |object|
            group = object.state[:context]
            next if group.state[:unsupported_context]
            attributes = object.attributes.merge(group.attributes)
            lines = (group.lines + object.lines).sort_by(&:index)
            unless attributes[:from_zone]
              diagnose(:missing_nat_context, "NAT rule #{attributes[:name]} has no source zone", object.lines.first)
              next
            end
            if object.state[:disabled]
              diagnose(:unsupported_nat_status, "NAT #{attributes[:name]} is deactivated; status is not represented by Elements", object.lines.last)
            end
            if object.state[:direction] == :static
              real, mapped = object.state.values_at(:real_ip, :mapped_ip)
              unless real && mapped
                diagnose(:incomplete_nat, "Static NAT #{attributes[:name]} needs match and translation", object.lines.first)
                next
              end
              emit(:static_nat, { name: attributes[:name], rule_set: attributes[:rule_set],
                                  mapped_zone: attributes[:from_zone], real_zone: zone_for(real), real_ip: real, mapped_ip: mapped,
                                  real_set: IPAddr.parse(real), mapped_set: IPAddr.parse(mapped) }, lines)
              next
            end
            direction = object.state[:direction]
            attributes[:direction] = direction
            if (target = object.state[:target])
              pool = (target[0] == "pool") ? find(:nat_pool, target[1]) : nil
              if target[0] == "pool" && !pool
                diagnose(:missing_reference, "NAT pool #{target[1]}", object.lines.last)
              elsif direction == :source
                attributes[:source_pool] = pool
                attributes[:translated_source_set] = pool&.set || Set.new(*Array(find(:zone, attributes[:to_zone])&.interfaces&.values).filter_map { |interface| IPAddr.to_i(interface.host)..IPAddr.to_i(interface.host) if interface.host })
                attributes[:destination_set] = all_addresses if attributes[:destination_set].nil? || attributes[:destination_set].empty?
              else
                attributes.merge!(destination_pool: pool, translated_destination_set: pool&.set,
                                  translated_destination_port: pool&.port, to_zone: pool&.zone)
              end
              attributes[:source_set] = all_addresses if attributes[:source_set].nil? || attributes[:source_set].empty?
            end
            emit(:dynamic_nat, attributes, lines)
          end
        end

        # 目的 NAT 池可由单 IP、前缀或两个端点组成；路由查询接收统一地址集合。
        def nat_pool_set(expression)
          first, last = expression.split(" ", 2)
          first_set = IPAddr.parse(first)
          return first_set unless last
          last_set = IPAddr.parse(last)
          IPAddr.between(IPAddr.from_i(first_set.min), IPAddr.from_i(last_set.max))
        end

        def parse_rule(line, words)
          return unless %w[set deactivate].include?(words[0]) && words[1, 3] == %w[security policies from-zone] && words[5] == "to-zone" && words[7] == "policy"
          from, to, name = words.values_at(4, 6, 8)
          key = [ from, to, name ]
          object = draft(:rule, key, name: name, from_zones: [ from ], to_zones: [ to ])
          object.attributes[:rule_number] ||= @drafts[:rule].size if words[0] == "set"
          rest = words.drop(9)
          if words[0] == "deactivate"
            # 子条件停用不等于整条规则停用；保留诊断，禁止扩大后续规则的匹配范围。
            return unless rest.empty?
            object.attributes[:status] = "disable"
          elsif rest[0] == "match"
            dimension = { "source-address" => :sources, "destination-address" => :destinations, "application" => :services }[rest[1]]
            return unless dimension
            values = rest.drop(2).reject { |value| %w[[ ]].include?(value) }
            add_members(object, dimension, values, zone: (dimension == :sources) ? from : to, addresses: dimension != :services)
          elsif rest[0, 2] == %w[then log]
            return unless rest.size == 3 && %w[session-init session-close].include?(rest[2])
            object.attributes[:log] = [ *object.attributes[:log]&.split, rest[2] ].uniq.sort.join(" ")
            object.attributes[:log_enabled] = true
          elsif rest[0] == "then" && %w[permit deny reject].include?(rest[1])
            return unless rest.size == 2
            object.attributes[:action] = rest[1]
          elsif rest[0] == "scheduler-name"
            object.attributes[:schedule_name] = rest[1]
          else
            return
          end
          capture(object, line)
        end
      end
    end
  end
end
