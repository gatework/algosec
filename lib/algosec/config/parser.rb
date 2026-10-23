# frozen_string_literal: true

require_relative "incomplete_configuration"
require_relative "parse_error"
require "shellwords"
require_relative "reader"
require_relative "result"
require_relative "parser/syntax"

module Algosec
  module Config
    # 每次解析独占读取器、草稿、内建对象、引用和报告。
    # 厂商解析器先收集命令，再构造不可变的元素身份。
    class Parser
      extend Declarations
      extend Syntax
      include Syntax::Runtime
      Line = Data.define(:index, :text) do
        # 返回面向用户的从一开始计数的行号。
        def number = index + 1
      end
      Draft = Struct.new(:attributes, :lines, :state)
      TYPES = {
        address: Elements::AddressObject, address_group: Elements::AddressGroup,
        service: Elements::ServiceObject,
        service_group: Elements::ServiceGroup, schedule: Elements::Schedule,
        rule: Elements::SecurityRule, rule_binding: Elements::RuleBinding, route: Elements::Route, interface: Elements::Interface,
        zone: Elements::Zone, nat_pool: Elements::NatPool,
        static_nat: Elements::StaticNat, dynamic_nat: Elements::DynamicNat
      }.freeze
      # 集中保存配置语法反复使用的通配端口和 IPv4 文本，避免厂商解析器散落数字字面量。
      ANY_SERVICE_PORTS = Elements::Definition::ANY_PORTS
      NONZERO_SERVICE_PORTS = "1-#{IPAddr::PORT_MAX}".freeze
      WILDCARD_IPV4 = "0.0.0.0".freeze

      # 根据输入读取器或显式厂商选择解析器实例并开始解析。
      def self.perform(input, vendor: nil, source_complete: true, settings: {}, **options)
        raise ArgumentError, "Parser settings must be a Hash" unless settings.is_a?(Hash)
        vendor ||= input.vendor if input.is_a?(Reader)
        implementation = Vendors.fetch(vendor, :parser)
        implementation.new(**implementation.options(settings), **options).perform(input, source_complete: source_complete)
      end

      # 厂商在此把保存设置转换为构造参数，公共选项仍由调用方显式传入。
      def self.options(_settings) = {}

      # 保存解析选项，复制内建服务模板，并固定时间和严格模式。
      def initialize(builtin_services: {}, device_id: nil, device_name: nil,
                     time_zone: "UTC", reference_time: Time.current, strict: false, dns_resolver: nil)
        unless builtin_services.is_a?(Hash) && builtin_services.values.all? { |service| service.is_a?(Elements::ServiceObject) }
          raise ArgumentError, "Built-in services must map names to Service objects"
        end
        @builtin_templates = builtin_services.dup.freeze
        @device_id, @device_name = device_id, device_name
        raise ArgumentError, "Strict must be true or false" unless strict == true || strict == false
        unless reference_time.is_a?(Time) || reference_time.is_a?(ActiveSupport::TimeWithZone)
          raise ArgumentError, "Reference time must be a Time"
        end
        @time_zone = Time.find_zone!(time_zone)
        @default_time_zone = @time_zone
        @reference_time = reference_time.dup.freeze
        @strict = strict
        @dns_resolver = dns_resolver
      end

      def parsing_settings = {}.freeze

      # 重置读取状态，执行厂商文档解析，生成目录和诊断结果。
      def perform(input, source_complete: true)
        raise ArgumentError, "Source completeness must be boolean" unless source_complete == true || source_complete == false
        @time_zone = @default_time_zone
        @syntax = self.class.declarations
        @reader = input.is_a?(Reader) ? input : Reader.new(input, vendor: self.class::VENDOR,
                                                           device_id: @device_id, device_name: @device_name, created_at: @reference_time, source_complete: source_complete)
        if input.is_a?(Reader)
          @reader = Reader.new(input.content, vendor: input.vendor, device_id: input.device_id,
            device_name: input.device_name, created_at: input.created_at, source_complete: source_complete && input.source_complete?)
        end
        raise ArgumentError, "Reader vendor differs from parser" unless @reader.vendor == self.class::VENDOR
        @reader.reset!
        @catalog = Elements::Catalog.new(vendor: vendor, device_id: @reader.device_id)
        @drafts = Hash.new { |hash, type| hash[type] = {} }
        @diagnostics, @origins, @builtins = [], {}, {}
        @diagnostic_keys = {}
        diagnose(:incomplete_source, "Configuration source is incomplete") unless @reader.source_complete?
        @lines = @reader.lines.each_with_index.map { |text, index| Line.new(index, text.sub(/(?:\r\n|\r|\n)\z/, "")) }
        @lines.each { |line| consume(line) if line.text.blank? }
        interpret_document
        @lines.each do |line|
          diagnose(:unsupported_command, "Unrecognized command: #{line.text.strip}", line) unless @reader.parsed?(line.index) || !diagnostic_line?(line)
        end
        builtins = @builtin_templates.to_h { |name, _template| [ name, builtin(name) ] }
        result = Result.new(reader: @reader, catalog: @catalog, diagnostics: @diagnostics, at: @reference_time,
                            builtin_services: builtins, dns_context: @dns_resolver&.context, time_zone: @time_zone, parsing_settings: parsing_settings, definition_id: vendor.to_s)
        raise IncompleteConfiguration, result if @strict && !result.complete?
        result
      rescue Elements::Group::CircularReference, Elements::Catalog::AmbiguousReference => error
        raise ParseError, error.message
      end

      private

      # 执行具体文档解析和引用装配，并把底层参数错误关联到当前行。
      def interpret_document
        @current_line = nil
        parse_document
        resolve_references
      rescue ArgumentError, IndexError => error
        raise ParseError.new(error.message, line_number: @current_line&.number)
      end

      # 返回当前输入的厂商。
      def vendor = @reader.vendor

      # 构造创建元素时共享的设备上下文。
      def context = { vendor: vendor, device_id: @reader.device_id }

      # 返回覆盖全部 IPv4 地址的集合。
      def all_addresses = Set.new(0..IPAddr::IPV4_MAX)

      # 返回覆盖全部服务编码的集合。
      def all_services = Set.new(0..IPAddr::SERVICE_MAX)

      # 按源行顺序拼接配置文本，避免重复消费同一行。
      def config_text(lines) = lines.uniq(&:index).sort_by(&:index).map(&:text).join("\n")

      # 标记一组行已被解析器消费。
      def consume(*lines) = lines.flatten.each { |line| @reader.mark(line.index) }

      # 厂商可将未建模业务排除在完整性诊断之外，原文仍保留。
      def diagnostic_line?(_line) = true

      # 返回当前仍未被消费的行。
      def pending = @lines.reject { |line| @reader.parsed?(line.index) }

      # 以 Shellwords 规则拆分一行，并记录当前错误定位行。
      def tokens(line)
        @current_line = line
        Shellwords.split(line.text)
      rescue ArgumentError => error
        raise ParseError.new(error.message, line_number: line.number)
      end

      # 取得或创建指定类型和身份键的草稿，并合并新增属性。
      def draft(type, key, **attributes)
        draft = (@drafts[type][key] ||= Draft.new({}, [], {}))
        draft.attributes.merge!(attributes)
        draft
      end

      # 把源行归属到草稿，并同步标记为已消费。
      def capture(draft, *lines)
        draft.lines.concat(lines.flatten)
        consume(*lines)
        draft
      end

      # 记录去重后的诊断信息；同一代码、消息和行只保留一次。
      def diagnose(code, message, line = nil)
        diagnostic = Diagnostic.new(code, message, line&.number)
        unless @diagnostic_keys[diagnostic]
          @diagnostic_keys[diagnostic] = true
          @diagnostics << diagnostic
        end
        nil
      end

      # 从属性和源行构造领域对象，加入目录并记录对象来源。
      def emit(type, attributes, lines = [])
        element = TYPES.fetch(type).new(**context, **attributes, config: config_text(lines))
        element.resolve_domains!(@dns_resolver) if @dns_resolver && element.is_a?(Elements::AddressObject)
        if element.is_a?(Elements::SecurityRule)
          diagnose(:unknown_rule_action, "Unknown rule action: #{element.native_action.inspect}", lines.first) unless element.action_known?
          diagnose(:unknown_rule_status, "Unknown rule status: #{element.status.inspect}", lines.first) unless element.status_known?
        end
        @catalog.add(element)
        @origins[element.object_id] = lines.first
        element
      rescue ArgumentError => error
        raise ParseError.new("#{type}: #{error.message}", line_number: lines.first&.number)
      end

      # 将草稿属性和附加属性一次性发射为领域对象。
      def emit_draft(type, draft, **overrides) = emit(type, draft.attributes.merge(overrides), draft.lines)

      # 在目录中查找类型和作用域匹配的对象，并兼容 NAT 池别名。
      def find(type, name, **scope)
        return nil if name.nil?
        element = @catalog.find(TYPES.fetch(type), name: name, **scope)
        element ||= @catalog.detect { |candidate| candidate.is_a?(Elements::NatPool) && candidate.alias_name == name } if type == :nat_pool
        element
      end

      # 设备的显式定义优先于厂商目录，支持局部修改内置服务的端口或超时。
      def service(name)
        find(:service, name) || find(:service_group, name) || builtin(name)
      end

      # 按名称缓存并克隆内建服务，避免修改共享模板。
      def builtin(name)
        return @builtins[name] if @builtins.key?(name)
        template = @builtin_templates[name]
        @builtins[name] = template && clone_service(template, name: name)
      end

      # 克隆内建服务及其服务项，同时按当前厂商重新编码协议。
      def clone_service(template, name: template.name)
        Elements::ServiceObject.new(**context, name: name, terms: template.terms)
      end

      # 用宽松模式装配所有引用，并把缺失引用转换为诊断信息。
      def resolve_references
        @catalog.resolve!(strict: false, on_missing: lambda { |owner, name|
          diagnose(:missing_reference, "#{owner.class.name.split("::").last} #{owner.name}: #{name}", @origins[owner.object_id])
        }) do |_owner, name, types|
          service(name) if types.include?(Elements::ServiceObject)
        end
      end

      # 按依赖顺序发射地址、服务和时间计划等普通对象。
      def emit_objects
        %i[address address_group service service_group schedule].each do |type|
          @drafts[type].each_value { |object| emit_draft(type, object) }
        end
      end

      # 发射规则，再把规则草稿中的各维度成员加入对应组。
      def emit_rules
        @drafts[:rule].each_value do |object|
          rule = emit_draft(:rule, object)
          %i[sources destinations services].each do |dimension|
            Array(object.state[dimension]).each do |member|
              name, value = member.is_a?(Array) ? member : [ member, nil ]
              rule.public_send(dimension).add(name, value)
            end
            group = rule.public_send(dimension)
            @origins[group.object_id] = object.lines.first if group
          end
        end
      end

      # 解析任意地址关键字；必要时创建占位地址对象并保留作用域。
      def address_reference(name, zone: nil, dimension: nil)
        if any_address?(name, dimension: dimension)
          scope = address_reference_scope(zone)
          address = find(:address, name, **scope) || emit(:address, { name: name, member: [ any_address_member(name, dimension: dimension) ], **scope })
          [ name, address ]
        else
          name
        end
      end

      # 任意地址的地址族语义由厂商显式声明，不能从 IPv4 /0 反推双栈。
      def any_address_member(_name, dimension: nil) = address_leaf(WILDCARD_IPV4, 0)

      # 把成员名称追加到草稿维度，并按需要先转换为地址引用。
      def add_members(object, dimension, values, zone: nil, addresses: false)
        (object.state[dimension] ||= []).concat(values.map { |name| addresses ? address_reference(name, zone: zone, dimension: dimension) : name })
      end

      # 将地址和可选掩码拆成主机文本及规范前缀长度。
      def ip_parts(expression, mask = nil)
        ip, prefix = expression.split("/", 2)
        [ ip, IPAddr.prefix_length(mask || prefix || 32) ]
      end

      # 厂商 IP/掩码语法在解析边界转换为统一叶子。
      def address_leaf(expression, mask = nil)
        cidr = IPAddr.network_cidr(expression, mask)
        cidr.end_with?("/32") ? { type: "host", value: cidr.delete_suffix("/32") } : { type: "subnet", value: cidr }
      end

      # 创建或复用直连路由草稿，并保留其来源行。
      def connected_route(interface, ip, mask, line, next_hop: nil)
        route = draft(:route, [ :connected, interface.attributes[:name], ip, mask ],
                      subnet: IPAddr.network_cidr(ip, mask), destination_interface: interface.attributes[:name], next_hop: next_hop)
        route.state[:connected] = true
        capture(route, line)
      end

      # 路由数值在语法边界校验；字段取值范围由厂商声明。
      def route_number(value, field, range = nil)
        raise ArgumentError, "Route #{field} must be numeric" unless /\A[0-9]+\z/.match?(value.to_s)
        number = Integer(value, 10)
        if range && !range.cover?(number)
          raise ArgumentError, "Route #{field} must be between #{range.begin} and #{range.end}"
        end
        number
      end

      # 草稿须先确定 VRF；用最长直连前缀定位唯一出口，不按接口登记顺序取首项。
      def resolve_route_target(object)
        attributes = object.attributes
        target_vrf = attributes[:destination_vrf] || attributes[:vrf]
        if attributes[:destination_interface]
          target = @drafts[:interface][attributes[:destination_interface]]
          if target && target.attributes[:vrf] != target_vrf
            (attributes[:extra_conf] ||= {})["unresolved_interface"] = attributes.delete(:destination_interface)
            diagnose(:conflicting_vrf, "Route and interface belong to different VRFs", object.lines.first)
          end
          return
        end
        if attributes[:destination_vrf] && !attributes[:next_hop]
          return diagnose(:unsupported_route_target, "Route lookup through VRF #{target_vrf} requires a next hop or interface", object.lines.first)
        end
        return unless attributes[:next_hop]

        hop = IPAddr.parse(attributes[:next_hop])
        candidates = @drafts[:route].values.select do |route|
          route.state[:connected] && route.attributes[:vrf] == target_vrf && IPAddr.parse(route.attributes[:subnet]).cover?(hop)
        end
        prefix = candidates.map { |route| IPAddr.new(route.attributes[:subnet]).prefix }.max
        targets = candidates.select { |route| IPAddr.new(route.attributes[:subnet]).prefix == prefix }
                            .map { |route| route.attributes[:destination_interface] }.uniq
        if targets.one?
          attributes[:destination_interface] = targets.first
        else
          diagnose(:missing_interface, "Cannot uniquely locate next hop #{attributes[:next_hop]} in #{target_vrf}", object.lines.first)
        end
      end

      # 发射接口、解析路由目标、连接 VLAN，并最终发射区域对象。
      def finish_network
        # 接口显式 VRF 优先，区域可补齐缺失值；冲突保留原值并报告。
        @drafts[:interface].each_value do |object|
          zone_vrf = @drafts[:zone][object.attributes[:zone]]&.attributes&.fetch(:vrf, nil)
          explicit = object.attributes[:vrf]
          if explicit && zone_vrf && explicit != zone_vrf
            diagnose(:conflicting_vrf, "Interface #{object.attributes[:name]} VRF #{explicit} differs from zone #{zone_vrf}", object.lines.first)
          end
          object.attributes[:vrf] ||= zone_vrf || "default"
        end
        interfaces = @drafts[:interface].transform_values { |object| emit_draft(:interface, object) }
        @drafts[:route].each_value do |object|
          attributes = object.attributes
          target = interfaces[attributes[:destination_interface]]
          if attributes[:destination_interface] && !target
            diagnose(:missing_interface, "Unknown route interface #{attributes[:destination_interface]}", object.lines.first)
          elsif target.nil? && attributes[:next_hop]
            target = interfaces[attributes[:next_hop]]
            unless target
              begin
                next_hop = IPAddr.parse(attributes[:next_hop])
                target = interfaces.values.find do |interface|
                  interface.host && interface.connected_set.cover?(next_hop) &&
                    route_interface?(interface, attributes)
                end
              rescue ArgumentError
                diagnose(:missing_interface, "Unknown route interface #{attributes[:next_hop]}", object.lines.first)
              end
            end
          end
          attributes[:zone] ||= target&.zone
          attributes[:destination_interface] ||= target&.name
          prepare_route(object, target)
          route = emit_draft(:route, object)
          target&.add_route(route)
        end
        link_interface_members(interfaces)
        @drafts[:zone].each_value do |object|
          members = Array(object.state[:interfaces]).uniq.filter_map do |name|
            interfaces[name] || diagnose(:missing_interface, "Zone #{object.attributes[:name]}: #{name}", object.lines.first)
          end
          prepare_zone(object, members)
          if members.map(&:vrf).uniq.size > 1
            diagnose(:conflicting_vrf, "Zone #{object.attributes[:name]} contains interfaces in different VRFs", object.lines.first)
          end
          emit_draft(:zone, object, interfaces: members)
        end
      end

      # 只用已证明覆盖整个目标范围的静态路由推导 NAT 区域。
      def zone_for(expression, vrf: nil)
        routes = @catalog.select { |element| element.is_a?(Elements::Route) }
        Elements::RoutingTable.new(routes).lookup_static(destination: expression, vrf: vrf)&.zone
      rescue Elements::RoutingTable::ConditionalRoute => error
        diagnose(:ambiguous_route, error.message, @current_line)
      end

      # 厂商可覆盖此钩子，用于把接口和 VLAN 草稿连接起来。
      def link_interface_members(interfaces) end

      # 判断文本是否表示任意地址。
      def any_address?(name, dimension: nil) = /\A(?:any|all)\z/i.match?(name)

      # 判断 NAT 地址文本是否表示任意地址。
      def any_nat_address?(name) = /\A(?:any|all)\z/i.match?(name)

      # 返回地址引用作用域；厂商可覆盖以加入区域或 VRF。
      def address_reference_scope(_zone) = {}

      # 判断候选接口能否承载路由；厂商可覆盖此钩子。
      def route_interface?(interface, attributes) = true

      # 厂商在发射路由前补齐或调整路由属性。
      def prepare_route(object, target) end

      # 厂商在发射区域前补齐区域属性。
      def prepare_zone(object, members) end

      # 同时创建接口和区域草稿，并记录区域的接口成员。
      def bind_zone(interface_name, zone_name, line, record_zone: true)
        interface = draft(:interface, interface_name, name: interface_name, zone: zone_name)
        zone = draft(:zone, zone_name, name: zone_name)
        (zone.state[:interfaces] ||= []) << interface_name
        record_zone ? capture(zone, line) : consume(line)
        interface
      end

      # 为时间计划补充当前解析器的时区和参考时间。
      def schedule_attributes(**attributes)
        { time_zone: @time_zone, reference_time: @reference_time, **attributes }
      end

      # 从起始行读取到终止模式，返回行数组和下一读取位置。
      def block_at(index, terminator:, stop: nil, include_end: false)
        rows = [ @lines[index] ]
        consume(@lines[index])
        index += 1
        while index < @lines.size
          line = @lines[index]
          if terminator.match?(line.text.strip)
            consume(line)
            rows << line if include_end
            return [ rows, index + 1 ]
          end
          break if stop&.match?(line.text.strip)
          rows << line
          index += 1
        end
        [ rows, index ]
      end

      # 将字面量地址表达式转换为临时地址对象。
      def literal_reference(expression, line = nil)
        leaf = expression.include?("-") ? { type: "iprange", value: expression } : address_leaf(expression)
        object = Elements::AddressObject.new(**context, name: expression, member: [ leaf ], config: line&.text)
        [ expression, object ]
      end

      # 将地址名称或文本转换为匹配集合，缺失时记录诊断。
      def lookup_address_set(expression, line = nil)
        return nil if expression.nil?
        return all_addresses if any_nat_address?(expression)
        object = find(:address, expression) || find(:address_group, expression)
        if object
          diagnose(:conditional_nat_address, "NAT address #{expression} depends on DNS", line) if object.conditional?
          unless object.resolved?
            diagnose(:unresolved_address, "Address #{expression} has unresolved members", line)
            return nil
          end
          return object.set
        end
        return IPAddr.parse(expression) if /\A\d+\./.match?(expression)
        diagnose(:missing_reference, "Address #{expression}", line)
      end

      # 将服务名称转换为服务集合，服务组按协议端口投影展开。
      def lookup_service_set(name, line = nil)
        return nil if name.nil?
        object = service(name)
        return diagnose(:missing_reference, "Service #{name}", line) unless object
        object.is_a?(Elements::ServiceGroup) ? service_projection(object.ports) : object.set
      end

      # 把协议到端口的映射编码成统一服务集合。
      def service_projection(ports)
        Set.new(*ports.flat_map { |protocol, ranges| ranges.flat_map { |range| IPAddr.service("#{protocol}/#{range.begin}-#{range.end}").ranges } })
      end

      # 根据路由表计算从源到目的的出口地址。
      def egress_address(source_set, destination_set, vrf: nil)
        interface = egress_interface(source_set, destination_set, vrf: vrf)
        interface&.host && IPAddr.parse(interface.host)
      end

      def egress_interface(source_set, destination_set, vrf: nil)
        return nil unless source_set && destination_set
        routes = @catalog.select { |element| element.is_a?(Elements::Route) }
        table = Elements::RoutingTable.new(routes)
        route = table.lookup(source: source_set, destination: destination_set, vrf: vrf)
        route && find(:interface, route.destination_interface)
      rescue Elements::RoutingTable::ConditionalRoute => error
        diagnose(:conditional_route, error.message, @current_line)
      end

      # 将端口文本转换为十进制整数。
      def port_number(value) = Integer(value, 10)

      # gt/lt 不包含给定端口；由服务边界拒绝越界或空范围。
      def port_condition(words, lower: 0)
        operator, first, last = words
        first = port_number(first)
        raise ArgumentError, "Port must be between 0 and #{IPAddr::PORT_MAX}" unless (0..IPAddr::PORT_MAX).cover?(first)
        case operator
        when "eq" then first.to_s
        when "range" then "#{first}-#{port_number(last)}"
        when "gt" then "#{first + 1}-#{IPAddr::PORT_MAX}"
        when "lt" then "#{lower}-#{first - 1}"
        else raise ParseError, "Unknown port operator #{operator.inspect}"
        end
      end

      # 内联引用键保留源端口，避免同协议、同目的端口的不同条件互相覆盖。
      def literal_service(protocol, destination_port = ANY_SERVICE_PORTS, source_port: nil)
        protocol = "any" if protocol == "ip"
        name = "#{protocol}/#{destination_port}"
        key = source_port ? "#{name}:source/#{source_port}" : name
        [ key, Elements::ServiceObject.new(**context, name: name, protocol: protocol,
                                    destination_port: destination_port, source_port: source_port) ]
      end
    end
  end
end
