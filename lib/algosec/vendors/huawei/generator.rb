# frozen_string_literal: true

require_relative "../../policy"
require_relative "nat/plan"
require_relative "nat/generation"

module Algosec
  module Vendors
    module Huawei
      # Huawei 生成对象、策略、时间和 NAT 命令。
      class Generator < Algosec::Policy::Generator
        command_policy placement: :append, permit: "permit", deny: "deny"
        command_frame before: [ "system-view" ], after: [ "return" ]
        # 根据新规则结果生成该厂商的完整策略命令。
        def create_rule
          create_nat_only
          write_rule(result.actions.fetch(:new))
        end

        # 把新增成员或 NAT 变更追加到已有策略，保留原规则范围。
        def modify_rule
          create_nat_only
          write_rule(result.actions.fetch(:add, {}), name: result.rule.name)
        end

        # 按厂商语法创建或复用服务对象，并返回命令引用。
        def create_service(value)
          return "any" if %w[any 0].include?(value.downcase)
          parts = service_parts(value)
          ports = (parts[:first] == parts[:last]) ? parts[:text] : "#{parts[:first]} to #{parts[:last]}"
          define_object(:service, parts, "#{parts[:protocol].upcase}_#{parts[:text]}", type: [ Algosec::Elements::ServiceObject, Algosec::Elements::ServiceGroup ]) do |name|
            emit("ip service-set #{identifier(name)} type object", "service 0 protocol #{parts[:protocol]} source-port 0 to 65535 destination-port #{ports}", "quit")
          end
        end

        # 把一次性时间条件转换为厂商计划命令。
        def create_schedule
          schedule_name do |name, schedule|
            emit("time-range #{identifier(name)}", "absolute-range #{schedule.start_at.strftime("%H:%M:%S %Y/%m/%d")} to #{schedule.end_at.strftime("%H:%M:%S %Y/%m/%d")}", "quit")
          end
        end

        # 按厂商语法创建或复用地址对象，并返回命令引用。
        def create_address(value, dimension:)
          address_argument(value)
        end

        # 校验静态 NAT 范围后生成转换命令，并登记可复用对象。
        def create_static_nat(record, direction:)
          require_modern_nat!
          unsupported_port_nat!
          real, mapped = equal_nat_ranges!(record)
          unless real[:prefix] == 32 && mapped[:prefix] == 32
            raise Algosec::Policy::Error.new("Huawei 静态 NAT 暂只生成主机映射", code: :unsupported_nat_range)
          end
          zone = (direction == :nat_sources) ? result.to_zone : result.from_zone
          key = [ zone, real[:first], mapped[:first] ]
          server_names = snapshot.elements(Algosec::Elements::DynamicNat).select { |nat| nat.rule_set == "nat-server" }.map(&:name)
          define_object(:static_nat, key, stable_name("nat", key), type: Algosec::Elements::StaticNat, occupied: server_names) do |name|
            command = "nat server #{identifier(name)} zone #{identifier(zone)} global #{mapped[:first]} inside #{real[:first]}"
            emit(command)
            @nat_evidence << Nat::Generation.server(snapshot: snapshot, command: command,
              zone: zone, real: real[:first], mapped: mapped[:first])
          end
        end

        protected

        # 在逐结果发射前规划整批交集，避免较早的目的规则挡住较晚的双向规则。
        def prepare_batch(results)
          @nat_plan = Nat::Plan.new(results)
          @nat_builder = Nat::Generation.new(snapshot)
          resolver = Algosec::Policy::Nat::Resolver.new(snapshot)
          @nat_plan.rules.each do |rule|
            resolver.validate_new_policy!(**rule.ranges.slice(:sources, :destinations),
              services: nat_services(rule), from_zone: rule.from_zone, to_zone: rule.to_zone)
          end
          registry.register_batch(:huawei_nat, @nat_plan.claims) { |previous| @nat_plan.validate_prior!(previous) }
        end

        def create_nat_only
          @nat_plan.static_for(result).each { |record, direction| create_static_nat(record, direction: direction == :source ? :nat_sources : :nat_destinations) }
          @nat_plan.rules_for(result).each { |rule| write_nat(rule) }
        end

        private

        def require_modern_nat!
          version = snapshot.software_version&.match(/V(\d+)R\d+/i)
          raise Algosec::Policy::Error.new("Huawei NAT 需要明确的 V500 或更新版本", code: :unsupported_version) unless version && version[1].to_i >= 500
        end

        # 双向规则使用目的转换后的目标选路，源转换仍使用原始源地址。
        def nat_interface(rule)
          specified = [ rule.source&.fetch(:interface), rule.destination&.fetch(:interface) ].compact.uniq
          if specified.size > 1
            raise Algosec::Policy::Error.new("双向 NAT 的两侧指定了不同出口接口", code: :ambiguous_nat_interface)
          end
          easy_ip = rule.source && rule.source[:target].nil?
          return unless easy_ip || specified.any?

          sources = rule.ranges.fetch(:sources)
          destinations = rule.destination ? rule.destination.fetch(:target) : rule.ranges.fetch(:destinations)
          route = Algosec::Elements::RoutingTable.new(snapshot.routes).lookup(
            source: sources, destination: destinations, vrf: snapshot.vrf(rule.from_zone), source_zone: rule.from_zone)
          unless route&.destination_interface
            raise Algosec::Policy::Error.new("Huawei NAT 缺少可确定的出口路由", code: :conditional_route)
          end
          selected = specified.first || route.destination_interface
          if selected != route.destination_interface
            raise Algosec::Policy::Error.new("Huawei NAT 指定接口与请求的出口路由不一致", code: :ambiguous_nat_interface)
          end
          interfaces = snapshot.zone(rule.to_zone).interfaces.values
          interfaces = interfaces.select { |interface| interface.name == selected }
          unless interfaces.one? && (!easy_ip || interfaces.first.host) && snapshot.egress_vrf(route) == snapshot.vrf(rule.from_zone)
            raise Algosec::Policy::Error.new("Huawei NAT 需要同路由域内确定的出口，Easy-IP 还需要接口主地址", code: :ambiguous_nat_interface)
          end
          interfaces.first
        rescue Algosec::Elements::RoutingTable::ConditionalRoute => error
          raise Algosec::Policy::Error.new(error.message, code: :conditional_route)
        end

        # 一条规划规则发射一次头部与两个可选动作，不再按方向拆成两条策略。
        def write_nat(rule)
          require_modern_nat!
          interface = nat_interface(rule)
          source_pool = create_pool(:source, rule.source[:target], name: rule.source[:pool_name]) if rule.source && rule.source[:target]
          destination_pool = create_pool(:destination, rule.destination[:target], name: rule.destination[:pool_name]) if rule.destination
          key = rule.key.merge(interface: interface&.name)
          define_object(:dynamic_nat, key, stable_name("policy_nat", key), type: Algosec::Elements::DynamicNat) do |name|
            offset = commands.size
            emit("nat-policy", "rule name #{identifier(name)}", "source-zone #{identifier(rule.from_zone)}", "destination-zone #{identifier(rule.to_zone)}")
            %i[sources destinations].each do |dimension|
              set = rule.ranges.fetch(dimension)
              next if set == Algosec::Set.new(0..IPAddr::IPV4_MAX)

              field = dimension == :sources ? "source-address" : "destination-address"
              set.each { |range| emit("#{field} #{address_argument(IPAddr.format_range(range))}") }
            end
            nat_services(rule).each_key do |service|
              next if service == "any"

              parts = service_parts(service)
              emit("service protocol #{parts[:protocol]} destination-port #{parts[:first]}")
            end
            emit("egress-interface #{identifier(interface.name)}") if interface
            emit("action source-nat #{source_pool ? "address-group #{identifier(source_pool)}" : "easy-ip"}") if rule.source
            if rule.destination
              action = "action destination-nat address-group #{identifier(destination_pool)}"
              action += " #{rule.destination[:port]}" if rule.destination[:port]
              emit(action)
            end
            emit("quit", "quit")
            begin
              @nat_evidence << @nat_builder.rule(commands: commands.drop(offset), approved: rule)
            rescue Algosec::Policy::Error => error
              record_proof_issue(error)
            end
          end
        end

        def nat_services(rule)
          set = rule.ranges.fetch(:services)
          return { "any" => { origin: "any" } } if set == Algosec::Set.new(0..IPAddr::SERVICE_MAX)

          unless set.cardinality == 1
            raise Algosec::Policy::Error.new("Huawei NAT 端口映射需要单一原始服务", code: :unsupported_port_nat)
          end
          value = "#{set.min >> 16}/#{set.min & IPAddr::PORT_MAX}"
          { value => { origin: value } }
        end

        def address_argument(value)
          parts = address_parts(value)
          parts[:prefix] ? "#{parts[:first]} #{parts[:prefix]}" : "range #{parts[:first]} #{parts[:last]}"
        end

        # 三个以上地址用一个确定名称的地址对象，编号是设备成员序号。
        def address_members(members)
          return members.sort.map { |value, names| names ? "address-set #{identifier(names.first)}" : address_argument(value) } if members.size <= 3
          set = Algosec::Policy::Ranges.addresses(members.keys)
          name = define_object(:address, set, stable_name("addrgroup", set), type: [ Algosec::Elements::AddressObject, Algosec::Elements::AddressGroup ]) do |selected|
            command_block("ip address-set #{identifier(selected)} type object", close: "quit") do
              set.each_with_index do |range, index|
                parts = address_parts(IPAddr.format_range(range))
                definition = parts[:prefix] ? "#{parts[:first]} mask #{parts[:prefix]}" : "range #{parts[:first]} #{parts[:last]}"
                emit("address #{index} #{definition}")
              end
            end
          end
          [ "address-set #{identifier(name)}" ]
        end

        def write_rule(action, name: nil)
          addresses = %i[sources destinations].to_h { |dimension| [ dimension, address_members(action.fetch(dimension, {})) ] }
          services = action.fetch(:services, {}).sort.map { |value, names| names ? names.first : create_service(value) }
          return if name && addresses.values.all?(&:empty?) && services.empty?
          addresses.each { |dimension, members| remember_members(dimension, members) }
          remember_members(:services, services.uniq)
          require_members!(addresses.merge(services: services)) unless name
          schedule = create_schedule unless name
          selected = name || rule_name("policy")
          emit("security-policy", "rule name #{identifier(selected)}")
          emit("source-zone #{identifier(result.from_zone)}", "destination-zone #{identifier(result.to_zone)}") unless name
          addresses.each do |dimension, values|
            field = (dimension == :sources) ? "source-address" : "destination-address"
            values.each { |value| emit("#{field} #{value}") }
          end
          services.uniq.each { |service| emit("service #{identifier(service)}") }
          emit("time-range #{identifier(schedule)}") if schedule
          emit("action #{policy_action}") unless name
          emit("quit", "quit")
          record_created_rule(name: selected) unless name
        end

        def create_pool(kind, set, name: nil)
          pools = snapshot.elements(Algosec::Elements::NatPool)
          candidates = pools.select { |pool| pool.direction == kind && pool.set == set && pool.port.nil? && (kind != :source || pool.mode == "pat") }
          if name
            existing = candidates.find { |pool| pool.name == name }
            unless existing
              raise Algosec::Policy::Error.new("指定的 Huawei NAT 地址池与转换目标或模式不一致", code: :nat_pool_mismatch)
            end
          else
            existing = candidates.min_by(&:name)
          end
          return existing.name if existing
          key = [ kind, set ]
          define_object(:pool, key, stable_name("natPool", key), type: Algosec::Elements::NatPool) do |name|
            offset = commands.size
            emit("#{(kind == :source) ? "nat" : "destination-nat"} address-group #{identifier(name)}")
            emit("mode pat") if kind == :source
            set.each_with_index { |range, index| emit("section #{index} #{IPAddr.from_i(range.begin)} #{IPAddr.from_i(range.end)}") }
            emit("quit")
            @nat_builder.pool(commands.drop(offset))
          end
        end
      end
    end
  end
end
