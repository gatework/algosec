# frozen_string_literal: true

require_relative "../../policy"

module Algosec
  module Vendors
    module H3c
      # H3C 生成对象组、ACL、时间和 NAT 命令。
      class Generator < Algosec::Policy::Generator
        command_policy placement: :append, permit: "pass", deny: "drop"
        command_operation :remove_rule, using: :remove_rule
        command_frame before: [ "sys" ], after: [ "save" ]
        command_fields sources: "source-ip", destinations: "destination-ip", services: "service"

        # 只删除对象策略中的指定规则，ACL 使用不同的视图和依赖协议。
        def remove_rule(rule)
          unless rule.native_rule_type == :object
            raise Algosec::Policy::Error.new("H3C ACL 回收需要专用适配", code: :unsupported_operation)
          end
          emit("object-policy ip #{literal_identifier(rule.rule_set)}", "undo rule #{numeric_identifier(rule.native_rule_id)}", "quit")
        end

        # 根据新规则结果生成该厂商的完整策略命令。
        def create_rule
          policy = policy_name
          members = prepare(result.actions.fetch(:new))
          require_members!(members)
          schedule = create_schedule
          used = snapshot.rules.select { |rule| rule.native_rule_type == :object && rule.rule_set&.casecmp?(policy) }.map(&:native_rule_id)
          id = available_id([ :policy_id, policy.downcase ], rule_key, 0..65534, used)
          first = command_fields.map { |dimension, field| "#{field} #{identifier(members[dimension].first)}" }
          command = "rule #{id} #{policy_action} #{first.join(" ")}"
          command += " time-range #{identifier(schedule)}" if schedule
          additions = command_fields.flat_map do |dimension, field|
            members[dimension].drop(1).map { |name| "rule #{id} append #{field} #{identifier(name)}" }
          end
          emit("object-policy ip #{identifier(policy)}", command, *additions, "exit")
          record_created_rule(native_rule_id: id, rule_set: policy)
        end

        # 把新增成员或 NAT 变更追加到已有策略，保留原规则范围。
        def modify_rule
          policy = policy_name
          members = prepare(result.actions[:add])
          create_nat_only
          id = numeric_identifier(result.rule.native_rule_id)
          additions = command_fields.flat_map do |dimension, field|
            members[dimension].map do |name|
              action = name.casecmp?("any") ? policy_action(snapshot.behavior.rule_decision(result.rule)) : "append"
              "rule #{id} #{action} #{field} #{identifier(name)}"
            end
          end
          emit("object-policy ip #{identifier(policy)}", *additions, "exit") unless additions.empty?
        end

        # 按厂商语法创建或复用地址对象，并返回命令引用。
        def create_address(value, dimension:)
          parts = address_parts(value)
          return "any" if parts[:prefix] == 0
          define_address(parts)
        end

        # 按厂商语法创建或复用服务对象，并返回命令引用。
        def create_service(value)
          return "any" if %w[any 0].include?(value.downcase)
          parts = service_parts(value)
          ports = (parts[:first] == parts[:last]) ? "eq #{parts[:first]}" : "range #{parts[:first]} #{parts[:last]}"
          preferred = "#{parts[:protocol].upcase}_#{parts[:text].tr("-", "_")}"
          define_group(:service, parts, preferred) do |name|
            emit("object-group service #{identifier(name)}", "service #{parts[:protocol]} destination #{ports}", "exit")
          end
        end

        # 把一次性时间条件转换为厂商计划命令。
        def create_schedule
          schedule_name do |name, schedule|
            # time-range 是系统视图单行命令，不进入子视图，不能额外退出系统视图。
            emit("time-range #{identifier(name)} from #{schedule.start_at.strftime("%H:%M %m/%d/%Y")} to #{schedule.end_at.strftime("%H:%M %m/%d/%Y")}")
          end
        end

        # 校验静态 NAT 范围后生成转换命令，并登记可复用对象。
        def create_static_nat(record, direction:)
          unsupported_port_nat!
          unless %i[nat_sources nat_destinations].include?(direction)
            raise Algosec::Policy::Error.new("H3C 不支持该静态 NAT 方向", code: :unsupported_nat_direction)
          end
          real, mapped = equal_nat_ranges!(record)
          unless real[:prefix] && mapped[:prefix]
            raise Algosec::Policy::Error.new("H3C 静态 NAT 需要对齐的等长网段", code: :unsupported_nat_range)
          end
          interface = identifier(record.fetch(:nat).fetch(:interface) do
            raise Algosec::Policy::Error.new("静态 NAT 缺少启用接口", code: :nat_interface_missing)
          end)
          # outbound 同时提供内部源转换和外部访问时的目标还原；inbound 是外部主机别名。
          command = if real[:prefix] == 32
                      "nat static outbound #{real[:first]} #{mapped[:first]}"
          else
                      names = [ real, mapped ].map { |parts| identifier(define_address(parts)) }
                      "nat static outbound object-group #{names.first} object-group #{names.last}"
          end
          once(command) { emit(command) }
          once([ :static_nat_enable, interface ]) do
            emit("interface #{interface}", "nat static enable", "exit")
          end
        end

        # 按方向和分配组生成动态 NAT 命令，保持请求分组边界。
        def create_dynamic_nat(groups, direction:)
          unsupported_port_nat!
          groups.each do |records|
            nat = records.first.fetch(:nat)
            interface = identifier(nat.fetch(:interface) { raise Algosec::Policy::Error, "NAT 缺少出口接口" })
            if direction == :nat_sources
              sources = Algosec::Policy::Ranges.addresses(records.map { |record| record.fetch(:real_ip) })
              acl = create_acl(sources, Algosec::Policy::Ranges.addresses(result.destinations.keys))
              command = "nat outbound #{acl.match?(/\A\d+\z/) ? acl : "name #{identifier(acl)}"}"
              if nat[:address]
                pool = create_pool(nat[:address])
                command += pool.match?(/\A\d+\z/) ? " address-group #{pool}" : " address-group name #{identifier(pool)}"
              end
              once([ interface, command ]) { emit("interface #{interface}", command, "exit") }
            else
              records.each do |record|
                real, mapped = equal_nat_ranges!(record)
                endpoints = [ mapped, real ].map { |parts| (parts[:set].cardinality == 1) ? parts[:first] : "#{parts[:first]} #{parts[:last]}" }
                command = "nat server global #{endpoints.first} inside #{endpoints.last}"
                once([ interface, command ]) { emit("interface #{interface}", command, "exit") }
              end
            end
          end
          nil
        end

        private

        # any 覆盖同维度其他成员；选择对象之前归一，保证命令和引用报告一致。
        def select_members(members, dimension)
          ranges = members.keys.map do |value|
            dimension == :services ? Algosec::Policy::Ranges.service(value) : IPAddr.parse(value)
          end
          maximum = dimension == :services ? IPAddr::SERVICE_MAX : IPAddr::IPV4_MAX
          ranges.include?(Set.new(0..maximum)) ? [ "any" ] : super
        end

        # NAT 引用必须是实际地址对象；策略的 any 关键字不能代替 /0 地址对象。
        def define_address(parts)
          definition = case parts[:prefix]
          when 32 then "host address #{parts[:first]}"
          when nil then "range #{parts[:first]} #{parts[:last]}"
          else "subnet #{parts[:first]} #{IPAddr.netmask(parts[:prefix])}"
          end
          preferred = parts[:prefix] == 0 ? "Net_#{parts[:text]}" : address_name(parts)
          define_group(:address, parts[:set], preferred) do |name|
            emit("object-group ip address #{identifier(name)}", "network #{definition}", "exit")
          end
        end

        # 地址组和服务组共享设备名称空间，本批新建对象也共用分配记录。
        def define_group(kind, key, preferred, &block)
          types = [ Algosec::Elements::AddressObject, Algosec::Elements::AddressGroup,
                    Algosec::Elements::ServiceObject, Algosec::Elements::ServiceGroup ]
          occupied = types.flat_map { |type| snapshot.elements(type).map(&:name) } + snapshot.builtin_services.map(&:name)
          define_object(:object_group, [ kind, key ], preferred, occupied: occupied, case_sensitive: false, &block)
        end

        # 查询与直接生成入口共用绑定证据，不按名称任选策略或改写其他区域。
        def policy_name
          scope = { from_zone: result.from_zone, to_zone: result.to_zone }
          if result.rule && result.rule.native_rule_type != :object
            raise Algosec::Policy::Error.new("H3C ACL 修改需要专用适配", code: :unsupported_operation)
          end
          names = snapshot.behavior.active_bindings(**scope).select { |entry| entry.rule_type == :object }.map(&:rule_set).uniq(&:downcase)
          raise Algosec::Policy::Error, "安全域 #{result.from_zone} 到 #{result.to_zone} 未绑定对象策略" if names.empty?
          unless names.one? && (!result.rule || names.first.casecmp?(result.rule.rule_set.to_s))
            raise Algosec::Policy::Error.new("无法确定当前规则的对象策略绑定", code: :ambiguous_policy)
          end
          policy = result.rule&.rule_set || names.first
          unless snapshot.behavior.exclusive_policy?(policy, **scope)
            raise Algosec::Policy::Error.new("对象策略 #{policy} 由多个区域或任意区域共用，需要先明确隔离范围", code: :shared_policy)
          end
          policy
        end

        def create_pool(value)
          parts = address_parts(value)
          existing = snapshot.elements(Algosec::Elements::NatPool).sort_by(&:name).find { |pool| pool.set == parts[:set] }
          return existing.name if existing
          define_object(:pool, parts[:set], "Pool-#{parts[:text]}", type: Algosec::Elements::NatPool) do |name|
            emit("nat address-group name #{identifier(name)}", "address #{parts[:first]} #{parts[:last]}", "exit")
          end
        end

        # 核对整个 ACL 的二维覆盖，拒绝将分别相等的源、目标并集当成完整笛卡尔积。
        def matching_acl?(rules, source, destination)
          slices = []
          rules.each do |rule|
            return false unless unconditional_acl_rule?(rule)
            return false unless Algosec::Policy::Ranges.rule_services(rule) == Algosec::Policy::Ranges.service("any")
            left, right = rule.sources.resolved_set, rule.destinations.resolved_set
            return false if left.empty? || right.empty? || !source.cover?(left) || !destination.cover?(right)
            slices << [ left, right ]
          end
          boundaries = ([ source ] + slices.map(&:first)).flat_map { |set| set.flat_map { |range| [ range.begin, range.end + 1 ] } }.uniq
          boundaries.all? do |point|
            next true unless source.include?(point)
            slices.select { |left, _| left.include?(point) }.reduce(Set.new) { |set, (_, right)| set | right } == destination
          end
        end

        # 待复用 ACL 必须能证明完整条件；已知地址投影不能替代 DNS 或其他限制。
        def unconditional_acl_rule?(rule)
          rule.from_zones.nil? && rule.to_zones.nil? && rule.action == "allow" && rule.status_known? && !rule.disabled? &&
            !rule.schedule_name && !rule.schedule && !rule.starts_at && !rule.expires_at &&
            !rule.application_or_user_restricted? && rule.security_profiles.empty? && !rule.unparsed_commands? &&
            rule.from_vlans.empty? && rule.to_vlans.empty? &&
            !rule.from_interface && rule.dst_interfaces.empty? && rule.services.resolved? &&
            [ rule.sources, rule.destinations ].all? { |group| group.resolved? && !group.conditional? }
        end

        def create_acl(source, destination)
          raise Algosec::Policy::Error, "NAT ACL 缺少地址" if source.empty? || destination.empty?
          acls = snapshot.rules.select { |rule| rule.native_rule_type == :acl && rule.rule_set }.group_by(&:rule_set)
          match = acls.keys.sort.find { |name| matching_acl?(acls[name], source, destination) }
          return match if match
          name = available_id(:acl, [ source, destination ], 3000..3999, acls.keys)
          once([ :acl, name ]) do
            addresses = [ source, destination ].map do |set|
              cidrs(set).map { |ip, prefix| "#{ip} #{(prefix == 32) ? "0" : IPAddr.from_i((1 << (32 - prefix)) - 1)}" }
            end
            emit("acl advanced #{name}")
            addresses.first.product(addresses.last).each { |left, right| emit("rule permit ip source #{left} destination #{right}") }
            emit("exit")
          end
          name
        end
      end
    end
  end
end
