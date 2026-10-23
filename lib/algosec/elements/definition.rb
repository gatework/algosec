# frozen_string_literal: true

require "date"
require_relative "../declarations"

module Algosec
  module Elements
    # 无状态的领域约定。范围算法由 Elements 持有，具体设备差异通过
    # Definition.resolve 取得；元素对象不保存厂商条件分支。
    class Definition
      extend Declarations
      ANY_PORTS = "0-65535".freeze

      class << self
        # 无参数默认值与布尔能力只生成现有协议的方法，不生成领域对象字段。
        def defaults(**values)
          location = caller_locations(1, 1).first
          values.each do |name, value|
            raise ArgumentError, "Duplicate declaration: #{name}" if (@declarations || {}).key?(name)
            unless Definition.singleton_methods(false).include?(name) && method(name).arity.zero?
              raise ArgumentError, "Unknown or computed element default: #{name}"
            end
            if name.to_s.end_with?("?") && value != true && value != false
              raise ArgumentError, "#{name} requires a boolean"
            end
          end
          values.each do |name, value|
            definition = declare(name, value: value, location: location)
            define_singleton_method(name) { definition.options.fetch(:value) }
          end
        end

        # 固定身份字段可声明，条件身份及校验仍由普通 Ruby 方法实现。
        def identity(type, *fields)
          name = :"#{type}_identity"
          unless respond_to?(name) && fields.any? && fields.all? { |field| field.is_a?(Symbol) }
            raise ArgumentError, "Invalid identity declaration: #{type}"
          end
          definition = declare(name, fields: fields)
          define_singleton_method(name) { |object| definition.options.fetch(:fields).map { |field| object.public_send(field) } }
        end

        # 显式定义优先；默认从唯一厂商登记表中取得领域约定。
        def resolve(vendor = :generic, explicit: nil)
          [ Vendors.normalize(vendor), validate_definition!(explicit || Vendors.fetch(vendor, :elements)) ]
        end

        private

        # 确保解析结果是 Definition 的子类，防止错误对象进入领域模型。
        def validate_definition!(definition)
          unless definition.is_a?(Class) && definition <= self
            raise ArgumentError, "Invalid element definition: #{definition.inspect}"
          end

          definition
        end

        public

        # 以下身份方法定义不同元素类型的稳定索引键。
        def address_identity(object) = [ object.name ]

        def address_group_identity(object) = [ object.name ]

        def rule_identity(object) = [ object.rule_set || "", object.native_rule_id || object.name ]

        def route_identity(object)
          [ object.kind, object.vrf, object.subnet, object.source, object.source_set&.ranges&.inspect,
           object.source_interface, object.destination_interface, object.next_hop, object.destination_vrf,
           object.name, object.distance, object.priority ].map { |part| part || "" }
        end

        # 普通策略路由按配置顺序；厂商可为源地址路由提供前缀和代价顺序。
        def policy_route_rank(route, index) = [ index ]

        def static_nat_identity(object) = [ object.mapped_ip ]

        def dynamic_nat_identity(object) = [ object.direction, object.id ]

        # 以下默认能力描述通用设备的作用域、默认值和可选特性。
        def element_scope(object)
          zone = object.zone if scoped_addresses? && object.respond_to?(:zone)
          Scope.new(device_id: object.device_id, zone: zone)
        end

        def scoped_addresses? = false

        def address_zones(zone) = [ nil ]

        def default_vrf = "default"

        def default_destination_vrf = nil

        def default_access_mode = nil

        def unresolved_route_source? = false

        # 规范化服务协议及源、目标端口；厂商定义可以覆盖默认规则。
        def service_protocol(protocol, uuid) = protocol

        def service_ports(protocol, source, destination)
          [ source.nil? ? ANY_PORTS : source,
           (destination.nil? && !%w[tcp udp].include?(protocol)) ? ANY_PORTS : destination ]
        end

        # 返回服务项的默认附加字段。
        def default_term = nil

        # 规范化规则动作；通用定义默认允许流量。
        def rule_action(action) = action.nil? ? "permit" : action

        # 校验规则的设备约束；通用定义没有额外限制。
        def validate_rule(rule, action:) end

        # 厂商扩展只接受声明的字段，保持公共规则模型稳定。
        def rule_vendor_fields = {}

        def rule_container?(rule) = false

        def rule_group_disabled?(rule) = false

        def rule_vendor_data(value)
          raise ArgumentError, "Rule vendor data must be an object" unless value.is_a?(Hash)
          value.to_h do |key, item|
            key = key.to_s
            type = rule_vendor_fields[key] || raise(ArgumentError, "Unknown vendor rule field: #{key}")
            item = Integer(item.to_s, 10) if type == Integer
            raise ArgumentError, "Invalid vendor rule field: #{key}" unless item.is_a?(type)
            raise ArgumentError, "Negative vendor rule field: #{key}" if item.is_a?(Integer) && item.negative?
            [ key.freeze, item.is_a?(String) ? item.dup.freeze : item ]
          end.freeze
        end

        # 描述禁用状态和计划时间的厂商差异。
        def rule_disabled(status)
          return false if %w[enable enabled active activate].include?(status)
          return true if %w[disable disabled inactive deactivate].include?(status)
          nil
        end

        def disabled_rule?(status) = rule_disabled(status) == true

        def validate_schedule(start_at, end_at) end

        def schedule_requires_start? = false

        def mixed_schedules? = false

        def schedule_format(value) = (value.count(":") == 1) ? "%Y-%m-%d %H:%M" : "%Y-%m-%d %H:%M:%S"

        def schedule_components(value, reference_time:) = Date._strptime(value, schedule_format(value))

        # 描述区域和 NAT 池的厂商校验钩子。
        def validate_zone(zone) end

        def validate_nat_pool(pool) end

        # 描述静态和动态 NAT 的默认范围、方向及校验行为。
        def default_nat_pool_direction = nil

        def validate_static_nat(nat)
          raise ArgumentError, "A real address expression is required" if nat.real_ip.nil?
        end

        def static_nat_set_mode = :expression

        def static_nat_any_destination? = false

        def default_dynamic_nat_direction = nil

        def validate_dynamic_nat(nat) end

        def dynamic_nat_empty_match? = false

        # 原生阶段和反向规则不能从地址数学逆映射推断。
        def nat_stage(nat) = nil
        def nat_bidirectional(nat) = nil
        def nat_source_translation_interface(nat) = nil

        # 未声明原生模式仅保留目标地址关系；静态/动态分配仍是未知。
        def nat_source_translation_mode(nat, pool: nil)
          if nat.is_a?(StaticNat)
            return nat.source_nat_enabled == false ? :none : :static_ip
          end
          return :unknown unless nat.nat_type.nil?
          return :none if nat.extra_conf["no_translation"] == true
          return :none if nat.direction == :destination
          return :unknown unless %i[source bidirectional].include?(nat.direction)
          nil
        end

        def nat_destination_translation_mode(nat, pool: nil, addresses: nil)
          return :static if nat.is_a?(StaticNat)
          return :none if nat.extra_conf["no_translation"] == true || nat.direction == :source
          return :unknown unless %i[destination bidirectional].include?(nat.direction)
          :static if pool.nil? && addresses&.cardinality == 1
        end

        protected

        # 供厂商定义复用的必填字段校验。
        def require_direction(nat)
          raise ArgumentError, "A NAT direction is required" if nat.direction.nil?
        end

        def require_source_zone(nat)
          raise ArgumentError, "A source zone is required" if nat.from_zone.nil?
        end

        def require_mapped_zone(nat)
          raise ArgumentError, "A mapped zone is required" if nat.mapped_zone.nil?
        end

        def require_real_zone(nat)
          raise ArgumentError, "A real zone is required" if nat.real_zone.nil?
        end
      end
    end
  end
end
