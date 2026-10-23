# frozen_string_literal: true

require_relative "address_group"
require_relative "service_group"
require_relative "schedule"
require_relative "unparsed_commands"

module Algosec
  module Elements
    # 保存一条规则的元数据、地址服务组和可选时间计划。
    class SecurityRule < Base
      include UnparsedCommands

      ELEMENT_TYPE = :security_rule
      UNSET = Object.new.freeze
      ACTIONS = %w[allow deny drop reset-client reset-server reset-both reject].to_h { |action| [ action, action ] }
        .merge("permit" => "allow", "accept" => "allow", "pass" => "allow").freeze
      private_constant :UNSET

      attr_reader :log_enabled, :native_action, :native_rule_type, :disabled, :applications, :source_users

      attr_reader :native_rule_id, :rule_id, :rule_set, :rule_number, :rule_type, :from_zones, :to_zones,
                  :from_interface, :dst_interfaces, :semantic_conditions, :vendor_data,
                  :action, :status, :log, :schedule_name, :schedule,
                  :sources, :destinations, :services, :service_selection

      # 公共匹配条件与厂商定位信息分开验证，设备编号不参与执行排序。
      def initialize(name: nil, native_rule_id: nil, rule_set: nil, rule_number: nil, rule_type: nil, native_rule_type: nil,
                     from_zones: UNSET, to_zones: UNSET, source_zones: UNSET, destination_zones: UNSET, from_interface: nil, dst_interfaces: [],
                     action: nil, native_action: UNSET, status: UNSET, disabled: UNSET, log: nil, log_enabled: nil, schedule_name: nil,
                     schedule: nil, sources: UNSET, destinations: UNSET, source_addresses: UNSET, destination_addresses: UNSET, services: nil,
                     applications: [], source_users: [], service_selection: :explicit,
                     nat: false, conditions: {}, unparsed_commands_metadata: nil, vendor_data: {}, **context)
        unless log_enabled.nil? || log_enabled == true || log_enabled == false
          raise ArgumentError, "Log enabled must be true, false or nil"
        end
        @service_selection = symbol(service_selection, label: "Service selection")
        unless %i[explicit application_default].include?(@service_selection)
          raise ArgumentError, "Service selection must be explicit or application_default"
        end
        @log_enabled = log_enabled
        raise ArgumentError, "SecurityRule NAT must be true or false" unless nat == true || nat == false
        @nat = nat
        @native_rule_id, @rule_set = [ native_rule_id, rule_set ].map { |value| text(value, optional: true) }
        @rule_number = rule_number.nil? ? nil : integer(rule_number)
        @rule_type, @native_rule_type = rule_types(rule_type, native_rule_type)
        @from_interface = text(from_interface, optional: true)
        @dst_interfaces = Array(dst_interfaces).map { |value| text(value) }.uniq.freeze
        @from_zones = aliased_value(source_zones, from_zones, :source_zones) { |value| names(value) }
        @to_zones = aliased_value(destination_zones, to_zones, :destination_zones) { |value| names(value) }
        @applications, @source_users = names(applications) || [].freeze, names(source_users) || [].freeze
        normalized_conditions = self.class.normalize_conditions(conditions)
        declared = normalized_conditions.key?("unparsed_commands")
        commands = declared ? normalized_conditions.fetch("unparsed_commands") : (unparsed_commands_metadata ? nil : [])
        initialize_unparsed_commands(commands, declared: declared, metadata: unparsed_commands_metadata)
        if declared && !self.unparsed_commands_metadata.fetch("declared")
          raise ArgumentError, "Unsupported commands contradict declaration evidence"
        end
        @semantic_conditions = normalized_conditions.reject { |key, _| key == "unparsed_commands" }.freeze
        @vendor_data = definition_for(context).rule_vendor_data(vendor_data)
        super(name: name, **context)
        # 保留厂商身份末项作为命令定位符，包括名称或规则序号的既有回退。
        @native_rule_id = identity_fields.last
        @rule_id = identity_fields.reject(&:empty?).map { |part| part.gsub("%", "%25").gsub("/", "%2F") }.join("/").freeze
        if native_action != UNSET && !action.nil? && (canonical_action(action) || text(action)) != (canonical_action(native_action) || text(native_action, optional: true))
          raise ArgumentError, "Conflicting action and native action"
        end
        resolved_action = element_definition.rule_action(native_action == UNSET ? action : native_action)
        element_definition.validate_rule(self, action: resolved_action)
        self.action = resolved_action
        initialize_status(status, disabled)
        self.log = log
        self.schedule_name = schedule_name
        @sources = group(aliased_value(source_addresses, sources, :source_addresses), AddressGroup, "sources")
        @destinations = group(aliased_value(destination_addresses, destinations, :destination_addresses), AddressGroup, "destinations")
        @services = group(services, ServiceGroup, "services")
        self.schedule = schedule
      end

      # 拷贝本规则拥有的声明，未修改的依赖继续引用同一领域对象。
      def with(**changes)
        attributes = { name: name, native_rule_id: native_rule_id, rule_set: rule_set,
          rule_number: rule_number, rule_type: rule_type, native_rule_type: native_rule_type,
          from_zones: from_zones, to_zones: to_zones, from_interface: from_interface,
          dst_interfaces: dst_interfaces, action: native_action, status: status, log: log,
          log_enabled: log_enabled, schedule_name: schedule_name, schedule: schedule,
          sources: sources, destinations: destinations, services: services,
          applications: applications, source_users: source_users, service_selection: service_selection,
          nat: nat?, conditions: semantic_conditions, unparsed_commands_metadata: unparsed_commands_metadata,
          vendor_data: vendor_data, description: description, ref_count: ref_count,
          config: config_available? ? config : nil, config_present: config_present?, **context }
        if unparsed_commands_available? && unparsed_commands_metadata.fetch("declared")
          attributes[:conditions] = semantic_conditions.merge("unparsed_commands" => unparsed_commands)
        end
        { source_zones: :from_zones, destination_zones: :to_zones, source_addresses: :sources, destination_addresses: :destinations }.each do |canonical, legacy|
          attributes.delete(legacy) if changes.key?(canonical) && !changes.key?(legacy)
        end
        attributes.delete(:action) if changes.key?(:native_action) && !changes.key?(:action)
        attributes.delete(:status) if changes.key?(:disabled) && !changes.key?(:status)
        attributes.delete(:unparsed_commands_metadata) if changes.key?(:conditions)
        self.class.new(**attributes.merge(changes))
      end

      # 设置规则动作文本；nil 表示设备定义提供的默认动作。
      def action=(value)
        native = text(value, optional: true)
        @action, @native_action = canonical_action(native), native
      end

      # 设置规则状态文本。
      def status=(value)
        normalized = text(value)
        state = element_definition.rule_disabled(normalized)
        @status, @status_known, @disabled = normalized, !state.nil?, state == true
      end

      def disabled=(value)
        raise ArgumentError, "Disabled must be true or false" unless value == true || value == false
        self.status = value ? "disable" : "enable"
      end

      def status_known? = @status_known

      def action_known? = !action.nil?

      # 缺少 App-ID 或用户上下文时，名称限制不能退化为端口放行。
      def application_or_user_restricted?
        service_selection == :application_default || application_check || [ applications, source_users ].any? { |values| !values.empty? && values != [ "any" ] }
      end

      alias source_zones from_zones
      alias destination_zones to_zones
      alias source_addresses sources
      alias destination_addresses destinations

      # 设置日志选项，允许 nil 表示未指定。
      def log=(value)
        @log = text(value, optional: true)
      end

      # 条件访问器有固定语义，核心算法不需要读取厂商扩展。
      # 兼容显式原始条件访问；算法使用不含正文的条件和存在性谓词。
      def conditions
        return semantic_conditions unless unparsed_commands_metadata.fetch("declared")
        semantic_conditions.merge("unparsed_commands" => unparsed_commands).freeze
      end

      def application_check = semantic_conditions["application_check"]

      def security_profiles = semantic_conditions.fetch("security_profiles", {})

      def from_vlans = semantic_conditions.fetch("from_vlans", {})

      def to_vlans = semantic_conditions.fetch("to_vlans", {})

      def starts_at = semantic_conditions["starts_at"] && Time.iso8601(semantic_conditions["starts_at"])

      def expires_at = semantic_conditions["expires_at"] && Time.iso8601(semantic_conditions["expires_at"])

      def container? = element_definition.rule_container?(self)

      def application_check=(value)
        @semantic_conditions = self.class.normalize_conditions(semantic_conditions.merge("application_check" => value))
      end

      # Rails 模型与领域对象使用同一条件协议，未知键不能被静默忽略。
      def self.normalize_conditions(value)
        raise ArgumentError, "SecurityRule conditions must be an object" unless value.is_a?(Hash)
        schema = { "application_check" => String, "security_profiles" => Hash, "expires_at" => String, "starts_at" => String,
                   "unparsed_commands" => Array, "from_vlans" => Hash, "to_vlans" => Hash }
        value.to_h do |key, item|
          key = key.to_s
          type = schema[key] || raise(ArgumentError, "Unknown rule condition: #{key}")
          raise ArgumentError, "Invalid rule condition: #{key}" unless item.nil? || item.is_a?(type)
          Time.iso8601(item) if %w[expires_at starts_at].include?(key) && item
          normalized = case item
          when Hash
                         item.to_h do |name, text|
                           raise ArgumentError, "Condition values must be text" unless text.is_a?(String) || text.nil?
                           [ name.to_s.freeze, text&.dup&.freeze ]
                         end.freeze
          when Array
                         raise ArgumentError, "Commands must be text" unless item.all? { |command| command.is_a?(String) }
                         item.map { |command| command.dup.freeze }.freeze
          else
                         item&.dup&.freeze
          end
          [ key.freeze, normalized ]
        end.reject { |_key, item| item.nil? }.freeze
      end

      # 设置计划名称，允许在目录解析阶段暂时保持未绑定。
      def schedule_name=(value)
        @schedule_name = text(value, optional: true)
      end

      # 绑定时间计划并检查设备归属。
      def schedule=(value)
        raise ArgumentError, "Expected a Schedule" unless value.nil? || value.is_a?(Schedule)
        same_device!(value) if value
        @schedule = value
      end

      # 对象图统一通过元素协议读取当前依赖，避免消费者重复识别规则结构。
      def dependencies = [ sources, destinations, services, schedule ].compact.freeze

      # 对外定位字段保留编码后的稳定规则身份。
      def locator = { rule_id: rule_id }

      # 仅用于展示的名称回退，不得写入 name 或作为唯一查询键。
      def display_name
        return name if name
        rule_id
      end

      # 判断规则是否被设备定义视为禁用。
      def disabled? = disabled || element_definition.rule_group_disabled?(self)

      # 内嵌转换即使未解析成独立 NAT 对象，也不能在迁移或回收时丢失。
      def nat? = @nat

      # 判断规则是否应从给定时刻的有效规则集中忽略。
      def expired?(at: Time.current) = !!((expires_at && at.to_r > expires_at.to_r) || schedule&.expired?(at: at))

      def ignored?(at: Time.current) = container? || disabled? || expired?(at: at)

      # 判断规则的三类匹配集合是否完整覆盖给定流量。
      def covers?(source:, destination:, service:)
        if sources.conditional? || destinations.conditional?
          raise Group::UnresolvedReference, "DNS-dependent rules cannot prove unconditional coverage"
        end
        source_set, destination_set, target_service = address_set(source), address_set(destination), coerce_service_set(service)
        source_ranges, destination_ranges = sources.resolved_set, destinations.resolved_set
        service_ranges = Set.new(*services.unique_leaves.flat_map { |item| item.unconditional_set.ranges })
        source_ranges.cover?(source_set) && destination_ranges.cover?(destination_set) && service_ranges.cover?(target_service)
      end

      # 判断规则在给定时刻是否可用；未解析的计划会显式报错。
      def active?(at: Time.current)
        return false if !status_known? || ignored?(at: at) || (starts_at && at.to_r < starts_at.to_r)
        if schedule_name && !schedule
          raise Group::UnresolvedReference, "SecurityRule #{identity_fields.inspect} -> schedule #{schedule_name}"
        end
        !schedule || schedule.active?(at: at)
      end

      protected

      # 由设备定义决定规则身份字段。
      def identity_parts = element_definition.rule_identity(self)

      private

      # 新旧属性必须指向同一状态；两者都有值时先规范化再检查冲突。
      def aliased_value(canonical, legacy, label)
        values = [ canonical, legacy ].reject { |value| value.equal?(UNSET) }
        values.map! { |value| yield value } if block_given?
        raise ArgumentError, "Conflicting #{label} parameters" if values.size == 2 && values[0] != values[1]
        values.first
      end

      def canonical_action(value) = ACTIONS[text(value, optional: true)]

      def initialize_status(status, disabled)
        if disabled != UNSET
          raise ArgumentError, "Disabled must be true or false" unless disabled == true || disabled == false
          if status != UNSET && element_definition.rule_disabled(text(status)) != disabled
            raise ArgumentError, "Conflicting disabled and status parameters"
          end
        end
        self.status = status == UNSET ? (disabled == true ? "disable" : "enable") : status
      end

      def rule_types(type, native)
        type = symbol(type, label: "Rule type") unless type.nil?
        native = symbol(native, label: "Native rule type") unless native.nil?
        if %i[object acl].include?(type)
          raise ArgumentError, "Conflicting native rule types" if native && native != type
          native, type = type, nil
        end
        unless type.nil? || %i[universal interzone intrazone].include?(type)
          raise ArgumentError, "Rule type must be universal, interzone or intrazone"
        end
        native ||= :object
        raise ArgumentError, "Native rule type must be object or acl" unless %i[object acl].include?(native)
        [ type, native ]
      end

      # 校验传入组的类型和设备，并为缺失组建立空的作用域组。
      def group(object, type, label)
        unless object.nil? || object.is_a?(type)
          raise ArgumentError, "Expected #{type.name} for #{label}"
        end
        if object
          same_device!(object)
          return object
        end
        group_options = (type == AddressGroup && element_definition.scoped_addresses?) ? { zone: ANY_ZONE } : {}
        type.new(name: label, **context, **group_options)
      end
    end
  end
end
