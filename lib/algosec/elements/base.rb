# frozen_string_literal: true

require_relative "../set"
require_relative "../ipaddr"
require_relative "definition"
require_relative "scope"
require_relative "../config/source_unavailable"

module Algosec
  module Elements
    # 共享元数据和结构化身份；地址、端口等数值相等性由 Set 负责。
    # 设备差异由 Definition 注入，领域对象本身不保存厂商分支。
    class Base
      ELEMENT_TYPE = :element
      # 作用域组使用它表示所有安全域；解析器会把它视为未限定区域。
      ANY_ZONE = "^".freeze

      attr_reader :name, :vendor, :device_id, :description, :ref_count,
                  :identity, :identity_fields, :scope

      # 规范化公共属性，解析元素定义，并一次性建立稳定身份。
      def initialize(name: nil, vendor: :generic, device_id: nil, config: nil, description: nil,
                     ref_count: 0, definition: nil, scope: nil, config_present: nil)
        @vendor, @element_definition = resolve_definition(vendor, definition)
        @name = text(name, optional: true)
        raise ArgumentError, "Expected a Scope" unless scope.nil? || scope.is_a?(Scope)
        @device_id = device_id.nil? ? scope&.device_id : integer(device_id)
        if scope&.device_id && @device_id != scope.device_id
          raise ArgumentError, "Scope belongs to another device"
        end
        @scope = (scope || element_definition.element_scope(self)).with(device_id: @device_id)
        @config = config.nil? ? nil : config_text(config)
        unless config_present.nil? || config_present == true || config_present == false
          raise ArgumentError, "Configuration presence must be boolean"
        end
        raise ArgumentError, "Configuration presence contradicts text" if config_present == false && !config.nil?
        @config_present = config_present.nil? ? !config.nil? : config_present
        @description = text(description, optional: true)
        @ref_count = integer(ref_count)
        @identity_fields = identity_parts.map { |part| text(part) }.freeze
        @identity = [ element_type, @vendor, @scope, *@identity_fields ].freeze
      end

      # 草稿由构造者装配；发布时仅封闭领域依赖和各类型明确拥有的容器。
      def seal!(visited = {})
        return self if sealed? || visited[object_id]
        visited[object_id] = true
        dependencies.each { |child| child.seal!(visited) }
        seal_owned_values!
        freeze
      end

      def sealed? = frozen?

      def config_present? = @config_present
      def config_available? = !config_present? || !@config.nil?

      def config
        raise Config::SourceUnavailable, "Element configuration is unavailable" unless config_available?
        @config
      end

      # 文档只恢复已登记的行为，不保存 Ruby 类名。
      def definition_id
        raise ArgumentError, "Unregistered element definition" unless element_definition.equal?(Vendors.fetch(vendor, :elements))
        vendor.to_s
      end

      # 通用日志和 JSON 只暴露身份，配置正文通过 config 显式读取。
      def as_json(*) = { type: element_type, vendor: vendor, device_id: device_id, scope: scope.to_h, identity: identity_fields }

      def element_type = self.class::ELEMENT_TYPE

      alias type element_type

      def inspect = "#<#{self.class.name} vendor=#{vendor} device_id=#{device_id} sealed=#{sealed?}>"
      alias to_s inspect

      # 判断两个对象是否代表同一个结构化元素。
      def same_identity?(other) = other.respond_to?(:identity) && identity == other.identity

      # 返回依赖对象；无引用的基础元素没有依赖。
      def dependencies = []

      # 由注入的定义提供地址作用域，引用解析器因此不需要写厂商分支。
      def address_reference_zones(zone) = element_definition.address_zones(zone)

      # 用完整的新配置替换原配置，并去掉每行末尾的换行。
      def replace_config(*lines)
        replacement = lines.map { |line| config_text(line).sub(/\r?\n\z/, "") }.join("\n").freeze
        @config_present, @config = true, replacement
        @config
      end

      # 在已有配置后追加行；没有新增行时保持原配置对象。
      def append_config(*lines)
        return config if lines.empty?
        replace_config(*((config.nil? || config.empty?) ? lines : [ config, *lines ]))
      end

      # 按指定属性返回差异，结果保留左右值以便生成修改报告。
      def differences(other, *attributes)
        attributes.each_with_object({}) do |attribute, result|
          left, right = public_send(attribute), other.public_send(attribute)
          result[attribute] = [ left, right ].freeze unless left == right
        end.freeze
      end

      protected

      # 标量在构造时已复制并冻结；可变容器由其所属子类声明。
      def seal_owned_values!; end

      attr_reader :element_definition
      # 为给定上下文选择元素定义，允许对象在解析时切换到同一设备配置。
      def definition_for(context)
        _vendor, selected = resolve_definition(context.fetch(:vendor, :generic), context[:definition])
        selected
      end

      # 通过统一入口解析厂商和显式定义。
      def resolve_definition(vendor, explicit)
        Definition.resolve(vendor, explicit: explicit)
      end

      # 返回构成元素身份的字段；子类按领域需要扩展。
      def identity_parts = [ name ]

      # 传递当前对象的厂商、设备和定义上下文。
      def context = { vendor: vendor, device_id: device_id, definition: element_definition, scope: scope }

      # 深度检查依赖关系，避免新增引用形成循环。
      def depends_on?(object, visited = {})
        return true if equal?(object)
        return false if visited[object_id]
        visited[object_id] = true
        dependencies.any? { |child| child.depends_on?(object, visited) }
      end

      # 把名称、标识等可接受输入复制并冻结为文本。
      def text(value, optional: false)
        return nil if optional && value.nil?
        unless value.is_a?(String) || value.is_a?(Integer) || value.is_a?(Symbol)
          raise ArgumentError, "Expected text, got #{value.inspect}"
        end
        value.to_s.dup.freeze
      end

      # 将枚举输入限制为字符串或符号，避免错误类型延迟到 to_sym 才失败。
      def symbol(value, label: "Value")
        unless value.is_a?(String) || value.is_a?(Symbol)
          raise ArgumentError, "#{label} must be a string or symbol"
        end
        value.to_sym
      end

      # 把非负整数文本转换为整数并拒绝其他类型。
      def integer(value)
        valid = value.is_a?(Integer) || (value.is_a?(String) && /\A[0-9]+\z/.match?(value))
        unless valid
          raise ArgumentError, "Expected a nonnegative integer"
        end
        number = value.is_a?(Integer) ? value : Integer(value, 10)
        raise ArgumentError, "Expected a nonnegative integer" if number.negative?
        number
      end

      # 复制并冻结配置文本，避免外部修改对象内部内容。
      def config_text(value)
        raise ArgumentError, "Configuration must be a string" unless value.is_a?(String)
        value.dup.freeze
      end

      # 检查厂商一致性；双方指定设备时必须属于同一设备。
      def same_device!(object)
        raise ArgumentError, "Elements belong to different vendors" if vendor != object.vendor
        if device_id && object.device_id && device_id != object.device_id
          raise ArgumentError, "Elements belong to different devices"
        end
      end

      # 将 IPv4、地址文本或已有集合统一成地址集合。
      def address_set(value, optional: false)
        return nil if optional && value.nil?
        result = case value
        when Set then value
        when IPAddr then value.to_set
        when String then IPAddr.parse(value)
        else raise ArgumentError, "Expected an IPv4 expression, IPAddr or Set"
        end
        raise ArgumentError, "Address range exceeds IPv4" if result.max && result.max > IPAddr::IPV4_MAX
        result
      end

      # 将服务文本或已有集合统一成 24 位服务编码集合。
      def coerce_service_set(value, optional: false)
        return nil if optional && value.nil?
        result = value.is_a?(Set) ? value : IPAddr.service(value)
        raise ArgumentError, "Service range exceeds 24 bits" if result.max && result.max > IPAddr::SERVICE_MAX
        result
      end

      # 把单值、数组或哈希键统一成去重后的冻结名称列表。
      def names(value)
        return nil if value.nil?
        list = case value
        when Hash then value.keys
        when Array then value
        else [ value ]
        end
        list.map { |item| text(item) }.uniq.freeze
      end

      # 把键和值都规范化为冻结文本的映射。
      def text_map(value)
        return nil if value.nil?
        raise ArgumentError, "Expected a text mapping" unless value.is_a?(Hash)
        value.to_h { |key, item| [ text(key), text(item, optional: true) ] }.freeze
      end

      # 匹配元数据属于当前元素；复制每层容器，避免调用方改写已建立的条件。
      def immutable_metadata(value)
        case value
        when Hash then value.to_h { |key, item| [ immutable_metadata(key), immutable_metadata(item) ] }.freeze
        when Array then value.map { |item| immutable_metadata(item) }.freeze
        else value.dup.freeze
        end
      end
    end
  end
end
