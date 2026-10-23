# frozen_string_literal: true

module Algosec
  module Vendors
    # 登记表只管理不可变定义；设备运行状态始终保存在解析器、快照或会话中。
    class Registry
      COMPONENTS = { elements: "Elements", parser: "Parser", policy: "Policy", generator: "Generator", connector: "Connector", collector: "Collector" }.freeze
      Entry = Data.define(:key, :namespace, :components, :aliases, :source_location, :policy_definition) do
        # 只加载已声明的组件，缺失能力不能回退到其他厂商。
        def fetch(component)
          raise UnsupportedCapability, "#{key} does not support #{component}" unless components.include?(component)
          namespace.const_get(Registry::COMPONENTS.fetch(component), false)
        end
      end

      # 独立登记表供测试或其他应用边界使用，不共享全局可变映射。
      def initialize(namespace)
        @namespace, @entries, @aliases = namespace, {}.freeze, {}.freeze
      end

      # 校验全部名称和组件路径后才发布定义；错误不会留下半份登记。
      def register(key, namespace:, components:, directory:, aliases: [], source_location: nil)
        key = key.to_sym
        raise ArgumentError, "Invalid vendor: #{key}" unless /\A[a-z][a-z0-9_]*\z/.match?(key.to_s)
        raise ArgumentError, "Invalid namespace: #{namespace}" unless /\A[A-Z][A-Za-z0-9]*\z/.match?(namespace)
        components = components.map(&:to_sym)
        unless components.any? && components.uniq == components && (components - COMPONENTS.keys).empty?
          raise ArgumentError, "Invalid components for #{key}"
        end
        if components.include?(:generator) && !components.include?(:policy)
          raise ArgumentError, "#{key}: generator requires policy"
        end
        names = [ key.to_s, *aliases.map(&:to_s) ].map { |name| normalize_name(name) }
        raise ArgumentError, "Empty vendor alias" if names.any?(&:empty?)
        collision = names.find { |name| @aliases.key?(name) }
        raise ArgumentError, "Duplicate vendor or alias: #{collision}" if collision || @entries.key?(key)
        raise ArgumentError, "Duplicate namespace: #{namespace}" if @namespace.const_defined?(namespace, false)
        paths = components.to_h do |component|
          path = File.expand_path("#{component}.rb", directory)
          raise ArgumentError, "#{key}: missing #{component} implementation: #{path}" unless File.file?(path)
          [ component, path ]
        end
        mod = Module.new
        paths.each { |component, path| mod.autoload(COMPONENTS.fetch(component), path) }
        policy = if components.include?(:policy)
                   Policy::Definition.for(behavior: -> { mod.const_get(:Policy, false) },
                                          generator: components.include?(:generator) ? -> { mod.const_get(:Generator, false) } : nil).freeze
        end
        entry = Entry.new(key: key, namespace: mod, components: components.freeze,
                          aliases: aliases.map { |name| name.to_s.dup.freeze }.freeze,
                          source_location: source_location&.map { |value| value.is_a?(String) ? value.dup.freeze : value }&.freeze,
                          policy_definition: policy)
        @namespace.const_set(namespace, mod)
        @entries = @entries.merge(key => entry).freeze
        @aliases = @aliases.merge(names.to_h { |name| [ name, key ] }).freeze
        entry
      end

      # 别名与正式名称使用相同规范，未知名称留给入口给出明确错误。
      def normalize(vendor)
        name = vendor.to_s.downcase
        raise ArgumentError, "Vendor cannot be empty" if name.empty?
        @aliases.fetch(normalize_name(name), name.to_sym)
      end

      # 返回厂商定义或明确的未知厂商错误。
      def definition(vendor)
        @entries.fetch(normalize(vendor)) { raise ArgumentError, "Unknown vendor: #{vendor}" }
      end

      # 返回不可变登记快照，供能力矩阵和扩展检查使用。
      def definitions = @entries

      # 查询厂商是否实际声明了指定组件。
      def supports?(vendor, component) = @entries[normalize(vendor)]&.components&.include?(component.to_sym) || false

      # 返回声明了指定组件的厂商，拒绝拼错的能力名。
      def names(component)
        raise ArgumentError, "Unknown vendor component: #{component}" unless COMPONENTS.key?(component.to_sym)
        @entries.values.select { |entry| entry.components.include?(component.to_sym) }.map(&:key).freeze
      end

      # 加载所有实现并核对基类、阶段处理方法及声明；在应用启动时失败。
      def validate!
        require_relative "../policy"
        require_relative "../connector"
        require_relative "../collector"
        bases = { elements: Elements::Definition, parser: Config::Parser, policy: Policy::Behavior,
                  generator: Policy::Generator, connector: Net::Connector::Base, collector: Algosec::Collector }
        @entries.each_value do |entry|
          entry.components.each do |component|
            implementation = entry.fetch(component)
            unless implementation.is_a?(Class) && implementation <= bases.fetch(component)
              raise ArgumentError, "#{entry.key}: invalid #{component} implementation"
            end
            if component == :parser && implementation::VENDOR != entry.key
              raise ArgumentError, "#{entry.key}: parser vendor does not match registration"
            end
            implementation.validate_declarations! if implementation.respond_to?(:validate_declarations!)
          end
        end
        self
      end

      private

      # 去掉设备平台名称中常见的分隔符。
      def normalize_name(name) = name.downcase.gsub(/[^a-z0-9]/, "")
    end
  end
end
