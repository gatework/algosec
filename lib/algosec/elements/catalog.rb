# frozen_string_literal: true

require "active_support/core_ext/object/inclusion"
require_relative "catalog/reference_resolver"

module Algosec
  module Elements
    # 保存配置范围内的元素身份并负责引用装配；不处理命令行解析和输入输出。
    class Catalog
      class AmbiguousReference < StandardError; end

      LOOKUP_SCOPES = %i[vendor device_id zone vrf scope].freeze
      include Enumerable

      # 建立按身份和名称索引的目录，并校验目录范围。
      def initialize(elements = [], vendor: nil, device_id: nil, definition: nil)
        raise ArgumentError, "Elements must be an array" unless elements.is_a?(Array)
        @vendor = vendor.nil? ? nil : Definition.resolve(vendor, explicit: definition).first
        @device_id = device_id.nil? ? nil : Integer(device_id.to_s, 10)
        raise ArgumentError, "Device ID must be nonnegative" if @device_id&.negative?
        @elements_by_identity, @elements_by_name = {}, {}
        elements.each { |element| add(element) }
      end

      # 发布目录及其索引；引用解析只能发生在发布之前。
      def seal!
        return self if sealed?
        visited = {}
        each { |element| element.seal!(visited) }
        @elements_by_identity.freeze
        @elements_by_name.each { |key, candidates| key.freeze; candidates.freeze }
        @elements_by_name.freeze
        freeze
      end

      def sealed? = frozen?

      def as_json(*) = { elements: size, sealed: sealed? }

      def inspect = "#<#{self.class.name} elements=#{size} sealed=#{sealed?}>"
      alias to_s inspect

      # 遍历目录中的元素；没有代码块时返回枚举器。
      def each(&block) = block ? @elements_by_identity.each_value(&block) : enum_for(__method__)

      # 返回目录中的元素数量。
      def size = @elements_by_identity.size

      # 按稳定身份读取元素。
      def [](identity) = @elements_by_identity[identity]

      # 写入元素，同时维护身份索引和同名候选索引。
      def add(element)
        raise ArgumentError, "Expected an Element" unless element.is_a?(Base)
        raise ArgumentError, "Element vendor differs from catalog" if @vendor && @vendor != element.vendor
        if @device_id && element.device_id && @device_id != element.device_id
          raise ArgumentError, "Element belongs to another device"
        end
        previous = @elements_by_identity[element.identity]
        @elements_by_name[[ previous.class, previous.name ]]&.delete(previous.identity) if previous
        @elements_by_identity[element.identity] = element
        (@elements_by_name[[ element.class, element.name ]] ||= {})[element.identity] = element
        self
      end

      # 按类型、名称和可选作用域查找唯一元素。
      def find(type, name:, **scope)
        raise ArgumentError, "Expected an Element class and a name" unless type.is_a?(Class) && type <= Base && !name.nil?
        scope.each_key do |key|
          raise ArgumentError, "Unknown lookup scope: #{key}" unless key.in?(LOOKUP_SCOPES)
        end
        candidates = @elements_by_name.fetch([ type, name.to_s ], {}).values.select do |element|
          scope.all? do |key, value|
            element.respond_to?(key) && (key == :scope ? element.scope == value : (value.nil? ? element.public_send(key).nil? : element.public_send(key)&.to_s == value.to_s))
          end
        end
        raise AmbiguousReference, "#{type.name} #{name.inspect} matches #{candidates.size} objects" if candidates.size > 1
        candidates.first
      end

      # 查找元素；缺失时抛出 KeyError，供严格解析路径使用。
      def fetch(type, name:, **scope)
        find(type, name: name, **scope) || raise(KeyError, "Missing #{type.name} #{name.inspect}")
      end

      # 先建立并校验完整依赖计划，再统一修改引用。
      # 可选代码块用于提供目录外置的内建对象。
      def resolve!(strict: true, on_missing: nil, &resolver)
        raise FrozenError, "Published catalog cannot resolve references" if sealed?
        raise ArgumentError, "Strict must be true or false" unless strict == true || strict == false
        unless on_missing.nil? || on_missing.respond_to?(:call)
          raise ArgumentError, "Missing-reference handler must respond to call"
        end
        ReferenceResolver.new(self, strict: strict, on_missing: on_missing, &resolver).resolve
        self
      end
    end
  end
end
