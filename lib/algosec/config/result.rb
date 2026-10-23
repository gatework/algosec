# frozen_string_literal: true

require_relative "diagnostic"
require_relative "../elements"
require_relative "result/rule_projection"

module Algosec
  module Config
    class Result
      attr_reader :reader, :catalog, :diagnostics, :rule_projection, :reference_counts, :builtin_services, :dns_context, :time_zone, :reference_time, :parsing_settings, :definition_id

      # 保存解析产物，生成报告，并从完整对象图统计目录内引用次数。
      def initialize(reader:, catalog:, diagnostics:, at:, builtin_services: {}, dns_context: nil, time_zone: nil, parsing_settings: {}, definition_id: nil)
        @reader, @catalog = reader, catalog
        @reference_time = at.dup.freeze
        @parsing_settings = immutable_value(parsing_settings)
        @definition_id = (definition_id || reader.vendor.to_s).dup.freeze
        @dns_context = immutable_value(dns_context)
        @time_zone = time_zone && Time.find_zone!(time_zone).name.dup.freeze
        @builtin_services = builtin_services.dup.freeze
        unless diagnostics.is_a?(Array) && diagnostics.all? { |item| item.is_a?(Diagnostic) }
          raise ArgumentError, "Diagnostics must be Diagnostic objects"
        end
        @diagnostics = diagnostics.dup.freeze
        @rule_projection = RuleProjection.new(rules, at: at)
        counts = Hash.new(0)
        visited = {}
        indexed = (catalog.to_a + builtin_services.values).to_h { |element| [ element.object_id, true ] }
        walk = lambda do |element|
          return if visited[element.object_id]
          visited[element.object_id] = true
          element.dependencies.each { |child|
            counts[child.identity] += 1 if indexed[child.object_id]
            walk.call(child)
          }
        end
        catalog.each { |element| walk.call(element) }
        @reference_counts = counts.freeze
        @complete = reader.source_complete? && @diagnostics.empty?
        catalog.seal!
        @builtin_services.each_value(&:seal!)
        reader.seal!
      end

      # 附加原文只替换 Reader；已封闭对象图和原有解析上下文保持一致。
      def with_source(content)
        self.class.new(reader: reader.with_source(content), catalog: catalog, diagnostics: diagnostics,
          at: reference_time, builtin_services: builtin_services, dns_context: dns_context, time_zone: time_zone,
          parsing_settings: parsing_settings, definition_id: definition_id).tap { |result| result.bind_source!(source_key) if source_key }
      end

      attr_reader :source_key

      # 调用方绑定解析来源；领域层只保存不透明标识，不解释数据库或版本结构。
      def bind_source!(source_key)
        raise ArgumentError, "Source key must be a nonempty string" unless source_key.is_a?(String) && !source_key.empty?
        raise ArgumentError, "Parsing source is already bound" if self.source_key && self.source_key != source_key
        @source_key = source_key.dup.freeze unless self.source_key
        self
      end

      # 返回指定类型的元素冻结数组。
      def elements(type = nil) = catalog.select { |element| type.nil? || element.is_a?(type) }.freeze

      # 返回结果中的规则集合。
      def rules = elements(Elements::SecurityRule)

      # 包含内联地址和嵌套组的所有叶子对象，用于 DNS 生命周期校验。
      def address_objects
        visited, addresses = {}, []
        walk = lambda do |object|
          return if visited[object.object_id]
          visited[object.object_id] = true
          addresses << object if object.is_a?(Elements::AddressObject)
          object.dependencies.each { |child| walk.call(child) }
        end
        catalog.each { |object| walk.call(object) }
        addresses
      end

      # 失败也有短有效期；到期后重新解析，而不是永久复用未知状态。
      def dns_refresh_required?(context, at: Time.current)
        domains = address_objects.select { |address| address.direct_member.any? { |leaf| leaf["type"] == "domain" && !DomainName.wildcard?(leaf["value"]) } }
        return false if domains.empty?
        return true unless dns_context == context
        domains.any? do |address|
          address.direct_member.select { |leaf| leaf["type"] == "domain" && !DomainName.wildcard?(leaf["value"]) }.any? do |leaf|
            answer = address.dns_answers[leaf.fetch("value")]
            !answer || Time.iso8601(answer.fetch("expires_at")) <= at
          end
        end
      end

      # 按名称和作用域查找目录元素。
      def find(type, name:, **scope) = catalog.find(type, name: name, **scope)

      # 判断解析期间是否没有诊断信息。
      def complete? = @complete

      # 报告摘要只显示数量与诊断码；原文、规则正文和凭据不进入日志。
      def as_json(*)
        { source: reader.as_json, complete: complete?, rules: rules.size,
          diagnostics: diagnostics.map { |item| { code: item.code, line_number: item.line_number } } }
      end

      def inspect = "#<#{self.class.name} complete=#{complete?} rules=#{rules.size} diagnostics=#{diagnostics.size}>"
      alias to_s inspect

      # 返回读取器中仍未消费的原始行。
      def unparsed_lines = reader.unparsed_lines

      private

      # DNS 和解析上下文是结果拥有的值；不接管调用方容器的冻结状态。
      def immutable_value(value)
        case value
        when Hash then value.to_h { |key, item| [ immutable_value(key), immutable_value(item) ] }.freeze
        when Array then value.map { |item| immutable_value(item) }.freeze
        when String then value.dup.freeze
        else value
        end
      end
    end
  end
end
