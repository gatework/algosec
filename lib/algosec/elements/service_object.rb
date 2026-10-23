# frozen_string_literal: true

require_relative "base"
require_relative "service/expansion"

module Algosec
  module Elements
    # 服务直接保存协议和端口定义；服务项是不可变数据，不具有独立元素身份。
    class ServiceObject < Base
      ELEMENT_TYPE = :service_object
      include Enumerable
      include Service::Expansion

      UNRESTRICTED_ICMP_TYPES = [ Set.new(0..IPAddr::PORT_MAX), Set.new(1..IPAddr::PORT_MAX) ].freeze
      private_constant :UNRESTRICTED_ICMP_TYPES

      attr_reader :terms, :set, :ports

      # 旧解析器的 1-65535 同样表示任意 ICMP 类型；按区间比较，保留等价文本的语义。
      def self.icmp_type_restricted?(protocol:, destination_port:)
        IPAddr.icmp?(protocol) && !UNRESTRICTED_ICMP_TYPES.include?(IPAddr.ports(destination_port))
      end

      # 创建空服务，按调用形式接收服务项数组或一个协议快捷定义。
      def initialize(name:, terms: [], protocol: nil, source_port: nil, destination_port: nil,
                     term: nil, uuid: nil, timeout: nil, **context)
        @terms, @ports, @set = [].freeze, {}.freeze, Set.new
        super(name: name, **context)
        raise ArgumentError, "Terms must be an array" unless terms.is_a?(Array)
        raise ArgumentError, "Supply terms or a protocol" if protocol && !terms.empty?
        terms.each do |item|
          unless item.is_a?(Hash) && item.keys.all? { |key| key.is_a?(String) || key.is_a?(Symbol) }
            raise ArgumentError, "ServiceObject terms must be objects with text keys"
          end
          add(**item.transform_keys(&:to_sym))
        end
        if protocol
          add(protocol: protocol, source_port: source_port, destination_port: destination_port,
              term: term, uuid: uuid, timeout: timeout)
        end
      end

      # 遍历服务项；没有代码块时返回枚举器。
      def each(&block) = terms.each(&block)

      # 只去重完整定义；相同协议和目的端口上的不同源端口、UUID 或超时不能丢失。
      def add(**attributes)
        item = normalize_term(**attributes)
        return false if terms.include?(item)
        destination_port = effective_destination_port(item)
        destination = IPAddr.ports(destination_port)
        updated_ports = ports.merge(item[:protocol] => (ports.fetch(item[:protocol], Set.new) | destination)).freeze
        updated_set = set | IPAddr.service("#{item[:protocol]}/#{destination_port}")
        @terms, @ports, @set = [ *terms, item ].freeze, updated_ports, updated_set
        true
      end

      # 先校验另一个服务的全部项，再逐项合并，避免部分写入。
      def merge!(other)
        unless other.is_a?(ServiceObject) && other.vendor == vendor
          raise ArgumentError, "Expected a service from the same vendor"
        end
        same_device!(other)
        normalized = other.map { |item| normalize_term(**item) }
        normalized.each { |item| add(**item) }
        self
      end

      # 判断任一服务项是否匹配给定流量。
      def matches?(protocol:, source_port:, destination_port:, uuid: nil)
        point = IPAddr.service("#{text(protocol)}/#{text(destination_port)}")
        source = IPAddr.ports(source_port)
        any? do |item|
          IPAddr.service("#{item[:protocol]}/#{effective_destination_port(item)}").cover?(point) &&
            IPAddr.ports(item[:source_port] || Definition::ANY_PORTS).cover?(source) &&
            (item[:uuid].nil? || item[:uuid] == uuid)
        end
      end

      # 不带源端口或应用等限制的索引，才可证明省略这些条件的查询被完整覆盖。
      def unconditional_set
        intervals = terms.select do |item|
          IPAddr.ports(item[:source_port] || Definition::ANY_PORTS) == IPAddr.ports(Definition::ANY_PORTS) &&
            item[:uuid].nil? && item[:timeout].nil? &&
            !self.class.icmp_type_restricted?(protocol: item[:protocol], destination_port: item[:destination_port])
        end.flat_map do |item|
          IPAddr.service("#{item[:protocol]}/#{effective_destination_port(item)}").ranges
        end
        Set.new(*intervals)
      end

      # 判断两个服务是否覆盖相同的服务编码集合。
      def same_port_set?(other) = other.respond_to?(:set) && set == other.set

      # 按服务项完整定义的多重集合比较服务内容。
      def same_definition?(other)
        other.is_a?(ServiceObject) && definitions == other.definitions
      end

      # 快捷属性只代表单项或所有项一致的值，混合定义不任取第一项。
      def protocol = common_value(:protocol)

      def source_port = common_value(:source_port)

      def destination_port = common_value(:destination_port)

      def timeout = common_value(:timeout)

      # 将超时写入所有服务项。
      def timeout=(value)
        normalized = text(value, optional: true)
        @terms = terms.map { |item| item.merge(timeout: normalized).freeze }.uniq.freeze
      end

      protected

      # 比较匹配语义；项名称仅用于保留设备原文，不参与内容相等性。
      def definitions
        map do |item|
          [ item[:protocol], IPAddr.ports(item[:source_port] || Definition::ANY_PORTS),
           IPAddr.ports(effective_destination_port(item)), item[:uuid], item[:timeout] ]
        end.tally
      end

      private

      # terms 保留设备声明，匹配与索引使用同一有效范围，任意类型标记不能漏掉类型 0。
      def effective_destination_port(item)
        if IPAddr.icmp?(item[:protocol]) && !self.class.icmp_type_restricted?(protocol: item[:protocol], destination_port: item[:destination_port])
          Definition::ANY_PORTS
        else
          item[:destination_port]
        end
      end

      # 厂商只负责语法差异；端口及协议校验统一在服务边界完成。
      def normalize_term(protocol:, source_port: nil, destination_port: nil, term: nil, uuid: nil, timeout: nil)
        protocol = text(protocol).downcase
        uuid = text(uuid, optional: true)
        protocol = text(element_definition.service_protocol(protocol, uuid))
        source_port, destination_port = element_definition.service_ports(protocol, source_port, destination_port)
        source_port, destination_port = [ source_port, destination_port ].map { |value| text(value, optional: true) }
        source_range = IPAddr.ports(source_port || Definition::ANY_PORTS)
        destination_range = IPAddr.ports(destination_port)
        if IPAddr.protocol_number(protocol).zero? &&
           [ source_range, destination_range ].any? { |range| range != IPAddr.ports(Definition::ANY_PORTS) }
          raise ArgumentError, "Any protocol services require unrestricted source and destination ports"
        end
        { protocol: protocol, source_port: source_port, destination_port: destination_port,
          term: text(term.nil? ? element_definition.default_term : term, optional: true),
          uuid: uuid, timeout: text(timeout, optional: true) }.freeze
      end

      # 无项或多种取值时保留 nil，完整定义始终从 terms 读取。
      def common_value(field)
        values = terms.map { |item| item[field] }.uniq
        values.first if values.one?
      end
    end
  end
end
