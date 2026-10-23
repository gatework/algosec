# frozen_string_literal: true

require_relative "security_rule"
require_relative "nat_rule"

module Algosec
  module Elements
    # 保存固定地址映射及其匹配范围；区域、访问控制和规则由上层判断。
    class StaticNat < NatRule
      ELEMENT_TYPE = :static_nat
      class InvalidMapping < StandardError; end

      attr_reader :log_enabled, :source_nat_enabled

      attr_reader :real_ip, :mapped_ip, :real_zone, :mapped_zone, :interface, :rule_set, :acl_name, :acl_number,
                  :mask, :id, :match_rule, :nat_order, :interfaces

      # 规范化映射端点，建立显式映射或推导出的真实、映射地址集合。
      def initialize(mapped_ip:, real_ip: nil, real_set: nil, mapped_set: nil, destination_set: nil,
                     mappings: nil, real_zone: nil, mapped_zone: nil, interface: nil, rule_set: nil,
                     acl_name: nil, acl_number: nil, mask: nil, id: nil, match_rule: nil, nat_order: nil,
                     interfaces: nil, disabled: false, log_enabled: nil, source_nat_enabled: nil, **context)
        unless log_enabled.nil? || log_enabled == true || log_enabled == false
          raise ArgumentError, "Log enabled must be true, false or nil"
        end
        @log_enabled = log_enabled
        unless source_nat_enabled.nil? || source_nat_enabled == true || source_nat_enabled == false
          raise ArgumentError, "Source NAT enabled must be true, false or nil"
        end
        @source_nat_enabled = source_nat_enabled
        raise ArgumentError, "NAT disabled must be true or false" unless disabled == true || disabled == false
        @disabled = disabled
        unless nat_order.nil? || (nat_order.is_a?(Array) && !nat_order.empty?)
          raise ArgumentError, "NAT order must be a nonempty array"
        end
        @nat_order = nat_order&.map { |part| integer(part) }&.freeze
        unless interfaces.nil? || (interfaces.is_a?(Array) && interfaces.all? { |name| name.is_a?(String) || name.is_a?(Symbol) || name.is_a?(Integer) })
          raise ArgumentError, "NAT interfaces must be an array of names"
        end
        @interfaces = interfaces&.map { |name| text(name) }&.uniq&.freeze
        interface ||= @interfaces.first if @interfaces&.one?
        @mapped_ip = text(mapped_ip)
        @real_ip, @real_zone, @mapped_zone, @interface, @rule_set, @acl_name, @mask, @id =
          [ real_ip, real_zone, mapped_zone, interface, rule_set, acl_name, mask, id ].map { |value| text(value, optional: true) }
        @acl_number = acl_number.nil? ? nil : integer(acl_number)
        super(**context)
        element_definition.validate_static_nat(self)
        raise ArgumentError, "Expected a SecurityRule" unless match_rule.nil? || match_rule.is_a?(SecurityRule)
        same_device!(match_rule) if match_rule
        @match_rule = match_rule
        if mappings
          raise ArgumentError, "Supply mappings or sets, not both" if real_set || mapped_set
          mappings = parse_mappings(mappings)
          real_set = Set.new(*mappings.map(&:first))
          mapped_set = Set.new(*mappings.map(&:last))
        else
          real_set = initial_set(real_set, @real_ip)
          mapped_set = initial_set(mapped_set, @mapped_ip)
          mappings = nil
        end
        destination_set = address_set(destination_set, optional: true)
        destination_set ||= Set.new(0..IPAddr::IPV4_MAX) if element_definition.static_nat_any_destination?
        source_mode = element_definition.nat_source_translation_mode(self)
        # 明确禁止源转换时，原始报文匹配公网目的；其余保留正向 real→mapped 关系。
        @original_packet = if source_mode == :none
          Nat::OriginalPacket.new(source_addresses: destination_set, destination_addresses: mapped_set,
            source_zones: @mapped_zone && [ @mapped_zone ], destination_zones: @real_zone && [ @real_zone ], match_rule: @match_rule)
        else
          Nat::OriginalPacket.new(source_addresses: real_set, destination_addresses: destination_set,
            source_zones: @real_zone && [ @real_zone ], destination_zones: @mapped_zone && [ @mapped_zone ], match_rule: @match_rule)
        end
        @source_translation = Nat::SourceTranslation.new(mode: source_mode,
          addresses: mapped_set, mappings: mappings)
        @destination_translation = if source_mode == :none
          Nat::DestinationTranslation.new(mode: :static, addresses: real_set, mappings: mappings)
        else
          Nat::DestinationTranslation.new(mode: :none)
        end
        initialize_nat_semantics
      end

      # 固定映射的两端直接读取原始报文和转换对象。
      def real_set = source_translation.identity? ? destination_translation.addresses : original_packet.source_addresses
      def destination_set = source_translation.identity? ? original_packet.source_addresses : original_packet.destination_addresses
      def mapped_set = source_translation.addresses
      def mappings = source_translation.mappings

      # 只做地址数学转换；区域、访问控制和规则匹配由调用方继续判断。
      def translate(addresses) = translate_set(address_set(addresses), reverse: false)

      # 禁用映射保留依赖和原文，但不能参与运行中的地址转换判断。
      def declared_disabled = @disabled

      def disabled? = @disabled || !!match_rule&.disabled?

      # 将映射地址反向转换为真实地址。
      def reverse_translate(addresses) = translate_set(address_set(addresses), reverse: true)

      # 匹配规则中的原始对象也参与引用统计与 DNS 证据失效，不能只保留地址投影。
      def dependencies = [ match_rule ].compact.freeze

      protected

      # 由设备定义决定静态 NAT 的身份字段。
      def identity_parts = element_definition.static_nat_identity(self)

      private

      # 根据显式集合、地址表达式或设备模式建立初始集合。
      def initial_set(value, expression)
        return address_set(value) unless value.nil?
        return Set.new if element_definition.static_nat_set_mode == :empty
        return address_set(expression) if element_definition.static_nat_set_mode == :expression
        raise ArgumentError, "Explicit real and mapped ranges are required"
      end

      # 解析成对地址，并保留每一段的配对关系。
      def parse_mappings(value)
        raise ArgumentError, "Mappings must be address pairs" unless value.is_a?(Array)
        pairs = value.map do |pair|
          raise ArgumentError, "A mapping needs real and mapped addresses" unless pair.is_a?(Array) && pair.size == 2
          pair.map do |expression|
            set = address_set(expression)
            raise InvalidMapping, "Each mapping endpoint must be one nonempty range" unless set.size == 1
            set.first
          end.freeze
        end
        # 合并集合会丢失相邻或乱序段之间的配对关系，因此保留原始数组。
        pairs.freeze
      end

      # 推导固定映射的分段配对，并校验每段的基数关系。
      def translation_pairs
        pairs = if mappings
                  mappings
        elsif mapped_set.cardinality == 1
                  real_set.map { |range| [ range, mapped_set.first ] }
        elsif real_set.size == mapped_set.size
                  real_set.zip(mapped_set)
        else
                  raise InvalidMapping, "The real and mapped segments need explicit pairing"
        end
        pairs.each do |real, mapped|
          unless real.size == mapped.size || mapped.size == 1
            raise InvalidMapping, "Unequal spans describe a pool or policy, not a fixed address mapping"
          end
        end
        validate_mapping_overlaps(pairs) if mappings
        pairs
      end

      # 只约束正向映射为单值函数；反向多对一和重叠区间上的相同转换仍然有效。
      def validate_mapping_overlaps(pairs)
        previous = nil
        # 已验证区间彼此兼容；保留终点最远的一段即可覆盖后续所有交叠部分。
        pairs.sort_by { |real, _mapped| real.begin }.each do |real, mapped|
          if previous && real.begin <= previous.first.end
            previous_real, previous_mapped = previous
            last = [ real.end, previous_real.end ].min
            [ real.begin, last ].each do |address|
              current = mapped.size == 1 ? mapped.begin : mapped.begin + address - real.begin
              prior = previous_mapped.size == 1 ? previous_mapped.begin : previous_mapped.begin + address - previous_real.begin
              raise InvalidMapping, "Overlapping real ranges have conflicting translations" unless current == prior
            end
          end
          previous = [ real, mapped ] if previous.nil? || real.end > previous.first.end
        end
      end

      # 在正向或反向域内检查查询范围，并按段执行偏移或单值映射。
      def translate_set(query, reverse:)
        domain = reverse ? mapped_set : real_set
        raise InvalidMapping, "Addresses fall outside the mapping" unless domain.cover?(query)
        translation_pairs.reduce(Set.new) do |result, (real, mapped)|
          origin, target = reverse ? [ mapped, real ] : [ real, mapped ]
          intersection = query & Set.new(origin)
          next result if intersection.empty?
          if mapped.size == 1
            result | Set.new(target)
          else
            offset = target.begin - origin.begin
            result | Set.new(*intersection.map { |range| (range.begin + offset)..(range.end + offset) })
          end
        end
      end
    end
  end
end
