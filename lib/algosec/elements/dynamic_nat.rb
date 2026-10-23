# frozen_string_literal: true

require_relative "nat_pool"
require_relative "security_rule"
require_relative "nat_rule"

module Algosec
  module Elements
    # 规则型 NAT 保存原始匹配条件和两侧转换；原生规则可以声明静态或动态分配。
    class DynamicNat < NatRule
      ELEMENT_TYPE = :dynamic_nat
      attr_reader :log_enabled

      attr_reader :id, :policy_id, :direction, :rule_set, :acl_name, :nat_type, :pool_name,
                  :from_zone, :to_zone, :interface, :protocol, :destination_ip,
                  :translated_destination_ip, :service, :match_rule, :vrf, :extra_conf, :references, :nat_order

      # 规范化 NAT 条件，按设备定义补齐方向并校验关联对象。
      def initialize(id: nil, policy_id: nil, direction: nil, rule_set: nil, acl_name: nil,
                     nat_type: nil, pool_name: nil, from_zone: nil, to_zone: nil, interface: nil,
                     protocol: "any", source_port: nil, translated_source_port: nil, destination_ip: nil, destination_port: nil, translated_destination_ip: nil,
                     translated_destination_port: nil, destination_port_mapping: nil, source_set: nil, destination_set: nil,
                     service_set: nil, translated_source_set: nil, translated_destination_set: nil,
                     translated_service_set: nil, source_pool: nil, destination_pool: nil,
                     service: nil, translated_service: nil, match_rule: nil, vrf: nil, extra_conf: {}, references: [], nat_order: nil, log_enabled: nil, **context)
        unless log_enabled.nil? || log_enabled == true || log_enabled == false
          raise ArgumentError, "Log enabled must be true, false or nil"
        end
        @log_enabled = log_enabled
        unless nat_order.nil? || (nat_order.is_a?(Array) && !nat_order.empty?)
          raise ArgumentError, "NAT order must be a nonempty array"
        end
        @nat_order = nat_order&.map { |part| integer(part) }&.freeze
        raise ArgumentError, "NAT extra_conf must be a Hash" unless extra_conf.is_a?(Hash)
        @extra_conf = immutable_metadata(extra_conf.transform_keys(&:to_s))
        @vrf = text(vrf, optional: true)
        @id, @policy_id, @rule_set, @acl_name, @nat_type, @pool_name, @from_zone, @to_zone, @interface =
          [ id, policy_id, rule_set, acl_name, nat_type, pool_name, from_zone, to_zone, interface ].map { |value| text(value, optional: true) }
        @direction = direction.nil? ? nil : symbol(direction, label: "NAT direction")
        @direction ||= definition_for(context).default_dynamic_nat_direction
        @protocol = text(protocol).downcase.freeze
        @destination_ip = text(destination_ip, optional: true)
        destination_port, translated_destination_port, @translated_destination_ip =
          [ destination_port, translated_destination_port, translated_destination_ip ].map { |value| text(value, optional: true) }
        source_port, translated_source_port = [ source_port, translated_source_port ].map { |value| text(value, optional: true) }
        [ source_port, translated_source_port, destination_port, translated_destination_port ].compact.each { |value| IPAddr.ports(value) }
        super(**context)
        unless references.is_a?(Array) && references.all? { |object| [ AddressObject, AddressGroup, ServiceObject, ServiceGroup ].any? { |type| object.is_a?(type) } }
          raise ArgumentError, "NAT references must contain address or service objects"
        end
        references.each { |object| same_device!(object) }
        @references = references.uniq.freeze
        unless @direction.nil? || %i[source destination bidirectional].include?(@direction)
          raise ArgumentError, "Invalid NAT direction"
        end
        element_definition.validate_dynamic_nat(self)
        source_set = address_set(source_set, optional: true)
        destination_set = address_set(destination_set, optional: true)
        if element_definition.dynamic_nat_empty_match?
          source_set ||= Set.new
          destination_set ||= Set.new
        end
        service_set = coerce_service_set(service_set, optional: true)
        translated_source_set = address_set(translated_source_set, optional: true)
        translated_destination_set = address_set(translated_destination_set, optional: true)
        translated_service_set = coerce_service_set(translated_service_set, optional: true)
        source_pool, destination_pool = typed_reference(source_pool, NatPool), typed_reference(destination_pool, NatPool)
        @service, @match_rule = typed_reference(service, [ ServiceObject, ServiceGroup ]), typed_reference(match_rule, SecurityRule)
        translated_service = typed_reference(translated_service, [ ServiceObject, ServiceGroup ])
        @original_packet = Nat::OriginalPacket.new(source_addresses: source_set, destination_addresses: destination_set,
          services: service_set, source_zones: @extra_conf.fetch("src_zones", @from_zone && [ @from_zone ]),
          destination_zones: @extra_conf.fetch("dst_zones", @to_zone && [ @to_zone ]), protocol: @protocol,
          source_port: source_port, destination_port: destination_port, interface: @interface, vrf: @vrf, match_rule: @match_rule)
        @source_translation = Nat::SourceTranslation.new(mode: element_definition.nat_source_translation_mode(self, pool: source_pool),
          native_mode: @nat_type, addresses: translated_source_set, pool: source_pool,
          port: translated_source_port, interface: element_definition.nat_source_translation_interface(self))
        @destination_translation = Nat::DestinationTranslation.new(mode: element_definition.nat_destination_translation_mode(self, pool: destination_pool, addresses: translated_destination_set),
          addresses: translated_destination_set, pool: destination_pool, port: translated_destination_port,
          services: translated_service_set, service: translated_service, port_mapping: destination_port_mapping)
        initialize_nat_semantics
      end

      # 匹配和转换属性委托给同一组值对象，不保存第二份范围状态。
      def source_set = original_packet.source_addresses
      def destination_set = original_packet.destination_addresses
      def service_set = original_packet.services
      def source_port = original_packet.source_port
      def destination_port = original_packet.destination_port
      def translated_source_set = source_translation.addresses
      def translated_source_port = source_translation.port
      def source_pool = source_translation.pool
      def translated_destination_set = destination_translation.addresses
      def translated_destination_port = destination_translation.port
      def destination_port_mapping = destination_translation.port_mapping
      def destination_pool = destination_translation.pool
      def translated_service_set = destination_translation.services
      def translated_service = destination_translation.service

      # 禁用 NAT 不参与命中，仍保留在目录中供依赖检查。
      def disabled? = extra_conf["disabled"] == true || !!match_rule&.disabled?

      # 返回已明确的转换目标；不猜测地址池分配。
      def source_targets = source_translation.targets

      def destination_targets = destination_translation.targets

      # 展开范围用于匹配，两侧原对象用于完整条件、引用计数及安全回收。
      def dependencies = (references + [ source_pool, destination_pool, service, translated_service, match_rule ]).compact.uniq

      protected

      # 由设备定义决定动态 NAT 的身份字段。
      def identity_parts = element_definition.dynamic_nat_identity(self)

      private

      # 校验关联对象类型并检查设备归属。
      def typed_reference(value, type)
        types = Array(type)
        unless value.nil? || types.any? { |candidate| value.is_a?(candidate) }
          raise ArgumentError, "Expected #{types.map(&:name).join(' or ')}"
        end
        same_device!(value) if value
        value
      end
    end
  end
end
