# frozen_string_literal: true

require_relative "../elements"
require_relative "value"

module Algosec
  module Policy
    module Ranges
      ANY_PORTS = Set.new(0..IPAddr::PORT_MAX)
      module_function

      # 将地址表达式合并成统一的 IPv4 范围集合。
      def addresses(values) = Set.new(*values.flat_map { |value| IPAddr.parse(value).ranges })

      # 同义协议和端口表达式共用一个请求键，避免绕过复用及 NAT 冲突检查。
      def normalize_service(value)
        protocol, ports, *extra = Value.text(value, label: "服务").downcase.split("/", -1)
        raise ArgumentError, "服务格式必须为协议或协议/端口范围" if extra.any? || ports == ""
        number = IPAddr.protocol_number(protocol)
        unless [ IPAddr::TCP, IPAddr::UDP ].include?(number)
          if ports && ports != "any"
            unrestricted = IPAddr.ports(ports) == ANY_PORTS ||
              (IPAddr.icmp?(protocol) && !Elements::ServiceObject.icmp_type_restricted?(protocol: protocol, destination_port: ports))
            raise ArgumentError, "非 TCP/UDP 服务请求不支持端口或 ICMP 类型限制" unless unrestricted
          end
          return number.zero? ? "any" : number.to_s
        end
        raise ArgumentError, "TCP/UDP 服务必须指定端口" if ports.nil?

        "#{number == IPAddr::TCP ? 'tcp' : 'udp'}/#{normalize_ports(ports)}"
      end

      # 延续端口查询的 min/max 语义，同时使用生成器能直接输出的规范文本。
      def normalize_ports(value)
        range = IPAddr.ports(value).first
        range.begin == range.end ? range.begin.to_s : "#{range.begin}-#{range.end}"
      end

      # 非 TCP/UDP 服务按协议比较；请求不提供源端口或应用约束。
      def service(value)
        protocol, ports = value.split("/", 2)
        number = IPAddr.protocol_number(protocol)
        return Set.new(0..IPAddr::SERVICE_MAX) if number.zero?
        ports = Elements::Definition::ANY_PORTS unless [ IPAddr::TCP, IPAddr::UDP ].include?(number)
        raise ArgumentError, "TCP/UDP 服务必须指定端口" if ports.nil?
        IPAddr.service("#{number}/#{ports}")
      end

      # 将多个服务表达式合并成统一服务编码集合。
      def services(values) = Set.new(*values.flat_map { |value| service(value).ranges })

      # 从规则的无限制服务项中生成可比较的服务投影。
      def rule_services(rule)
        unrestricted = rule.services.unique_leaves.flat_map(&:terms).select { |term| unrestricted_term?(term) }
        services(unrestricted.map { |term| "#{term[:protocol]}/#{term[:destination_port]}" })
      end

      # 判断服务项是否覆盖所有源端口和可接受的目标协议范围。
      def unrestricted_term?(term)
        return false unless (IPAddr.ports(term[:source_port] || Elements::Definition::ANY_PORTS)) == ANY_PORTS && term[:uuid].nil? && term[:timeout].nil?
        !Elements::ServiceObject.icmp_type_restricted?(protocol: term[:protocol], destination_port: term[:destination_port])
      end

      # 把规则投影成查询匹配器使用的地址和服务维度。
      def projection(rule)
        if rule.unparsed_commands?
          raise Error.new("规则 #{rule.rule_id || rule.name} 包含未解析命令", code: :conditional_policy)
        end
        {
          sources: rule_addresses(rule.sources),
          destinations: rule_addresses(rule.destinations),
          services: rule_services(rule)
        }
      end

      # 域名或 IPv6 成员不能用已知 IPv4 子集冒充整个地址定义。
      def rule_addresses(group)
        group.unique_leaves.each { |address| validate_address!(address) }
        group.resolved_set
      end

      def validate_address!(address)
        unless address.resolved?
          raise Error.new("地址 #{address.name} 不能完整投影为 IPv4", code: :unsupported_address)
        end
      end
    end
  end
end
