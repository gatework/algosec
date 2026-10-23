# frozen_string_literal: true

require_relative "../../elements/service_object"

module Algosec
  module Vendors
    module Huawei
      # 服务对象与策略内联服务共用的协议、源端口和目的端口语法。
      class ServiceTerms
        # 公共查询目前只对 TCP/UDP 保留端口；其他协议的端口条件不能降成全协议。
        PORT_PROTOCOLS = [ IPAddr::TCP, IPAddr::UDP ].freeze
        PORT_FIELDS = { "source-port" => :source_port, "destination-port" => :destination_port }.freeze
        attr_reader :terms

        def initialize(words)
          words = words.dup
          protocol = words.shift
          protocol = "132" if protocol == "sctp"
          unless protocol&.match?(/\A(?:\d+|tcp|udp|icmp|icmpv6)\z/)
            raise ArgumentError, "Service requires an IP protocol number or a supported name"
          end
          number = IPAddr.protocol_number(protocol)
          raise ArgumentError, "Literal IP protocol 0 cannot be represented as any" if number.zero?

          protocol = { IPAddr::TCP => "tcp", IPAddr::UDP => "udp", IPAddr::ICMP => "icmp", IPAddr::ICMPV6 => "icmpv6" }.fetch(number, number.to_s).freeze
          fields = {}
          until words.empty?
            field = PORT_FIELDS[words.shift]
            unless PORT_PROTOCOLS.include?(number) && field && !fields.key?(field)
              raise ArgumentError, "Unsupported or repeated service condition"
            end
            ports = []
            ports << port_range(words) while words.first&.match?(/\A\d+\z/)
            raise ArgumentError, "Service port condition requires numeric ports" if ports.empty?

            fields[field] = ports.uniq
          end
          sources = fields.fetch(:source_port, [ Algosec::Elements::Definition::ANY_PORTS ])
          destinations = fields.fetch(:destination_port, [ Algosec::Elements::Definition::ANY_PORTS ])
          @terms = sources.product(destinations).map do |source, destination|
            { protocol: protocol, source_port: source, destination_port: destination }.freeze
          end.freeze
        end

        private

        # 每个范围完整消费；多端口是并集，倒序或不完整的 to 不能被截短。
        def port_range(words)
          first = words.shift
          last = first
          if words.first == "to"
            words.shift
            last = words.shift
          end
          unless last&.match?(/\A\d+\z/) && Integer(first, 10) <= Integer(last, 10)
            raise ArgumentError, "Service port range is incomplete or descending"
          end
          first, last = Integer(first, 10), Integer(last, 10)
          range = "#{first}-#{last}"
          IPAddr.ports(range)
          (first == last ? first.to_s : range).freeze
        end
      end
    end
  end
end
