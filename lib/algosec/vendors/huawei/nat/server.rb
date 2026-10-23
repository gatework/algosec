# frozen_string_literal: true

require_relative "../../../vendors"
require_relative "../../../ipaddr"
require_relative "../network_syntax"

module Algosec
  module Vendors
    module Huawei
      module Nat
        # 一条服务器映射的语法与投影；配置来源、目录写入和诊断由 Parser 管理。
        class Server
          class Error < StandardError
            attr_reader :code

            def initialize(message, code: :invalid_nat_server)
              @code = code
              super(message)
            end
          end

          attr_reader :name

          def initialize(words, &find_interface)
            words = words.dup
            if words.include?("vpn-instance")
              raise Error.new("Huawei NAT server VPN instance is not modeled", code: :unsupported_nat_vrf)
            end
            if words.include?("unr-route")
              raise Error.new("Huawei NAT server black-hole route is not modeled", code: :unsupported_nat_server_option)
            end
            @name = words.shift
            if @name.nil? || %w[zone protocol global inside].include?(@name)
              raise Error, "Huawei NAT server is missing its name"
            end
            @id = words.shift if words.first&.match?(/\A\d+\z/)
            selectors = {}
            while %w[zone protocol].include?(words.first)
              key, value = words.shift(2)
              if selectors.key?(key) || value.nil? || %w[zone protocol global inside].include?(value)
                raise Error, "Huawei NAT server has a duplicate or missing #{key}"
              end
              selectors[key] = value
            end
            @zone, @protocol = selectors.values_at("zone", "protocol")
            if @protocol && IPAddr.protocol_number(@protocol).zero?
              raise Error, "Huawei NAT server protocol must be explicit when specified"
            end
            unless words.first == "global" && words.count("global") == 1 && words.count("inside") == 1
              raise Error, "Huawei NAT server requires a global section followed by an inside section"
            end
            inside = words.index("inside")
            public = words[1...inside]
            private = words.drop(inside + 1)
            @no_reverse = private.last == "no-reverse"
            private.pop if @no_reverse
            if public.first == "interface"
              public.shift
              @interface = NetworkSyntax.shift_interface(public)
              interface = find_interface&.call(@interface)
              unless interface&.host
                raise Error.new("NAT interface #{@interface} has no IP", code: :missing_interface)
              end
              public = [ interface.host, *public ]
            end
            @public_set, @public_port = endpoint(public)
            @private_set, @private_port = endpoint(private)
            unless @public_set.cardinality == @private_set.cardinality
              raise Error, "Huawei NAT server public and private address ranges must have equal sizes"
            end
            if @private_port && !@public_port
              raise Error, "Huawei NAT server private port requires a public port"
            end
            @private_port ||= @public_port
            if @protocol && @public_set.cardinality > 1
              raise Error.new("Huawei protocol-specific NAT server range pairing is not modeled", code: :unsupported_nat_server_range)
            end
          rescue ArgumentError => error
            raise Error, error.message
          end

          def type = @protocol ? :dynamic_nat : :static_nat

          # 协议限定映射的反向条件需要版本证据，不能从前向条件猜测。
          def unresolved_reverse? = !!@protocol && !@no_reverse

          def attributes
            common = { name: name, id: @id, rule_set: "nat-server", interface: @interface }
            if type == :static_nat
              common.merge(real_ip: IPAddr.format_range(@private_set.first), mapped_ip: IPAddr.format_range(@public_set.first),
                           real_set: @private_set, mapped_set: @public_set, mapped_zone: @zone,
                           source_nat_enabled: !@no_reverse)
            else
              # 仅限定协议时端口保持，不声明另一段转换服务。
              common.merge(direction: :destination, from_zone: @zone, source_set: Set.new(0..IPAddr::IPV4_MAX),
                           destination_set: @public_set, translated_destination_set: @private_set, protocol: @protocol,
                           destination_port: @public_port, translated_destination_port: @private_port,
                           service_set: IPAddr.service("#{@protocol}/#{@public_port || '0-65535'}"),
                           translated_service_set: @private_port && IPAddr.service("#{@protocol}/#{@private_port}"))
            end
          end

          private

          # 一个端点是单地址或连续地址段，加一个可选端口；未识别尾项必须报错。
          def endpoint(words)
            words = words.dup
            first = words.shift
            last = words.first&.include?(".") ? words.shift : first
            unless [ first, last ].all? { |value| value && /\A(?:\d{1,3}\.){3}\d{1,3}\z/.match?(value) }
              raise Error, "Huawei NAT server has an invalid IPv4 address"
            end
            first_set, last_set = IPAddr.parse(first), IPAddr.parse(last)
            unless first_set.min <= last_set.min && words.size <= 1
              raise Error, "Huawei NAT server address or port fields are invalid"
            end
            port = words.first
            if port
              unless @protocol && [ 6, 17, 132 ].include?(IPAddr.protocol_number(@protocol)) && /\A\d+\z/.match?(port)
                raise Error, "Huawei NAT server port mapping needs a transport protocol and a numeric port"
              end
              ports = IPAddr.ports(port)
              if ports.min.zero?
                raise Error.new("Huawei NAT server zero-port wildcard is not modeled", code: :unsupported_nat_server_port)
              end
            end
            [ IPAddr.between(first, last), port ]
          end
        end
      end
    end
  end
end
