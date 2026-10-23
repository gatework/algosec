# frozen_string_literal: true

require_relative "../../ipaddr"
require_relative "elements"

module Algosec
  module Vendors
    module Huawei
      # 网络命令只转换语法和值；接口状态、来源行和出口解析由 Parser 管理。
      module NetworkSyntax
        DEFAULT_PREF = 60
        INTERFACE_TYPE = /(?:[a-z][a-z-]*|[1-9]\d*ge)/i
        INTERFACE_NUMBER = /\d+(?:[\/.:-]\d+)*/

        class << self
          # 声明、区域绑定及路由/NAT 引用共用名称，兼容类型与编号分写。
          def interface_name(words)
            valid = (words.one? && /\A#{INTERFACE_TYPE}#{INTERFACE_NUMBER}\z/o.match?(words.first)) ||
              (words.size == 2 && /\A#{INTERFACE_TYPE}\z/o.match?(words.first) && /\A#{INTERFACE_NUMBER}\z/o.match?(words.last))
            raise ArgumentError, "Interface requires a type and number" unless valid

            words.join
          end

          # 从仍含后续端口或选项的命令中读取一个完整接口名称。
          def shift_interface(words)
            count = /\A#{INTERFACE_TYPE}\z/o.match?(words.first.to_s) ? 2 : 1
            interface_name(words.shift(count))
          end

          def vpn_name(value)
            unless value && (1..31).cover?(value.length) && value != "_public_"
              raise ArgumentError, "VPN instance requires a name of 1 to 31 characters other than _public_"
            end
            if value == Elements.default_vrf
              raise ArgumentError, "VPN instance #{value} conflicts with the public routing domain name"
            end
            value
          end

          def preference(value) = route_number(value, "preference", 1..255)

          # 原生命令要求点分 IPv4，不能沿用查询层把 any 转成零地址的便利语法。
          def ipv4(value)
            unless value.is_a?(String) && /\A\d{1,3}(?:\.\d{1,3}){3}\z/.match?(value)
              raise ArgumentError, "Network command requires an IPv4 address"
            end
            IPAddr.from_i(IPAddr.to_i(value))
          end

          # 完整消费一条静态路由；未建模的跟踪、递归等条件不能丢失后变成普通路由。
          def route_fields(words, preference: DEFAULT_PREF)
            rest = words.dup
            vrf = Elements.default_vrf
            if rest.first == "vpn-instance"
              rest.shift
              vrf = vpn_name(rest.shift)
            end
            address, mask = rest.shift(2)
            raise ArgumentError, "Route requires an IPv4 address and mask" unless address && mask

            subnet = IPAddr.network_cidr(ipv4(address), mask)
            attributes = { vrf: vrf, subnet: subnet, distance: self.preference(preference), extra_conf: {} }
            if rest.first == "vpn-instance"
              rest.shift
              attributes[:destination_vrf] = vpn_name(rest.shift)
            elsif rest.first && !%w[preference tag description].include?(rest.first) &&
                  /\A#{INTERFACE_TYPE}(?:#{INTERFACE_NUMBER})?\z/o.match?(rest.first)
              attributes[:destination_interface] = shift_interface(rest)
            end
            if rest.first&.match?(/\A\d+\./)
              attributes[:next_hop] = ipv4(rest.shift)
            end
            if rest.first == "public" && vrf != Elements.default_vrf && attributes[:next_hop] &&
               !attributes[:destination_interface] && !attributes[:destination_vrf]
              attributes[:destination_vrf] = Elements.default_vrf
              rest.shift
            end
            unless attributes[:destination_interface] || attributes[:next_hop] || attributes[:destination_vrf]
              raise ArgumentError, "Route requires an interface, next hop or destination VPN instance"
            end
            route_options(attributes, rest)
            attributes
          end

          private

          def route_options(attributes, rest)
            fields = {}
            until rest.empty?
              field = rest.shift
              raise ArgumentError, "Duplicate route field #{field}" if fields[field]
              fields[field] = true
              case field
              when "preference" then attributes[:distance] = preference(rest.shift)
              when "tag" then attributes[:extra_conf]["tag"] = route_number(rest.shift, field, 1..4_294_967_295)
              when "description"
                raise ArgumentError, "Route description is empty" if rest.empty?
                attributes[:description] = rest.join(" ")
                rest.clear
              else raise ArgumentError, "Unsupported route field #{field}"
              end
            end
          end

          def route_number(value, field, range)
            unless (value.is_a?(String) || value.is_a?(Integer)) && /\A\d+\z/.match?(value.to_s)
              raise ArgumentError, "Route #{field} must be numeric"
            end
            number = Integer(value.to_s, 10)
            unless range.cover?(number)
              raise ArgumentError, "Route #{field} must be between #{range.begin} and #{range.end}"
            end
            number
          end
        end
      end
    end
  end
end
