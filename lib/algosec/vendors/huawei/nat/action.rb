# frozen_string_literal: true

require_relative "../../../vendors"
require_relative "../../../ipaddr"

module Algosec
  module Vendors
    module Huawei
      module Nat
        # 动作只描述转换方向和目标；地址池查找、接口选路与服务引用由 Parser 装配。
        class Action
          attr_reader :direction, :target, :value, :port

          def initialize(words)
            words = words.dup
            @direction = { "source-nat" => :source, "destination-nat" => :destination }[words.shift]
            raise ArgumentError, "Unsupported Huawei NAT action" unless direction
            if words.first == "static"
              raise ArgumentError, "Huawei static NAT policy pairing is not modeled"
            end

            @target = words.shift
            unless %w[address-group address easy-ip].include?(target) && (target != "easy-ip" || direction == :source)
              raise ArgumentError, "Unsupported Huawei NAT translation target"
            end
            if target != "easy-ip"
              @value = words.shift
              raise ArgumentError, "NAT translation target is missing" if value.nil? || value.empty?
              if target == "address"
                unless /\A(?:\d{1,3}\.){3}\d{1,3}\z/.match?(value) && IPAddr.new(value).ipv4?
                  raise ArgumentError, "NAT translation requires an IPv4 host"
                end
              end
            end
            if direction == :destination && !words.empty?
              @port = words.shift
              unless /\A\d+\z/.match?(port) && (1..IPAddr::PORT_MAX).cover?(Integer(port, 10))
                raise ArgumentError, "NAT destination port requires one number in 1..65535"
              end
              @port = Integer(port, 10).to_s
            end
            raise ArgumentError, "Unsupported Huawei NAT action suffix" unless words.empty?
          end
        end
      end
    end
  end
end
