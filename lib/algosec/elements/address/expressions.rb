# frozen_string_literal: true

module Algosec
  module Elements
    module Address
      # 地址表达式与类型化叶子之间的转换；数值范围仍由 Elements 校验和计算。
      module Expressions
        module_function

        def format(leaves)
          leaves.map { |leaf| leaf.fetch("value") }
        end

        def parse(values, concrete: false)
          validate_expressions!(values).map do |value|
            validate_expression!(value)
            type = if value.include?(":") then "ipv6"
            elsif value.include?("/") then "subnet"
            elsif value.match?(/\A[\d.]+-[\d.]+\z/) then "iprange"
            elsif value.match?(/\A[\d.]+\z/) then "host"
            else "domain"
            end
            if concrete && !%w[host subnet iprange].include?(type)
              raise ArgumentError, "Rule addresses must be concrete IPv4 values"
            end
            raise ArgumentError, "Invalid domain expression" if type == "domain" && !value.match?(/\A[\p{L}\p{N}_*.-]+\z/)
            { "type" => type, "value" => value }
          end
        end

        def validate_expressions!(values)
          raise ArgumentError, "Members must be an array of expressions" unless values.is_a?(Array)
          values
        end

        def validate_expression!(value)
          raise ArgumentError, "Member expression must be nonempty text" unless value.is_a?(String) && !value.empty? && value == value.strip
        end
        private_class_method :validate_expressions!, :validate_expression!
      end
    end
  end
end
