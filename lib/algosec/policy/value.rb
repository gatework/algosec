# frozen_string_literal: true

require_relative "error"
module Algosec
  module Policy
    # 只复制请求中的容器，保留配置对象的来源身份，不使用 Marshal。
    module Value
      module_function

      # 递归复制请求容器，保留领域对象的来源身份。
      def copy(value)
        case value
        when Hash then value.to_h { |key, item| [ copy(key), copy(item) ] }
        when Array then value.map { |item| copy(item) }
        when String then value.dup
        else value
        end
      end

      # 递归冻结请求容器和文本叶子。
      def freeze(value)
        case value
        when Hash then value.each { |key, item|
          freeze(key)
          freeze(item)
        }.freeze
        when Array then value.each { |item| freeze(item) }.freeze
        when String then value.freeze
        else value
        end
      end

      # 返回不再受调用方影响的深复制冻结值。
      def immutable(value) = freeze(copy(value))

      # 校验请求记录是文本键哈希，并转换为符号键副本。
      def hash(value)
        raise ArgumentError, "请求记录必须是 Hash" unless value.is_a?(Hash)
        value.each_with_object({}) do |(key, item), fields|
          raise ArgumentError, "请求字段名必须是字符串或符号" unless key.is_a?(String) || key.is_a?(Symbol)
          name = key.to_sym
          raise ArgumentError, "重复请求字段：#{name}" if fields.key?(name)
          fields[name] = copy(item)
        end
      end

      # 校验非空单行文本并返回副本。
      def text(value, label: "字段")
        unless value.is_a?(String) && !value.empty? && !value.match?(/[\x00-\x1f\x7f]/)
          raise ArgumentError, "#{label}必须是非空单行字符串"
        end
        value.dup
      end

      # 接受符号或字符串形式的枚举值，并把错误输入转换为领域参数错误。
      def symbol(value, label: "字段")
        unless value.is_a?(String) || value.is_a?(Symbol)
          raise ArgumentError, "#{label}必须是字符串或符号"
        end

        value.to_sym
      end
    end
  end
end
