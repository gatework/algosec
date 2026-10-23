# frozen_string_literal: true

module Algosec
  module Vendors
    module Topsec
      # 解析器与生成器共用关键字/值语法，不从字段值中的文本推断关键字。
      module Fields
        def self.parse(words)
          raise ArgumentError, "Expected command keyword/value pairs" if words.size.odd?

          words.each_slice(2).each_with_object({}) do |(key, value), fields|
            raise ArgumentError, "Duplicate command field #{key.inspect}" if fields.key?(key)

            fields[key] = value
          end
        end
      end
    end
  end
end
