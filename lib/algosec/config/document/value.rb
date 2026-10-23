# frozen_string_literal: true

require "json"
require "digest"
require "time"
require "date"

module Algosec
  module Config
    class Document
      # JSON 值和固定结构校验独立于领域对象构造。
      module Value
        module_function

        def object(value, keys)
          fail! unless value.instance_of?(Hash) && value.keys.sort == keys.map(&:to_s).sort
          value
        end

        def fail! = raise(InvalidDocument, "Invalid configuration document")

        def json(value, depth = 0, budget = [ 0, 0 ])
          fail! if depth > 64 || (budget[0] += 1) > 1_000_000
          case value
          when Hash
            fail! unless value.keys.all? { |key| key.instance_of?(String) }
            value.each_value { |item| json(item, depth + 1, budget) }
          when Array then value.each { |item| json(item, depth + 1, budget) }
          when String then fail! if value.bytesize > 16_000_000 || (budget[1] += value.bytesize) > 64_000_000 || !value.valid_encoding?
          when Integer, NilClass, TrueClass, FalseClass
          when Float then fail! unless value.finite?
          else fail!
          end
          value
        end

        def canonical(value)
          case value
          when Hash then value.keys.sort.to_h { |key| [ key, canonical(value.fetch(key)) ] }
          when Array then value.map { |item| canonical(item) }
          else value
          end
        end

        def digest(value) = Digest::SHA256.hexdigest(JSON.generate(canonical(value)))
        def time(value) = value&.iso8601(9)

        # 声明保留历史 ISO 精度与偏移格式，仅验证日期和时间，不重写原文。
        def declaration_time(value)
          fail! unless value.is_a?(String)
          DateTime.iso8601(value)
          Time.iso8601(value)
          value
        end

        def instant(value)
          fail! unless value.is_a?(String) && /\A\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{9}(?:Z|[+-]\d\d:\d\d)\z/.match?(value)
          Date.iso8601(value[0, 10])
          time = Time.iso8601(value)
          fail! unless time.iso8601(9) == value
          time
        end

        def ranges(value) = value&.ranges&.map { |range| { "first" => range.begin, "last" => range.end } }

        def set(value, maximum: IPAddr::IPV4_MAX)
          return nil if value.nil?
          fail! unless value.is_a?(Array)
          previous = -2
          ranges = value.map do |entry|
            object(entry, %w[first last])
            first, last = entry.values_at("first", "last")
            fail! unless first.is_a?(Integer) && last.is_a?(Integer) && first >= 0 && last >= first && last <= maximum && first > previous + 1
            previous = last
            first..last
          end
          Set.new(*ranges)
        end

        def scalar(value)
          value.is_a?(Symbol) ? value.to_s : value
        end

        def fields(object, names) = names.to_h { |name| [ name.to_s, scalar(object.public_send(name)) ] }

        def keywords(data, names) = names.to_h { |name| [ name, data.fetch(name.to_s) ] }
      end
    end
  end
end
