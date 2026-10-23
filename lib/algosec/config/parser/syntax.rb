# frozen_string_literal: true

require_relative "../../declarations"

module Algosec
  module Config
    class Parser
      # 只声明阶段、词前缀和字段映射；树、块、NAT 等语法仍由具名方法解释。
      module Syntax
        # 以声明顺序执行阶段；同一方法可在不同依赖点显式调用。
        def stage(name, using: nil)
          raise ArgumentError, "Stage names and handlers must be symbols" unless name.is_a?(Symbol) && (using.nil? || using.is_a?(Symbol))
          declare([ :stage, name ], using: using)
        end

        # 同阶段的相同词前缀不能重复；不同前缀按声明顺序选择第一个。
        def line_rule(stage, name, prefix:, using:)
          unless [ stage, name, using ].all? { |value| value.is_a?(Symbol) }
            raise ArgumentError, "Line rule requires a stage, name and named handler"
          end
          unless prefix.is_a?(Array) && prefix.any? && prefix.all? { |word| word.is_a?(String) }
            raise ArgumentError, "Line rule requires a nonempty token prefix"
          end
          if declarations.any? { |key, entry| key[0, 2] == [ :line, stage ] && key.last != name && entry.options[:prefix] == prefix }
            raise ArgumentError, "Duplicate line prefix in #{stage}: #{prefix.inspect}"
          end
          declare([ :line, stage, name ], prefix: prefix, using: using)
        end

        # 字段声明明确值转换和累积方式；复杂转换通过具名方法处理。
        def field(group, keyword, to:, convert: :first, merge: :replace)
          raise ArgumentError, "Invalid field merge: #{merge}" unless %i[replace append union].include?(merge)
          raise ArgumentError, "Field target and conversion must be symbols" unless to.is_a?(Symbol) && convert.is_a?(Symbol)
          declare([ :field, group, keyword.to_s ], to: to, convert: convert, merge: merge)
        end

        # 在应用加载时发现阶段拼写、处理方法缺失和孤立的匹配声明。
        def validate_declarations!
          prefixes = Hash.new { |hash, key| hash[key] = [] }
          declarations.each do |key, entry|
            method = entry.options[:using]
            method = entry.options[:convert] if key.first == :field && !%i[first join values].include?(entry.options[:convert])
            if method && !method_defined?(method) && !private_method_defined?(method)
              raise ArgumentError, "#{self}: missing handler #{method} at #{entry.source_location.join(':')}"
            end
            if key.first == :line && !declarations.key?([ :stage, key[1] ])
              raise ArgumentError, "#{self}: undeclared stage #{key[1]}"
            end
            if key.first == :stage && !method && declarations.keys.none? { |candidate| candidate[0, 2] == [ :line, key[1] ] }
              raise ArgumentError, "#{self}: stage #{key[1]} has no handler or line rules"
            end
            if key.first == :line
              prefix = entry.options[:prefix]
              if prefixes[key[1]].any? { |earlier| prefix.take(earlier.size) == earlier }
                raise ArgumentError, "#{self}: shadowed line prefix #{prefix.inspect} at #{entry.source_location.join(':')}"
              end
              prefixes[key[1]] << prefix
            end
          end
        end

        # 解析器实例只读取类声明，运行数据仍保存在本次解析状态中。
        module Runtime
          private

          # 阶段边界清除上一行定位，避免装配错误指向无关配置行。
          def parse_document
            @syntax.each do |key, entry|
              next unless key.first == :stage
              @current_line = nil
              handler = entry.options[:using]
              handler ? send(handler) : parse_lines(key[1])
            end
          end

          # 只匹配本阶段仍未消费的行；处理器成功返回 true 才自动消费。
          def parse_lines(stage)
            rules = @syntax.select { |key, _entry| key[0, 2] == [ :line, stage ] }.values
            pending.each do |line|
              words = tokens(line)
              rule = rules.find { |entry| words.take(entry.options[:prefix].size) == entry.options[:prefix] }
              next unless rule
              consume(line) if send(rule.options[:using], line, words) == true
            end
          end

          # 值转换成功后才修改草稿并消费原文；未知字段留给诊断阶段。
          def map_field(group, object, keyword, values, line)
            entry = @syntax[[ :field, group, keyword.to_s ]]
            return false unless entry
            @current_line = line
            conversion = entry.options[:convert]
            value = case conversion
            when :first then values.fetch(0)
            when :join then values.join(" ")
            when :values then values.dup
            else send(conversion, values)
            end
            target = entry.options[:to]
            previous = object.attributes[target]
            object.attributes[target] = case entry.options[:merge]
            when :replace then value
            when :append then Array(previous) + Array(value)
            when :union then (Array(previous) + Array(value)).uniq
            end
            capture(object, line)
            true
          end
        end
      end
    end
  end
end
