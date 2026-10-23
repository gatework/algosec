# frozen_string_literal: true

require_relative "../../declarations"

module Algosec
  module Policy
    class Generator
      # 声明稳定的命令外壳和维度名称，决策与 NAT 算法仍在厂商生成器中。
      module Syntax
        # 声明策略动作和新规则的落位方式，迁移据此保持原有执行顺序。
        def command_policy(placement:, logging_default: nil, **actions)
          unless %i[append prepend].include?(placement) && actions.key?(:permit) &&
                 (actions.keys - %i[permit deny]).empty?
            raise ArgumentError, "Invalid policy actions or placement"
          end
          actions.each_value { |value| Value.text(value, label: "策略动作") }
          raise ArgumentError, "Invalid default logging state" unless [ nil, true, false ].include?(logging_default)
          declare(:command_policy, placement: placement, actions: actions, logging_default: logging_default)
        end

        # 操作需要显式登记；未支持的厂商不会猜测删除或修改语法。
        def command_operation(name, using:)
          raise ArgumentError, "Invalid policy operation" unless name.is_a?(Symbol) && using.is_a?(Symbol)
          declare([ :command_operation, name ], handler: using)
        end

        # 三个策略维度使用统一名称；声明值是设备命令关键字。
        def command_fields(**fields)
          unless (fields.keys - Result::DIMENSIONS).empty? && fields.values.all? { |value| value.is_a?(String) && !value.empty? }
            raise ArgumentError, "Invalid policy command fields"
          end
          fields.each_value { |value| Value.text(value, label: "设备字段") }
          declare(:command_fields, fields: fields)
        end

        # 动态外壳通过具名方法生成，静态外壳只声明有序命令列表。
        def command_frame(before: [], after: [])
          unless [ before, after ].all? { |value| value.is_a?(Array) || value.is_a?(Symbol) }
            raise ArgumentError, "Command frame requires arrays or a named opening handler"
          end
          [ before, after ].grep(Array).flatten.each { |line| Value.text(line, label: "设备命令") }
          declare(:command_frame, before: before, after: after)
        end

        # 启动时检查动态外壳，避免直到生成命令时才发现方法拼写错误。
        def validate_declarations!
          handlers = declarations[:command_frame]&.options&.values || []
          handlers.concat(declarations.filter_map { |key, value| value.options[:handler] if key.is_a?(Array) && key.first == :command_operation })
          handlers.each do |handler|
            if handler.is_a?(Symbol) && !method_defined?(handler) && !private_method_defined?(handler)
              raise ArgumentError, "#{self}: missing command handler #{handler}"
            end
          end
        end

        module Runtime
          protected

          # 返回共享的只读维度映射，不保存任何设备运行数据。
          def command_fields = self.class.declarations.fetch(:command_fields).options.fetch(:fields)

          # 普通查询默认放行；声明能力的厂商才能生成其他动作。
          def policy_action(decision = result.decision)
            actions = self.class.declarations[:command_policy]&.options&.fetch(:actions) || { permit: "permit" }
            actions.fetch(decision) { raise Error.new("厂商不支持 #{decision} 动作", code: :unsupported_action) }
          end

          # 默认逐成员输出；厂商仍可覆盖需要 any 或编号处理的特殊语法。
          def member_commands(members, prefix: nil, quote: :quoted)
            command_fields.flat_map do |dimension, field|
              members.fetch(dimension, []).map { |name| [ prefix, field, send(quote, name) ].compact.join(" ") }
            end
          end

          # 配置块的打开和关闭必须显式；生成异常时由 Generator 丢弃整批命令。
          def command_block(*opening, close:)
            emit(*opening)
            yield
            emit(*Array(close))
          end

          # 批次与逐条预览共用外壳，不修改生成中的命令数组。
          def frame(lines)
            declaration = self.class.declarations[:command_frame]
            return lines if lines.empty? || !declaration
            before = declaration.options[:before]
            before = send(before) if before.is_a?(Symbol)
            after = declaration.options[:after]
            after = send(after) if after.is_a?(Symbol)
            [ *before, *after ].each { |line| Value.text(line, label: "设备命令") }
            [ *before, *lines, *after ]
          end
        end
      end
    end
  end
end
