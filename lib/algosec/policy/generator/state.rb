# frozen_string_literal: true

require_relative "../value"

module Algosec
  module Policy
    class Generator
      # 本次生成的对象名称、编号和 NAT 绑定；成功后才复制回同一快照的共享状态。
      class State
        # 从共享状态复制本次设计的对象分配记录，隔离单次失败。
        def initialize(snapshot, generator:, state: {})
          unless state.empty? || state[:snapshot].equal?(snapshot)
            raise Error.new("对象分配状态只能用于原始配置快照，请使用新的状态重新生成", code: :mixed_snapshots)
          end
          unless state.empty? || state[:generator].equal?(generator)
            raise Error.new("对象分配状态只能用于原始命令生成器，请使用新的状态重新生成", code: :mixed_definitions)
          end
          @snapshot, @state = snapshot, Value.copy(state)
          @state[:snapshot] = snapshot
          @state[:generator] = generator
        end

        # 只有命令生成成功时才把本次状态复制回共享状态。
        def commit(shared_state)
          shared_state&.replace(Value.copy(@state))
        end

        # 多次从同一旧规则计算追加项可能互相覆盖，或产生请求之外的组合流量。
        def claim_rule_modification(rule)
          modifications = @state[:rule_modifications] ||= {}
          key = rule.locator
          if modifications.key?(key)
            raise Error.new("同一批次不能重复修改规则 #{@snapshot.signature(rule)}，请合并请求后重新设计", code: :conflicting_rule_modifications)
          end
          modifications[key] = true
        end

        # 为业务定义分配不冲突的稳定名称，并在代码块成功后登记。
        def define(kind, key, preferred, type: nil, zone: nil, occupied: [], case_sensitive: true)
          definitions = @state[kind] ||= {}
          return definitions[key] if definitions.key?(key)

          occupied += definitions.values
          if type
            # 一种原生引用可同时指向对象和对象组；外置内建服务同样占用名称。
            types = Array(type)
            objects = @snapshot.catalog.to_a + @snapshot.builtin_services
            occupied += objects.select do |element|
              types.any? { |klass| element.is_a?(klass) } && (!zone || element.address_reference_zones(zone).include?(element.zone))
            end.map(&:name)
          end
          name_key = ->(name) { case_sensitive ? name : name.downcase }
          occupied = occupied.to_h { |name| [ name_key.call(name), true ] }
          name = preferred
          suffix = 2
          while occupied.include?(name_key.call(name))
            name = "#{preferred}_#{suffix}"
            suffix += 1
          end
          yield name
          definitions[key] = name
        end

        # 对同一状态键只执行一次命令生成代码。
        def once(key)
          emitted = @state[:commands] ||= {}
          return if emitted[key]

          yield
          emitted[key] = true
        end

        # 在既有编号和本次编号中选择范围内第一个可用编号。
        def available_id(kind, key, range, used)
          definitions = @state[kind] ||= {}
          return definitions[key] if definitions.key?(key)

          occupied = (used.compact + definitions.values).to_h do |id|
            text = id.to_s
            [ /\A[0-9]+\z/.match?(text) ? text.to_i.to_s : text, true ]
          end
          selected = range.find { |id| !occupied.key?(id.to_s) }
          raise Error, "没有可用的 #{kind} 编号" unless selected

          definitions[key] = selected.to_s
        end

        # 检查绑定冲突，只有对应命令生成成功才登记目标。
        def claim(kind, key, binding, message:)
          bindings = @state[kind] ||= {}
          previous = bindings[key]
          raise Error, message if previous && previous != binding

          result = yield
          bindings[key] = binding
          result
        end

        # 范围型声明先核对历史批次；成功后才登记，沿用外层生成事务。
        def register_batch(kind, entries)
          previous = @state.fetch(kind, [])
          yield previous
          @state[kind] = (previous + entries).uniq
        end
      end

      private_constant :State
    end
  end
end
