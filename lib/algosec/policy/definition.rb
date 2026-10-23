# frozen_string_literal: true

module Algosec
  module Policy
    # 策略层的应用边界协议。核心对象只持有行为和命令生成器的定义，
    # Definition.resolve 在应用边界统一查找厂商。
    class Definition
      class << self
        # 元素和策略共用厂商规范化与登记，不再安装全局 resolver。
        def resolve(vendor = :generic, explicit: nil)
          key = Vendors.normalize(vendor)
          definition = explicit || Vendors.definition(key).policy_definition
          raise ArgumentError, "不支持策略厂商：#{vendor}" unless definition
          [ key, validate_definition!(definition) ]
        end

        # 创建懒加载的厂商配置，避免核心定义文件直接加载厂商实现。
        def for(behavior:, generator:)
          unless behavior.respond_to?(:call) && (generator.nil? || generator.respond_to?(:call))
            raise ArgumentError, "Policy definition factories must respond to call"
          end

          Class.new(self) do
            define_singleton_method(:behavior) { |snapshot| behavior.call.new(snapshot) }
            define_singleton_method(:generator) do
              implementation = generator&.call
              raise ArgumentError, "当前策略厂商不支持命令生成" unless implementation
              implementation
            end
          end
        end

        # 用当前快照创建查询行为对象。
        def behavior(snapshot)
          require_relative "behavior" unless defined?(Behavior)
          Behavior.new(snapshot)
        end

        # 通用定义不提供命令生成器，具体厂商必须显式实现。
        def generator
          raise ArgumentError, "当前策略厂商不支持命令生成"
        end

        # 用结果和本次分配状态构造生成器；返回对象，不生成命令。
        def build_generator(result, state: nil) = generator.new(result, state: state)

        private

        # 确保解析结果是当前策略定义的子类。
        def validate_definition!(definition)
          unless definition.is_a?(Class) && definition <= self
            raise ArgumentError, "Invalid policy definition: #{definition.inspect}"
          end

          definition
        end
      end
    end
  end
end
