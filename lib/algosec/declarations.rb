# frozen_string_literal: true

module Algosec
  # 有限 DSL 的登记机制：复制并冻结声明，继承时合并，保留原始定义位置。
  module Declarations
    Declaration = Data.define(:options, :source_location)

    # 返回当前类和父类的只读声明，不向父类写入子类定义。
    def declarations
      inherited = superclass.respond_to?(:declarations) ? superclass.declarations : {}
      inherited.merge(@declarations || {}).freeze
    end

    # 同一类不能重复声明；子类可以显式覆盖继承值。
    def declare(key, location: caller_locations(2, 1).first, **options)
      raise ArgumentError, "Duplicate declaration: #{key.inspect}" if (@declarations || {}).key?(key)
      value = Declaration.new(deep_freeze(options), [ location.path.freeze, location.lineno ].freeze)
      @declarations = (@declarations || {}).merge(deep_freeze(key) => value).freeze
      value
    end

    private :declare

    private

    # 不冻结调用者持有的容器，避免声明产生跨类副作用。
    def deep_freeze(value)
      case value
      when Hash then value.to_h { |key, item| [ deep_freeze(key), deep_freeze(item) ] }.freeze
      when Array then value.map { |item| deep_freeze(item) }.freeze
      when String, Regexp then value.dup.freeze
      else value
      end
    end
  end
end
