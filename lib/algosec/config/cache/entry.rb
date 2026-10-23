# frozen_string_literal: true

module Algosec
  module Config
    class Cache
      # Rails cache store 会保留对象引用关系，但不会保留冻结标记。记录这些对象，
      # 恢复时重新冻结已发布领域图；Reader 自行恢复证据，游标保持独立。
      class Entry
        attr_reader :result, :source_key

        # 遍历结果对象图，记录已冻结对象并拒绝未知对象类型。
        def initialize(result, source_key: nil)
          @result = result
          @source_key = source_key&.dup&.freeze
          @frozen_objects = []
          visited = {}.compare_by_identity
          pending = [ result ]
          until pending.empty?
            object = pending.pop
            next if visited[object]
            visited[object] = true
            case object
            when NilClass, TrueClass, FalseClass, Symbol, Numeric, Class, ActiveSupport::TimeZone
              next
            when Array
              pending.concat(object)
            when Hash
              pending.concat(object.keys).concat(object.values)
              pending << object.default
            when Reader
              # Reader 的 marshal_load 会重建并冻结来源值，不缓存第三方游标内部布局。
            when Diagnostic
              pending.concat(object.cache_values)
            when Elements::Scope, Elements::Nat::OriginalPacket, Elements::Nat::Translation
              pending.concat(object.to_h.values)
            when Result, Result::RuleProjection, Elements::Catalog, Elements::Base
              # 这是对象布局缓存，不是公共序列化格式；模型布局变化时必须提升 CACHE_VERSION。
              pending.concat(object.instance_variables.map { |name| object.instance_variable_get(name) })
            when String, Range, Time, ActiveSupport::TimeWithZone, Set
              # 值类型由 Rails cache coder 负责序列化，Set 会在恢复时重新计算哈希。
            else
              raise TypeError, "Unsupported configuration cache value: #{object.class}"
            end
            @frozen_objects << object if object.frozen?
          end
        end

        def as_json(*) = { result: result.as_json }

        def inspect = "#<#{self.class.name} result=#{result.inspect}>"
        alias to_s inspect

        # 恢复记录的冻结标记，并返回原始结果对象。
        def restore
          @frozen_objects.each(&:freeze)
          @source_key&.freeze
          result
        end
      end

      private_constant :Entry
    end
  end
end
