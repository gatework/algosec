# frozen_string_literal: true

require_relative "base"

module Algosec
  module Elements
    # 维护名称到成员的映射；派生范围由具体组按当前依赖计算。
    class Group < Base
      ELEMENT_TYPE = :group
      class UnresolvedReference < StandardError; end

      class CircularReference < StandardError; end

      include Enumerable

      # 通过 add 校验并登记初始成员。
      def initialize(name:, members: {}, **context)
        @members = {}
        super(name: name, **context)
        raise ArgumentError, "Members must be a name-to-object hash" unless members.is_a?(Hash)
        members.each { |key, object| add(key, object) }
      end

      # 返回成员类型约束。
      def member_class = self.class::MEMBER_CLASS

      # 返回成员映射的只读副本。
      def members = @members.dup.freeze

      # 返回当前直接依赖对象。
      def dependencies = @members.values.compact.freeze

      # 遍历名称和成员；没有代码块时返回枚举器。
      def each(&block) = block ? @members.each(&block) : enum_for(__method__)

      # 登记或覆盖同名成员，派生范围始终以当前成员为准。
      def add(name, object = nil)
        key = text(name)
        validate_member!(object)
        @members[key] = object
        self
      end

      # 替换成员；保留显式方法供调用方表达替换意图。
      def replace(name, object)
        key = text(name)
        validate_member!(object)
        commit(@members.merge(key => object))
      end

      # 删除成员后立即反映在派生范围中。
      def delete(name)
        key = text(name)
        candidate = @members.dup
        candidate.delete(key)
        commit(candidate)
      end

      # 解析本组直接引用；调用方负责先完成子组解析。
      def resolve!(strict: true)
        raise ArgumentError, "Strict must be true or false" unless strict == true || strict == false
        raise ArgumentError, "A reference resolver is required" unless block_given?
        candidate = @members.to_h do |key, object|
          resolved = object || yield(key)
          raise UnresolvedReference, "#{name} -> #{key}" if strict && resolved.nil?
          validate_member!(resolved)
          [ key, resolved ]
        end
        commit(candidate)
      end

      # 深度遍历叶子对象；未解析引用和循环会抛出领域异常。
      def leaves(&block)
        return enum_for(__method__) unless block
        @members.each do |key, object|
          raise UnresolvedReference, "#{name} -> #{key}" if object.nil?
          object.is_a?(Group) ? object.leaves(&block) : block.call(object)
        end
        self
      end

      # 通过一次叶子遍历判断整组引用是否完整。
      def resolved?
        unique_leaves { |_object| }
        true
      rescue UnresolvedReference
        false
      end

      # 集合查询按对象去重；公开 leaves 仍保留每条引用路径的遍历契约。
      def unique_leaves(strict: true, &block)
        raise ArgumentError, "Strict must be true or false" unless strict == true || strict == false
        return enum_for(__method__, strict: strict) unless block

        visited = {}
        walk = lambda do |object|
          return if visited[object.object_id]
          visited[object.object_id] = true
          if object.is_a?(Group)
            object.each do |key, child|
              raise UnresolvedReference, "#{object.name} -> #{key}" if strict && child.nil?
              walk.call(child) if child
            end
          else
            block.call(object)
          end
        end
        walk.call(self)
        self
      end

      protected

      # dup 创建可编辑候选；clone 沿用已封存成员，保持整个对象图不可变。
      def initialize_dup(original)
        super
        @members = @members.dup
      end

      def seal_owned_values!
        @members.freeze
        super
      end

      private

      # 检查成员类型、设备归属和循环依赖。
      def validate_member!(object)
        return if object.nil?
        unless object.is_a?(member_class) || object.is_a?(group_class)
          raise ArgumentError, "Invalid member for #{self.class.name}"
        end
        same_device!(object)
        if object.depends_on?(self)
          raise CircularReference, "#{name} -> #{object.name} -> #{name}"
        end
      end

      # 全部校验完成后一次提交成员快照。
      def commit(candidate)
        return self if sealed? && candidate == @members
        @members = candidate
        self
      end
    end
  end
end
