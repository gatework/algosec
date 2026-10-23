# frozen_string_literal: true

require_relative "service_object"
require_relative "group"

module Algosec
  module Elements
    # 服务组把成员服务投影为协议到端口的映射，并按需重新计算服务集合。
    class ServiceGroup < Group
      ELEMENT_TYPE = :service_group
      include Service::Expansion
      MEMBER_CLASS = ServiceObject
      attr_reader :protocol

      def group_class = ServiceGroup

      def initialize(protocol: nil, **attributes)
        @protocol = text(protocol, optional: true)
        super(**attributes)
      end

      # 报告保留已知成员的端口证据；严格范围查询通过 set 检查缺失引用。
      def ports
        unique_leaves(strict: false).reduce({}) do |result, object|
          result.merge(object.ports) { |_protocol, previous, added| previous | added }
        end.freeze
      end

      # 从当前叶子重新计算集合，避免嵌套服务变化留下旧范围。
      def set = Set.new(*unique_leaves.flat_map { |object| object.set.ranges })

      # 判断任一叶子服务是否匹配给定流量。
      def matches?(**traffic)
        complete = unique_leaves.to_a
        complete.any? { |service| service.matches?(**traffic) }
      end
    end
  end
end
