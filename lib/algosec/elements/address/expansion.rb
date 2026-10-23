# frozen_string_literal: true

require_relative "expansion/projection"

module Algosec
  module Elements
    module Address
      # 地址与地址组共用叶子展开协议；引用图保留在内存，数据库只保存投影。
      module Expansion
        # 静态 IPv4 取精确并集；域名和不支持类型保留原定义及独立证据。
        def self.normalize_member(leaves)
          concrete, other = leaves.partition { |leaf| %w[host subnet iprange].include?(leaf["type"]) }
          ranges = Set.new(*concrete.flat_map { |leaf| IPAddr.parse(leaf.fetch("value")).ranges })
          normalized = ranges.map do |range|
            if range.begin == range.end
              { "type" => "host", "value" => IPAddr.from_i(range.begin) }
            else
              value = IPAddr.format_range(range)
              { "type" => value.include?("/") ? "subnet" : "iprange", "value" => value }
            end
          end
          (normalized + other.uniq).map { |leaf| leaf.transform_values { |value| value.dup.freeze }.freeze }.freeze
        end

        # 递归展开并去重，域名保持原表达式，不用解析结果替换成员。
        def member = address_projection.fetch(:member)

        # 数据库范围使用整数闭区间，与 Set 无损往返。
        def range = set.ranges.map { |item| [ item.begin, item.end ] }

        # 双栈成员使用独立集合，不能将低位 IPv6 地址混入 IPv4。
        def ipv6_set
          address_projection(family: :ipv6).fetch(:set)
        end

        def ipv6_range = IPv6.ranges(ipv6_set)

        # 不完整和完整空集合不能混淆；域名即使成功解析仍具有条件性。
        def resolution = address_projection.fetch(:resolution)

        # 当前依赖的快照投影，成员替换和 DNS 更新后立即反映新值。
        def set = address_projection.fetch(:set)

        # 严格调用者不能使用部分集合证明覆盖。
        def resolved_set
          projection = address_projection
          unless projection[:resolution]["complete"]
            raise Group::UnresolvedReference, "#{name}: #{projection[:resolution]['errors'].join('; ')}"
          end
          projection[:set]
        end

        def resolved? = resolution.fetch("complete")

        def conditional? = resolution.fetch("conditional")

        # 统一递归入口同时生成叶子、范围和诊断，避免不同消费者各自展开。
        def address_projection(at: Time.current, domain: nil, answer: nil, family: nil)
          Projection.new(at: at, domain: domain, answer: answer, family: family).call(self)
        end

        # 成员展开后再应用对象自身的集合语义，嵌套组与共享报告使用同一协议。
        def transform_address_projection(projection, family:) = projection
      end
    end
  end
end
