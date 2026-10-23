# frozen_string_literal: true

require_relative "unknown"
require_relative "../snapshot"
require_relative "../ranges"

module Algosec
  module Policy
    class Analysis
      # 一次分析中的规则视图；共享投影，保留设备规则作为证据来源。
      class RuleView
        attr_reader :snapshot, :rule, :at, :id, :scope, :rule_number

        # 每次分析重新建立视图，组成员和规则状态的变化不会留下陈旧缓存。
        def initialize(snapshot, rule, at:)
          @snapshot, @rule, @at = snapshot, rule, at
          @id = snapshot.signature(rule).freeze
          @scope = Value.immutable(snapshot.behavior.rule_scope(rule))
          @rule_number = snapshot.behavior.rule_number(rule)
        end

        def decision = snapshot.behavior.rule_decision(rule)

        def permit?
          unknown!("无法识别规则动作", :unsupported_action) unless decision
          decision == :permit
        end

        def disabled?
          unknown!("规则状态未识别", :unsupported_status) unless rule.status_known?
          unknown!("未解析命令可能改变规则状态", :unsupported_conditions) if rule.unparsed_commands?
          rule.disabled?
        end

        def expired?
          unknown!("未解析命令可能改变规则时间", :unsupported_conditions) if rule.unparsed_commands?
          schedule
          rule.expired?(at: at)
        end

        def enabled? = !disabled? && !expired?

        # 未绑定计划不能视作永久策略。
        def schedule
          unknown!("规则的时间计划未解析", :unresolved_schedule) if rule.schedule_name && !rule.schedule
          unknown!("组合时间计划尚不能确定生效条件", :unsupported_schedule) if rule.schedule && !rule.schedule.resolved?
          rule.schedule
        end

        # 完整网络语义才能用于覆盖判断或迁移，不能沿用查询中的部分服务投影。
        def ranges
          unknown!("配置解析不完整", :incomplete_configuration) unless snapshot.complete?
          @ranges ||= begin
                        if rule.application_or_user_restricted? ||
                           snapshot.behavior.unresolved_network_conditions?(rule) ||
                           !rule.security_profiles.empty? || rule.unparsed_commands?
                          unknown!("规则包含应用、接口、VLAN 或未解析条件", :unsupported_conditions)
                        end
                        unless terms.all? { |term| Ranges.unrestricted_term?(term) }
                          unknown!("服务包含源端口、ICMP 类型、应用标识或超时约束", :unsupported_service)
                        end
                        [ rule.sources, rule.destinations ].each { |group| group.unique_leaves { |address| validate_address!(address) } }
                        projected = Ranges.projection(rule)
                        unknown!("规则包含空匹配集合", :empty_match) if projected.values.any?(&:empty?)
                        projected.freeze
                      end
        rescue Elements::Group::UnresolvedReference => error
          unknown!(error.message, :unresolved_reference)
        end

        # 合规规则使用统一维度，无须重新展开厂商对象。
        def any?(dimension)
          maximum = (dimension == :services) ? IPAddr::SERVICE_MAX : IPAddr::IPV4_MAX
          ranges.fetch(dimension) == Set.new(0..maximum)
        end

        def services_overlap?(values) = ranges.fetch(:services).overlap?(Ranges.services(values))

        # 合规检查配置声明的单个维度，不据此证明整条策略可达或覆盖流量。
        # 未识别命令仍可能改变任一维度，不能跳过；其他维度的未知不扩散。
        def declared_range(dimension)
          raise ArgumentError, "Unknown policy dimension" unless %i[sources destinations services].include?(dimension)
          unknown!("规则包含未解析条件", :unsupported_conditions) if rule.unparsed_commands?
          @declared_ranges ||= {}
          @declared_ranges[dimension] ||= begin
            projected = if dimension == :services
              unless terms.all? { |term| Ranges.unrestricted_term?(term) }
                unknown!("服务包含源端口、ICMP 类型、应用标识或超时约束", :unsupported_service)
              end
              Ranges.rule_services(rule)
            else
              group = rule.public_send(dimension)
              group.unique_leaves { |address| validate_address!(address) }
              Ranges.rule_addresses(group)
            end
            unknown!("规则包含空匹配集合", :empty_match) if projected.empty?
            projected
          end
        rescue Elements::Group::UnresolvedReference => error
          unknown!(error.message, :unresolved_reference)
        end

        # 范围和时间窗口同时覆盖才成立；周期计划暂不推断等价关系。
        def covers?(other)
          unknown!("配置解析不完整", :incomplete_configuration) unless snapshot.complete? && other.snapshot.complete?
          return false unless scope == other.scope
          return false unless ranges.all? { |dimension, set| set.cover?(other.ranges.fetch(dimension)) }
          if rule.starts_at
            other_start = [ other.rule.starts_at, other.schedule&.start_at ].compact.max
            return false unless other_start && rule.starts_at <= other_start
          end
          if rule.expires_at
            other_end = [ other.rule.expires_at, other.schedule&.end_at ].compact.min
            return false unless other_end && rule.expires_at >= other_end
          end
          return true unless schedule
          return false unless other.schedule
          unless schedule.kind == :once && other.schedule.kind == :once && schedule.window && other.schedule.window
            unknown!("不能证明周期或不完整计划的覆盖关系", :unsupported_schedule)
          end
          schedule.window.begin <= other.schedule.window.begin && schedule.window.end >= other.schedule.window.end
        end

        # 把精确范围转换为现有请求协议，保持同一规则的三个维度组合。
        def request
          ranges
          {
            sources: ranges[:sources].map { |range| IPAddr.format_range(range) },
            destinations: ranges[:destinations].map { |range| IPAddr.format_range(range) },
            services: terms.map do |term|
              number = IPAddr.protocol_number(term[:protocol])
              if number.zero?
                "any"
              elsif [ IPAddr::TCP, IPAddr::UDP ].include?(number)
                "#{number}/#{term[:destination_port]}"
              else
                number.to_s
              end
            end.uniq
          }
        end

        # 领域检查可主动报告证据不足，而不是返回貌似合规的 false。
        def unknown!(message, code = :unknown_analysis)
          raise Analysis::Unknown.new(message, code: code)
        end

        private

        def terms = @terms ||= rule.services.unique_leaves.flat_map(&:terms)

        # 地址中的主机名和 IPv6 可能与 IPv4 混合，非空 IPv4 投影不代表完整定义。
        def validate_address!(address)
          if !address.resolved? || address.conditional?
            unknown!("地址包含未解析成员或随 DNS 变化的条件", :unsupported_address)
          end
        end
      end
    end
  end
end
