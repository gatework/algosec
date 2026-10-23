# frozen_string_literal: true

require_relative "../policy"
require_relative "error"
module Algosec
  module OfflineCheck
    # 一个 case 的累计配置声明；不模拟设备命令执行或首条命中行为。
    class Readback
      SUPPORTED = %i[hillstone h3c huawei].freeze
      RULE_FIELDS = %i[name action from_zones to_zones status log log_enabled rule_number rule_set rule_type
                       from_interface dst_interfaces conditions vendor_data nat?].freeze
      Check = Data.define(:result, :rule_ids)
      private_constant :SUPPORTED, :RULE_FIELDS, :Check

      def initialize(config, enabled:, prefix:, at:, &parse)
        @config, @text, @vendor = config, config.reader.content, config.reader.vendor
        @enabled, @prefix, @at, @parse = enabled, Array(prefix), at, parse
        @checks = []
      end

      # 同批后续命令可引用前段创建的对象；只有本段全部核验成功才推进状态。
      def perform(result, command_text, nat_context: result)
        # 缺口切片保留原始地址作来源；缩小区间本身不是地址转换。
        nat = nat?(nat_context)
        if result.type == :ignore && command_text.empty? && !nat
          check = Check.new(result: result, rule_ids: [ result.rule&.identity ])
          verify_rules!(check, @config)
          @checks << check
          return :existing_coverage_verified
        end
        if result.type == :ignore && !command_text.empty? && !nat_changes?(result)
          raise Error, "已有规则生成了非 NAT 命令"
        end
        return :readback_skipped unless @enabled
        return :readback_unavailable unless SUPPORTED.include?(@vendor)
        raise Error, "新增或修改规则没有生成命令" if command_text.empty? && result.type != :ignore

        text = command_text.empty? ? @text : @text + "\n" + normalize(command_text, result)
        candidate = command_text.empty? ? @config : @parse.call(text)
        require_complete!(candidate)
        new_rules = verify_changes!(result, candidate)
        ids = result.type == :new ? new_rules.map(&:identity) : [ result.rule&.identity ]
        check = Check.new(result: result, rule_ids: ids)
        verify_rules!(check, candidate)
        @config, @text = candidate, text
        @checks << check
        nat ? :policy_ranges_nat_unverified : :exact_ranges_after_readback
      end

      # 报告发布前重新核对全部结果，后段成功不能代替前段在最终配置中的成立。
      def verify!
        @checks.each { |check| verify_rules!(check, @config) }
        true
      end

      private

      # 已有 NAT 的复用和地址还原同样需要转换证据，不能只检查新建动作。
      def nat?(result)
        nat_changes?(result) || result.services.values.any? { |entry| entry[:translated_port] } ||
          [ result.sources, result.destinations ].any? do |members|
            members.any? do |address, entry|
              entry[:nat] || ([ address ] + entry.values_at(:origin, :main, :private, :real_ip).compact).uniq.size > 1
            end
          end
      end

      # :ignore 只表示安全策略已覆盖，仍可能带有独立的 NAT 新建操作。
      def nat_changes?(result)
        (result.actions || {}).values.any? do |action|
          %i[nat_sources nat_destinations].any? { |dimension| action.fetch(dimension, {}).any? }
        end
      end

      # 原配置已完整，候选的旧行、无行号诊断同样不能跳过。
      def require_complete!(config)
        return if config.complete?

        details = config.diagnostics.map do |diagnostic|
          "#{diagnostic.code}@#{diagnostic.line_number || 'unknown'}: #{diagnostic.message}"
        end.join("; ")
        raise Error, "生成命令回读不完整：#{details}"
      end

      # 每段只允许其声明的规则变化；共享对象变更会由引用图传播到其他规则。
      def verify_changes!(result, candidate)
        comparison = Config::Comparison.new(before: @config, after: candidate).perform
        raise Error, "回读规则引用图不完整" unless comparison.fetch(:complete)
        comparison.fetch(:changes).each do |change|
          allowed = change[:status] == "added" && result.type == :new
          allowed ||= change[:status] == "modified" && result.type == :modify && change[:rule_id] == result.rule.rule_id
          raise Error, "回读改变了目标之外的规则 #{change[:rule_id]}" unless allowed
        end
        before_bindings, after_bindings = [ @config, candidate ].map do |config|
          config.elements(Elements::RuleBinding).map(&:identity).sort
        end
        raise Error, "回读改变了规则链的区域绑定" unless before_bindings == after_bindings

        original_ids = @config.rules.map(&:identity)
        candidate.rules.reject { |rule| original_ids.include?(rule.identity) }
      end

      # 使用现有的严格规则视图；服务限制、DNS 条件等不能只取已知范围。
      def verify_rules!(check, config)
        result = check.result
        snapshot = snapshot(config, result.snapshot)
        if result.type == :ignore && result.rule.nil?
          return verify_existing_coverage!(result, snapshot)
        end
        rules = check.rule_ids.map do |id|
          config.rules.find { |rule| rule.identity == id } || raise(Error, "目标规则未在配置回读中找到")
        end
        requested = request_ranges(result)
        if result.type == :new
          raise Error, "新规则没有被配置回读识别" if rules.empty?
          actual = rules.reduce(Policy::TrafficSet.new) do |traffic, rule|
            verify_metadata!(rule, result, snapshot)
            request = Policy::Analysis::RuleView.new(snapshot, rule, at: @at).request
            maps = request.transform_values { |values| values.to_h { |value| [ value, {} ] } }
            traffic | Policy::Request::Traffic.from_maps(maps)
          end
          expected = result.uncovered || result.traffic_set
          raise Error, "新规则扩大了请求的源/目的/服务组合" unless expected.cover?(actual)
          raise Error, "新规则没有覆盖请求的源/目的/服务组合" unless actual.cover?(expected)
        else
          rule = rules.fetch(0)
          verify_metadata!(rule, result, snapshot)
          actual = rule_ranges(rule, snapshot)
          if result.type == :ignore
            raise Error, "已有规则不能覆盖请求" unless actual.all? { |dimension, set| set.cover?(requested.fetch(dimension)) }
          else
            expected = rule_ranges(result.rule, result.snapshot).to_h do |dimension, current|
              values = result.actions.fetch(:add, {}).fetch(dimension, {}).keys
              additions = dimension == :services ? Policy::Ranges.services(values) : Policy::Ranges.addresses(values)
              [ dimension, current | additions ]
            end
            raise Error, "修改后的规则范围与请求不一致" unless actual == expected
          end
        end
      end

      # 联合覆盖或默认动作没有唯一规则身份；重新计算完整请求，保留顺序与时间约束。
      def verify_existing_coverage!(result, snapshot)
        group = %i[device_id device_name vendor nat_mode from_zone to_zone hit sources destinations services].to_h do |field|
          [ field, result.public_send(field) ]
        end
        current = Policy::RuleMatcher.new(snapshot, at: @at).match(group, schedule: result.schedule)
        raise Error, "已有规则不能覆盖请求" unless current.type == :ignore && !nat_changes?(current)
        true
      end

      def request_ranges(result)
        { sources: Policy::Ranges.addresses(result.sources.keys), destinations: Policy::Ranges.addresses(result.destinations.keys),
          services: Policy::Ranges.services(result.services.keys) }
      end

      def rule_ranges(rule, snapshot)
        raise Error, "查询结果没有已有规则" unless rule
        Policy::Analysis::RuleView.new(snapshot, rule, at: @at).ranges
      end

      # 配置使用同一厂商定义、固件版本、设置和内置服务，来源仍由解析结果提供。
      def snapshot(config, template)
        Policy::Snapshot.from_config(config, version: template.version, software_version: template.software_version,
          settings: template.settings, builtin_services: template.builtin_services, definition: template.definition)
      end

      # 修改保留范围以外的全部规则属性；新增规则必须保留请求的动作和时间条件。
      def verify_metadata!(rule, result, snapshot)
        if result.type == :new
          unless [ rule.from_zones, rule.to_zones ] == [ [ result.from_zone ], [ result.to_zone ] ] &&
                 snapshot.behavior.rule_decision(rule) == result.decision && !rule.disabled?
            raise Error, "新规则的安全域、动作或启用状态与请求不一致"
          end
          actual = Policy::Analysis::RuleView.new(snapshot, rule, at: @at).schedule
          expected = result.schedule
          matches = expected ? actual&.kind == :once && actual.window == expected.window : actual.nil?
          raise Error, "新规则的时间条件与请求不一致" unless matches && !rule.starts_at && !rule.expires_at
          unless snapshot.behavior.rule_in_zones?(rule, from_zone: result.from_zone, to_zone: result.to_zone)
            raise Error, "新规则没有绑定到请求的区域方向"
          end
        else
          original = result.rule
          raise Error, "查询结果没有已有规则" unless original
          unless RULE_FIELDS.all? { |field| rule.public_send(field) == original.public_send(field) } &&
                 schedule_data(rule.schedule) == schedule_data(original.schedule) && rule.schedule_name == original.schedule_name &&
                 snapshot.behavior.rule_scope(rule) == result.snapshot.behavior.rule_scope(original)
            raise Error, "回读改变了已有规则的范围外属性、顺序或绑定"
          end
        end
      end

      def schedule_data(schedule)
        return unless schedule
        [ schedule.kind, schedule.time_zone.name, schedule.start_at, schedule.end_at,
          schedule.weekly_windows, schedule.monthly_periods, schedule.unparsed_commands ]
      end

      # 只删除生成器声明的命令外壳；厂商归一化不隐藏正文中的未知命令。
      def normalize(command_text, result)
        lines = command_text.lines.map(&:chomp)
        frame = result.definition.generator.declarations.fetch(:command_frame).options
        before, after = frame.values_at(:before, :after)
        unless before.is_a?(Array) && after.is_a?(Array) && lines.take(before.size) == before && lines.last(after.size) == after
          raise Error, "生成命令的配置模式外壳无法归一化"
        end
        lines = lines.drop(before.size).take(lines.size - before.size - after.size)
        lines = case @vendor
        when :hillstone then hillstone(lines)
        when :h3c then lines.map { |line| line == "exit" ? "#" : line }
        when :huawei then lines.map { |line| line == "quit" ? "#" : line }
        end
        rows = @prefix + lines
        rows << "#" if %i[h3c huawei].include?(@vendor) && rows.last != "#"
        rows.join("\n") + "\n"
      end

      # 合成编号只用于声明回读；追加文本不能证明 rule top 的设备执行顺序。
      def hillstone(lines)
        ids = @config.rules.filter_map do |rule|
          Integer(rule.native_rule_id, 10) if rule.native_rule_id&.match?(/\A\d+\z/)
        end
        next_id = (ids.max || 0) + 1
        lines.map do |line|
          next line unless line == "rule top"
          replacement = "rule id #{next_id}"
          next_id += 1
          replacement
        end
      end
    end

    private_constant :Readback
  end
end
