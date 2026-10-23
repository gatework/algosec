# frozen_string_literal: true

require "digest"
require "json"
require "time"
require_relative "../builtin_services"
require_relative "../config"
require_relative "../policy"
require_relative "error"
require_relative "output"
require_relative "readback"

module Algosec
  module OfflineCheck
    # 执行配置解析、策略查询、策略设计和可选配置回读的离线验证流程。
    class Firewall
      attr_reader :vendor, :plan, :output_path

      # 固定验证输入、设备元数据和完整性闸门，不连接设备或数据库。
      def initialize(config_path:, plan_path:, vendor: nil, output_path: nil,
                     builtin_services_path: nil, allow_incomplete: false, readback: true)
        @config_path = File.expand_path(config_path)
        @plan_path = File.expand_path(plan_path)
        @plan = load_plan(@plan_path)
        @vendor = Vendors.normalize(vendor || plan_vendor)
        @device_id = @plan.fetch("device_id")
        @device_name = @plan["device_name"] || network_device_name
        @time_zone = @plan.fetch("time_zone", "UTC")
        @reference_time = Time.iso8601(@plan.fetch("reference_time", Time.now.iso8601))
        @settings = @plan.fetch("settings", {})
        @version = @plan["version"]
        @builtin_services_path = if builtin_services_path
                                   File.expand_path(builtin_services_path)
        else
                                   resolve_plan_path(@plan["builtin_services"])
        end
        @output_path = File.expand_path(output_path || "tmp/firewall-verification-#{@vendor}").freeze
        validate_plan!
        raise ArgumentError, "allow_incomplete 必须是布尔值" unless [ true, false ].include?(allow_incomplete)
        @allow_incomplete = allow_incomplete || @plan["allow_incomplete"] == true
        raise ArgumentError, "readback 必须是布尔值" unless [ true, false ].include?(readback)
        @readback = readback && plan_readback_enabled?
      rescue KeyError, ArgumentError => error
        raise Error, "验证计划无效：#{error.message}"
      end

      # 顺序执行解析、缓存、查询和设计，并写出可审阅的 JSON 与 CLI 文件。
      def perform
        inputs = [ @config_path, @plan_path, @builtin_services_path ].compact
        Output.new(@output_path, inputs: inputs).open do |output|
          config_text = File.binread(@config_path)
          builtin_services_text = File.binread(@builtin_services_path) if @builtin_services_path
          input_checksums = [ checksum(@config_path, config_text), @plan_checksum.transform_values(&:dup) ]
          input_checksums << checksum(@builtin_services_path, builtin_services_text) if builtin_services_text
          ensure_inputs_unchanged!(input_checksums)
          builtin_services = load_builtin_services(builtin_services_text)
          @builtin_service_count = builtin_services.size
          parsed_config = parse(config_text, builtin_services)
          restored_config, cache_verified = cache_round_trip(parsed_config, output)
          snapshot, policy_gate = policy_snapshot(restored_config, builtin_services)
          searcher = Policy::Searcher.new(networks: @plan.fetch("networks"), snapshots: { @device_id => snapshot },
                                          clock: -> { @reference_time })
          cases = verify_cases(searcher, restored_config, builtin_services, output)
          ensure_inputs_unchanged!(input_checksums)
          summary = build_summary(restored_config, cache_verified, policy_gate, input_checksums, cases)
          summary.merge(report: output.publish(summary))
        end
      rescue SystemCallError, IOError, EncodingError => error
        raise Error, error.message
      end

      private

      # 读取计划并保留原始 JSON 结构，错误在入口统一转换为业务提示。
      def load_plan(path)
        content = File.binread(path)
        @plan_checksum = checksum(path, content)
        freeze_plan(JSON.parse(content))
      rescue Errno::ENOENT, JSON::ParserError => error
        raise Error, "验证计划不可读：#{path}（#{error.message}）"
      end

      # 计划在公开 reader 中只读，验证运行不能被调用者的内存修改改变。
      def freeze_plan(value)
        case value
        when Hash
          value.each { |key, item| freeze_plan(key); freeze_plan(item) }.freeze
        when Array
          value.each { |item| freeze_plan(item) }.freeze
        else
          value.freeze
        end
      end

      # 解析已计算摘要的服务原文，后续不重新读取可能已变化的文件。
      def load_builtin_services(content)
        return {} unless content

        BuiltinServices.new(JSON.parse(content), vendor: @vendor, device_id: @device_id).services
      rescue BuiltinServices::Error => error
        raise Error, error.message
      rescue JSON::ParserError => error
        raise Error, "内置服务文件不可读：#{@builtin_services_path}（#{error.message}）"
      end

      # 从显式厂商或网络记录取得 Parser、Policy 共用的厂商身份。
      def plan_vendor
        @plan["vendor"] || Array(@plan["networks"]).first&.fetch("vendor")
      end

      # 没有显式设备名时使用网络记录或配置文件名。
      def network_device_name
        Array(@plan["networks"]).first&.fetch("device_name", nil) || File.basename(@config_path)
      end

      # 计划内的相对辅助文件相对计划文件解析，命令行路径相对当前目录解析。
      def resolve_plan_path(path)
        return unless path
        value = path.to_s
        value.start_with?(File::SEPARATOR) ? value : File.expand_path(value, File.dirname(@plan_path))
      end

      # 检查设备编号、网络范围、厂商一致性和至少一个策略请求。
      def validate_plan!
        raise ArgumentError, "settings 必须是 JSON 对象" unless @settings.is_a?(Hash)
        if @plan.key?("allow_incomplete") && ![ true, false ].include?(@plan["allow_incomplete"])
          raise ArgumentError, "allow_incomplete 必须是布尔值"
        end
        validate_readback!
        raise ArgumentError, "device_id 必须是正整数" unless @device_id.is_a?(Integer) && @device_id.positive?
        raise ArgumentError, "device_name 必须是非空字符串" unless @device_name.is_a?(String) && !@device_name.empty?
        raise ArgumentError, "网络记录必须是非空数组" unless @plan["networks"].is_a?(Array) && !@plan["networks"].empty?
        unless @plan["networks"].all? do |row|
          row.is_a?(Hash) && row["device_id"] == @device_id && Vendors.normalize(row["vendor"]) == @vendor
        end
          raise ArgumentError, "网络记录必须属于同一设备和厂商"
        end
        raise ArgumentError, "cases 必须是非空数组" unless @plan["cases"].is_a?(Array) && !@plan["cases"].empty?
        @plan["cases"].each do |scenario|
          raise ArgumentError, "每个 case 必须包含 name 和 request" unless scenario.is_a?(Hash) && scenario["name"] && scenario["request"].is_a?(Hash)
          %w[sources destinations services].each do |dimension|
            values = scenario["request"][dimension] || scenario["request"][dimension.to_sym]
            raise ArgumentError, "#{scenario["name"]} 缺少 #{dimension}" unless values.is_a?(Array) && !values.empty?
          end
          validate_expectations!(scenario)
        end
        raise ArgumentError, "配置文件不存在：#{@config_path}" unless File.file?(@config_path)
        raise ArgumentError, "内置服务文件不存在：#{@builtin_services_path}" if @builtin_services_path && !File.file?(@builtin_services_path)
      end

      # 断言字段类型明确，防止 malformed expected 被静默忽略或延迟触发 TypeError。
      def validate_expectations!(scenario)
        expected = scenario.fetch("expected", {})
        raise ArgumentError, "expected 必须是 JSON 对象" unless expected.is_a?(Hash)
        unknown = expected.keys - %w[type rule_id verification]
        raise ArgumentError, "expected 包含未知字段：#{unknown.map(&:inspect).join(', ')}" if unknown.any?

        type_keys = %w[expected_type expected_types].select { |key| scenario.key?(key) }
        type_keys << "expected.type" if expected.key?("type")
        raise ArgumentError, "expected type 只能声明一次" if type_keys.size > 1
        type = type_keys.one? ? (type_keys.first == "expected.type" ? expected.fetch("type") : scenario.fetch(type_keys.first)) : nil
        if type
          values = type.is_a?(Array) ? type : [ type ]
          raise ArgumentError, "expected type 必须是非空字符串或字符串数组" unless values.any? && values.all? { |value| value.is_a?(String) && !value.empty? }
        elsif type_keys.any?
          raise ArgumentError, "expected type 不能为空"
        end

        validate_expected_scalar!(scenario, expected, "expected_rule_id", "rule_id", String, Integer)
        validate_expected_scalar!(scenario, expected, "expected_verification", "verification", String)
      end

      # 顶层和嵌套断言是同一字段的两种写法，不能同时提供互相遮蔽。
      def validate_expected_scalar!(scenario, expected, top_level, nested, *types)
        present = scenario.key?(top_level) || expected.key?(nested)
        if scenario.key?(top_level) && expected.key?(nested)
          raise ArgumentError, "#{top_level} 与 expected.#{nested} 只能提供一个"
        end
        return unless present

        value = scenario.key?(top_level) ? scenario.fetch(top_level) : expected.fetch(nested)
        valid = types.any? { |type| value.is_a?(type) } && !(value.is_a?(String) && value.empty?)
        raise ArgumentError, "#{top_level} 类型无效" unless valid
      end

      # 回读配置只接受已实现的选项，避免错误形状延迟到命令生成阶段才失败。
      def validate_readback!
        return unless @plan.key?("readback")
        options = @plan["readback"]
        raise ArgumentError, "readback 必须是 JSON 对象" unless options.is_a?(Hash)
        unknown = options.keys - %w[enabled prefix]
        raise ArgumentError, "readback 包含未知字段：#{unknown.map(&:inspect).join(', ')}" if unknown.any?
        if options.key?("enabled") && ![ true, false ].include?(options["enabled"])
          raise ArgumentError, "readback.enabled 必须是布尔值"
        end
        prefix = options["prefix"]
        unless prefix.nil? || prefix.is_a?(String) || (prefix.is_a?(Array) && prefix.all? { |line| line.is_a?(String) })
          raise ArgumentError, "readback.prefix 必须是字符串或字符串数组"
        end
      end

      # 计划可以关闭回读，但默认对已有的三家厂商执行回读检查。
      def plan_readback_enabled?
        @plan.fetch("readback", {}).fetch("enabled", true)
      end

      # 统一使用 Parser 入口，保留部分结果而不把未知命令当成成功。
      def parse(config_text, builtin_services)
        Config::Parser.perform(config_text, vendor: @vendor, device_id: @device_id, device_name: @device_name,
                               time_zone: @time_zone, reference_time: @reference_time, builtin_services: builtin_services,
                               settings: @settings)
      rescue Config::ParseError => error
        raise Error, "配置解析失败：#{error.message}"
      end

      # 保存并恢复 Result，确保后续策略验证使用与持久化结果相同的对象图。
      def cache_round_trip(parsed_config, output)
        cache = Config::Cache.new(directory: output.cache_path)
        cache.save(parsed_config)
        restored_config = cache.load(@device_id)
        raise Error, "配置缓存回读改变了解析结果" unless cache_signature(parsed_config) == cache_signature(restored_config)

        [ restored_config, true ]
      end

      # 只比较跨进程稳定的 Reader、诊断、引用统计和范围报告。
      def cache_signature(parsed_config)
        [ parsed_config.reader.content, parsed_config.reader.lines, parsed_config.reader.parsed_flags, parsed_config.diagnostics,
         parsed_config.reference_counts, parsed_config.rule_projection.sources, parsed_config.rule_projection.destinations, parsed_config.rule_projection.services ]
      end

      # 部分配置可以输出解析诊断，但不升级为可用于策略验证的证据。
      def policy_snapshot(parsed_config, builtin_services)
        unless parsed_config.complete? || @allow_incomplete
          raise Error, "配置有 #{parsed_config.diagnostics.size} 条诊断，不能验证策略；设置 allow_incomplete: true 可输出解析诊断"
        end
        snapshot = Policy::Snapshot.from_config(parsed_config, version: @version, builtin_services: builtin_services.values,
                                                settings: @settings, allow_incomplete: @allow_incomplete)
        [ snapshot, snapshot.complete? ? :complete_configuration : :partial_configuration ]
      rescue Policy::Error, ArgumentError => error
        raise Error, "策略快照构造失败：#{error.message}"
      end

      # 对每个请求执行查询、设计、命令保存和范围/回读验证。
      def verify_cases(searcher, original_config, builtin_services, output)
        @plan.fetch("cases").each_with_index.map do |scenario, index|
          request = scenario.fetch("request").transform_keys(&:to_sym)
          unless original_config.complete?
            Policy::Request.new(**request)
            next { name: scenario.fetch("name"), request: json_value(request), results: [], status: "unknown",
                   reason: "配置解析不完整，未执行策略查询、命令生成或回读验证" }
          end
          report = searcher.perform!(**request)
          check_expected_type!(scenario, report)
          designs = Policy::Planner.new(report).perform
          # 查询可能包含多个精确缺口；逐段结果必须与生成器使用同一拆分契约。
          results = report.results.flat_map do |result|
            result.generation_results.map { |slice| [ slice, result ] }
          end
          readback = Readback.new(original_config, enabled: @readback, prefix: @plan.dig("readback", "prefix"), at: @reference_time) do |text|
            parse(text, builtin_services)
          end
          offsets = Hash.new(0)
          case_results = results.each_with_index.map do |(policy_result, query_result), result_index|
            device_design = designs.find { |design| design[:device_id] == policy_result.device_id }
            raise Error, "#{scenario.fetch("name")} 没有对应的设备设计" unless device_design
            offset = offsets[policy_result.device_id]
            offsets[policy_result.device_id] += 1
            command_text = device_design.fetch(:policy_contents).fetch(offset).fetch(:new).fetch(:content)
            verification = readback.perform(policy_result, command_text, nat_context: query_result)
            check_expected_result!(scenario, policy_result, verification)
            command_file = output.write(command_name(index, policy_result, scenario, results.size, result_index), command_text)
            {
              device_id: policy_result.device_id, device_name: policy_result.device_name, vendor: policy_result.vendor,
              type: policy_result.type, hit: policy_result.hit, rule_id: policy_result.rule&.rule_id,
              from_zone: policy_result.from_zone, to_zone: policy_result.to_zone, verification: verification,
              commands: command_file, design: json_value(device_design)
            }
          end
          readback.verify!
          { name: scenario.fetch("name"), request: json_value(request), results: case_results }
        end
      rescue Policy::Error, ArgumentError => error
        raise Error, "策略验证失败：#{error.message}"
      end

      # 预期类型是可选断言，未声明时保留实际查询结果。
      def check_expected_type!(scenario, report)
        expected_types = scenario["expected_types"] || scenario["expected_type"] || scenario.dig("expected", "type")
        return unless expected_types

        expected_types = Array(expected_types).map(&:to_s)
        actual_types = report.results.map { |policy_result| policy_result.type.to_s }
        raise Error, "#{scenario.fetch("name")} 类型为 #{actual_types.inspect}，预期 #{expected_types.inspect}" unless actual_types == expected_types
      end

      # 预期规则编号是可选断言，适合固定配置的复用/追加样例。
      def check_expected_result!(scenario, policy_result, verification)
        expected_rule_id = scenario["expected_rule_id"] || scenario.dig("expected", "rule_id")
        if expected_rule_id && policy_result.rule&.rule_id.to_s != expected_rule_id.to_s
          raise Error, "#{scenario.fetch("name")} 命中规则 #{policy_result.rule&.rule_id.inspect}，预期 #{expected_rule_id.inspect}"
        end
        expected_state = scenario["expected_verification"] || scenario.dig("expected", "verification")
        if expected_state && verification.to_s != expected_state.to_s
          raise Error, "#{scenario.fetch("name")} 验证状态 #{verification.inspect}，预期 #{expected_state.inspect}"
        end
      end

      # 给每个 case/result 分配稳定、可审阅的 CLI 文件名。
      def command_name(index, policy_result, scenario, result_count, result_index)
        label = scenario.fetch("name").to_s.encode("UTF-8", invalid: :replace, undef: :replace)
                        .gsub(/[^\p{Alnum}_.-]+/u, "-").sub(/\A-+|-+\z/, "")
        label = "case" if label.empty?
        suffix = result_count > 1 ? "-device-#{policy_result.device_id}-result-#{result_index + 1}" : ""
        format("%02d-%s-%s%s.cli", index + 1, policy_result.type, label, suffix)
      end

      # 读取当前磁盘摘要，在解析前和验证结束时检查输入是否发生变化。
      def checksums
        [ @config_path, @plan_path, @builtin_services_path ].compact.map do |path|
          { path: path, sha256: Digest::SHA256.file(path).hexdigest }
        end
      end

      # 报告摘要绑定实际参与解析的字节，不以之后再次读取的内容替代。
      def checksum(path, content)
        { path: path, sha256: Digest::SHA256.hexdigest(content) }
      end

      # 验证期间不允许配置、计划或服务定义发生变化。
      def ensure_inputs_unchanged!(before)
        after = checksums
        raise Error, "验证输入在运行期间发生变化" unless before == after
      end

      # 汇总配置对象、诊断、缓存闸门和各请求验证结果。
      def build_summary(parsed_config, cache_verified, policy_gate, input_checksums, cases)
        {
          status: parsed_config.complete? ? "ok" : "incomplete", vendor: @vendor, device_id: @device_id, device_name: @device_name,
          reference_time: @reference_time.iso8601, analysis_mode: @plan["analysis_mode"],
          topology_assumption: @plan["topology_assumption"], inputs: input_checksums,
          builtin_services: { provided: !@builtin_services_path.nil?, imported: @builtin_service_count },
          configuration: {
            bytes: parsed_config.reader.content.bytesize, lines: parsed_config.reader.size, complete: parsed_config.complete?,
            objects: parsed_config.elements.group_by { |element| element.class.name.split("::").last }.transform_values(&:size),
            diagnostics: parsed_config.diagnostics.group_by(&:code).transform_keys(&:to_s).transform_values do |diagnostic_rows|
              { count: diagnostic_rows.size, lines: diagnostic_rows.filter_map(&:line_number) }
            end,
            unparsed_lines: parsed_config.unparsed_lines.size, rules: parsed_config.rules.size
          },
          policy: { gate: policy_gate, allow_incomplete: @allow_incomplete, readback: @readback && parsed_config.complete? },
          cache_verified: cache_verified, cases: cases
        }
      end

      # 把符号键和领域值转换为 JSON 可读的递归结构。
      def json_value(value)
        case value
        when Hash then value.to_h { |key, item| [ key.to_s, json_value(item) ] }
        when Array then value.map { |item| json_value(item) }
        when Symbol then value.to_s
        else value
        end
      end
    end
  end
end
