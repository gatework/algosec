# frozen_string_literal: true

require "ctx_driver"
require_relative "connector"
require_relative "config/reader"
require_relative "collector"
require_relative "device_session/read_error"
require_relative "device_session/capture"

module Algosec
  # 业务采集使用借用会话；认证、分页、命令执行和关闭仍由 net-connector 管理。
  class DeviceSession
    attr_reader :device_id

    # 块的所有退出路径均由连接器关闭会话，不在业务层重复连接或重试。
    def self.open(vendor, device_id: nil, **options)
      raise ArgumentError, "open requires a block" unless block_given?

      Connector.open(vendor, **options) do |connector|
        yield new(connector, vendor: vendor, device_id: device_id)
      end
    end

    def self.factory(vendor, **options) = Factory.new(vendor, options)

    # 借用连接器并保留其原始 Result，不提前 value! 丢失部分完成收据。
    def execute_script(script, on_receipt: nil, &progress)
      validate_receipt!(on_receipt)
      if receipt_callback?(:execute_script)
        @connector.execute_script(script, on_receipt: on_receipt, &progress)
      elsif on_receipt
        # 未提供完成回调的连接器使用进度通知；失败步骤仍由部署方从返回 Result 补录。
        @connector.execute_script(script) do |step|
          on_receipt.call(step)
          progress&.call(step)
        end
      else
        @connector.execute_script(script, &progress)
      end
    end

    def save_config(on_receipt: nil)
      validate_receipt!(on_receipt)
      receipt_callback?(:save_config) ? @connector.save_config(on_receipt: on_receipt) : @connector.save_config
    end

    def initialize(connector, vendor:, device_id: nil)
      @connector, @vendor, @device_id = connector, Vendors.normalize(vendor), device_id
      @reader = CtxDriver::Reader.new(session: connector)
    end

    # 独立命令由 ctx_driver 固定正文、摘要和首次断链原因，不隐式重连。
    def read(command) = @reader.read(command)

    # 多步骤配置读取保留上游厂商策略，例如 PAN-OS 前后 candidate 差异检查。
    def read_config
      raise ReadError, @reader.failure if @reader.failure

      result = @connector.running_config
      content = config_body(result.value!, result.steps)
      raise ReadError, { code: :incomplete_configuration } if content.strip.empty?

      observed_at = Time.now.utc.iso8601(6)
      evidence = result.steps.map do |step|
        { command: step.command.text, sha256: Digest::SHA256.hexdigest(step.output),
          bytes: step.output.bytesize, observed_at: observed_at }
      end
      Capture.new(content: content, evidence: evidence)
    end

    # 可选厂商采集器只借用本会话，不改变连接器的认证和关闭职责。
    def collect
      collector = Vendors.supports?(@vendor, :collector) ? Vendors.fetch(@vendor, :collector) : Algosec::Collector
      collector.new.collect(self)
    end

    def inspect = "#<#{self.class.name} vendor=#{@vendor}>"

    private

    # 完成回执必须由依赖明确声明；当前无回执参数的实现按返回 Result 补录。
    def receipt_callback?(operation) = @connector.method(operation).parameters.include?([ :key, :on_receipt ])

    def validate_receipt!(callback)
      raise ArgumentError, "on_receipt must respond to call" unless callback.nil? || callback.respond_to?(:call)
    end

    # 上游配置策略可能保留首行回显与末尾提示符；仅删除本次已确认的边界。
    def config_body(content, steps)
      body = CtxParser::Input.text(content, encoding: :transcode)
      steps.reverse_each do |step|
        prompt = step.prompt.to_s
        next if prompt.empty?

        suffix = [ prompt, Net::Connector::Terminal::Text.render(prompt) ].find do |value|
          body == value || body.end_with?("\n#{value}", "\r#{value}")
        end
        next unless suffix

        body = body.delete_suffix(suffix)
        break
      end
      first = body[/\A[^\r\n]*(?:\r\n|\r|\n)/]
      body = body.delete_prefix(first) if first && steps.any? { |step| first.strip == step.command.text.strip }
      body
    end
  end
end

require_relative "device_session/factory"
