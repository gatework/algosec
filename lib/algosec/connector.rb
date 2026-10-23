# frozen_string_literal: true

require "net/connector"
require_relative "vendors"

module Algosec
  # 厂商注册入口；会话、认证、传输和脚本执行由 net-connector 提供。
  module Connector
    SAVE_FAILURE = /\b(?:error|failed|failure|denied|cannot|unable|unsuccessful|aborted)\b|
      \b(?:not|never)\s+(?:(?:yet|successfully)\s+)?(?:save|saved|saving|write|writing|written|commit|committing|committed|persist|persisting|persisted|finished|successful)\b|
      \b(?:save|saving|write|writing|commit|committing|persist|persisting)\s+(?:(?:was|is|has|did)\s+)?(?:not|never)\b/ix

    # 静态能力不建立连接；保存流程未声明的设备不能进入自动下发。
    def self.capabilities(vendor)
      entry = Vendors.definition(vendor)
      components = entry.components
      connector = entry.fetch(:connector) if components.include?(:connector)
      profile = connector&.profile
      collect = profile && profile.config_commands.any?
      parse = components.include?(:parser)
      design = components.include?(:generator)
      { login: !profile.nil?, collect: !!collect, parse: parse, design: design,
        deploy: !!(collect && parse && design && profile.save_commands.any? && connector.const_defined?(:SAVE_CONFIRMATION, false)) }.freeze
    end

    # 只接受本厂商保存命令的明确完成行；失败历史不能被终端重绘覆盖。
    def self.persistence_confirmed?(vendor, result)
      connector = Vendors.fetch(vendor, :connector)
      return false unless connector.const_defined?(:SAVE_CONFIRMATION, false)
      # 已完成响应之后的日志故障不撤销设备保存事实；其他执行错误仍需核实。
      return false unless result.success? || result.error.instance_of?(Net::Connector::LogError)
      expected = connector.profile.save_commands
      return false if expected.empty? || result.steps.map { |step| step.command.text } != expected

      pattern = connector.const_get(:SAVE_CONFIRMATION, false)
      result.steps.all? do |step|
        raw = step.output.delete_suffix(step.prompt.to_s)
        history = raw.gsub(/\e\[[0-9;:]*m/, "").gsub(/\r(?!\n)/, "\n")
        rendered = Net::Connector::Terminal::Text.render(raw)
        next false if [ history, Net::Connector::Terminal::Text.render(history), rendered ].any? { |text| text.match?(SAVE_FAILURE) }

        rendered.lines.any? { |line| line.strip.match?(pattern) }
      end
    end

    def self.build(vendor, **options)
      Vendors.fetch(vendor, :connector).new(**options)
    end

    def self.open(vendor, **options, &block)
      Vendors.fetch(vendor, :connector).open(**options, &block)
    end
  end
end
