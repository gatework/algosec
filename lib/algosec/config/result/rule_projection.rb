# frozen_string_literal: true

require_relative "../../elements"

module Algosec
  module Config
    class Result
      # 报告只投影已经识别的规则部分；使用导入结果做策略判断前应先检查完整性。
      # 缺失引用永远不等同于任意范围。
      class RuleProjection
        attr_reader :sources, :destinations, :services

        # 跳过忽略规则，并按规则身份保存地址和协议端口投影。
        def initialize(rules, at:)
          @sources, @destinations, @services = {}, {}, {}
          addresses = Elements::Address::Expansion::Projection.new(at: at)
          rules.each do |rule|
            next if rule.ignored?(at: at)
            @sources[rule.identity] = addresses.call(rule.sources).fetch(:set)
            @destinations[rule.identity] = addresses.call(rule.destinations).fetch(:set)
            rule.services.ports.each do |protocol, ports|
              (@services[protocol] ||= {})[rule.identity] = ports
            end
          end
          @sources.freeze
          @destinations.freeze
          @services.each_value(&:freeze)
          @services.freeze
          freeze
        end
      end
    end
  end
end
