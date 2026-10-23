# frozen_string_literal: true

require_relative "../../connector"

module Algosec
  module Vendors
    module Netscreen
      # Juniper ScreenOS 在单个命令批次内跟踪新分配的策略编号。
      class Connector < Net::Connector::Base
        vendor :netscreen
        # 声明 ScreenOS 的命令、提示、超时和诊断规则。
        profile do
          running_config_strategy Net::Connector::RunningConfig::Rendered
          commands do
            running_config "get config"
            save_config "save"
          end

          prompts do
            login(/(?:\A|(?<=[\r\n]))[^\r\n]+->\s*\z/)
            command(/(?:\A|(?<=[\r\n]))[^\r\n]+->\s*\z/)
          end

          errors do
            command(/^[ \t]*\^-+[ \t]*unknown keyword/i, /^[ \t]*error:/i, /^[ \t]*Failed command/i)
          end

          command_timeout 120
        end

        # 清除退格回显并统一换行，返回稳定的配置文本。
        def clean_config(text) = text.gsub(/\x00?\x08+[ \t]+\x08+/, "").gsub("\r\n", "\n")

        protected

        # 发送占位策略命令前，用同一批次中的真实编号替换 X。
        def prepare_command(command, execution)
          return command unless /\A[ \t]*set\s+policy\s+id\s+X+[ \t]*\z/i.match?(command.text)

          policy_id = execution.context[:policy_id]
          raise execution.build_error("policy ID is missing; execute set policy top first") unless policy_id

          command.with_text("set policy id #{policy_id}")
        end

        # 创建策略后从设备响应中提取编号并保存到当前批次变量。
        def after_command(command, response, execution)
          return unless /\A[ \t]*set[ \t]+policy[ \t]+top(?:[ \t]|\z)/i.match?(command.text)

          policy_id = response.raw[/policy\s+id\s*=\s*(\d+)\s*/i, 1]
          raise execution.build_error("device did not return the new policy ID") unless policy_id

          execution.context[:policy_id] = policy_id
        end
      end
    end
  end
end
