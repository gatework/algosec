# frozen_string_literal: true

require_relative "../../connector"

module Algosec
  module Vendors
    module Neteye
      # Neteye 通过显式 configure mode 操作进入配置模式。
      class Connector < Net::Connector::Base
        vendor :neteye
        # 声明 Neteye 的命令、提示、诊断、提权和兼容规则。
        profile do
          running_config_strategy Net::Connector::RunningConfig::Rendered
          commands do
            running_config "show current-config"
            save_config "save config"
          end

          prompts do
            login(/\S+[#>\]]\s*\z/)
            command(/(?:\A|(?<=[\r\n]))\s*\S+[>#\]]\s*\z/)
            username(/(?:login|name):\s*\z/i)
          end

          errors do
            command(/^[ \t]*(?:%[ \t]*)?Invalid input detected\s+.+\^/i)
          end

          ssh do
            legacy_arguments "-v", "-1", "-c", "des"
          end

          privilege do
            command "configure mode"
            prompt(/(?:\A|(?<=[\r\n]))\S+#\s*\z/)
          end

          command_timeout 10

          interactions do
            confirm(/\[startup-config\]\?/i, response: "\n")
          end
        end

        # 清除退格回显和 CRLF，避免终端编辑字符污染配置结果。
        def clean_config(text)
          text.gsub(/\x00?\x08+[ \t]+\x08+/, "").gsub("\r\n", "\n")
        end
      end
    end
  end
end
