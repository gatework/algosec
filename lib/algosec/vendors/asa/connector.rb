# frozen_string_literal: true

require_relative "../../connector"

module Algosec
  module Vendors
    module Asa
      # Cisco ASA 连接器；登录停留在非特权提示符时自动进入特权模式。
      class Connector < Net::Connector::Base
        SAVE_CONFIRMATION = /\A\[OK\]\z/i

        vendor :asa
        # 声明 ASA 的命令、提示、分页、诊断和认证规则；运行钩子继续使用普通方法。
        profile do
          running_config_strategy Net::Connector::RunningConfig::Rendered
          commands do
            running_config "show run | exclude !Time"
            save_config "write memory"
          end

          prompts do
            login(/\S+[#>]\s*\z/)
            command(/(?:\A|(?<=[\r\n]))\s*\S+[>#]\s*\z/)
            username(/(?:login|name):\s*\z/i)
          end

          pager do
            pattern(/(?:\A|(?<=[\r\n]))[ \t]*(?:--More--|---- More ----|<--- More --->)[ \t\x00\x08]*(?=\r|\n|\z)/i)
          end

          errors do
            command(/^[ \t]*(?:%[ \t]*)?(?:Invalid|Incomplete|Ambiguous)\s+(?:input|command)\b/i,
                    /^[ \t]*ERROR[:\s]/i)
          end

          ssh do
            legacy_arguments "-v", "-1", "-c", "des"
          end

          privilege do
            command "enable"
            prompt(/(?:\A|(?<=[\r\n]))\S+#\s*\z/)
          end

          command_timeout 10

          interactions do
            confirm(/\[startup-config\]\?/i, response: "\n")
          end
        end

        # 删除退格回显和设备换行差异，返回稳定的配置文本。
        def clean_config(text)
          text.gsub(/\x00?\x08+[ \t]+\x08+/, "").gsub("\r\n", "\n")
        end

        protected

        # 根据登录后的提示符判断是否已提权；未提权时立即执行 enable。
        def after_login(session, response)
          if /#\s*\z/.match?(response.prompt)
            session.mark_privileged!
          else
            session.enable(enable_command, enable_prompt)
          end
        end
      end
    end
  end
end
