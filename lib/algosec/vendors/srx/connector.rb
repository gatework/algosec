# frozen_string_literal: true

require_relative "../../connector"

module Algosec
  module Vendors
    module Srx
      # Juniper SRX 的 set 格式配置连接器，支持 Junos 分页和错误诊断。
      class Connector < Net::Connector::Base
        vendor :srx

        # 运行配置只能从 operational 视图读取，不能把 candidate 当作已生效配置。
        class RunningConfiguration < Net::Connector::RunningConfig::Rendered
          def prompt_text(command)
            prompt = super
            unless prompt.end_with?(">")
              raise Net::Connector::DeviceError.new("SRX collection requires operational mode",
                code: :uncommitted_configuration, host: @device.host, phase: :collect)
            end
            prompt
          end
        end

        # 声明 Junos 的配置命令、提示、分页和错误规则。
        profile do
          running_config_strategy RunningConfiguration
          commands do
            running_config "show config | display set | no-more"
          end

          prompts do
            login(/(?:\A|(?<=[\r\n]))\S+[#>]\s*\z/)
            command(/(?:\A|(?<=[\r\n]))[^\r\n]+[>#]\s*\z/)
          end

          pager do
            pattern(/(?:\A|(?<=[\r\n]))[ \t]*-{2,3}\(more(?:[ \t]+\d+%)?\)-{2,3}[ \t]*(?=\r|\n|\z)/i)
          end

          errors do
            command(/^[ \t]*(?:%[ \t]*)?Invalid input detected\s+.+\^/i, /^[ \t]*error:/i,
                    /^[ \t]*syntax error/i
            )
          end
        end
      end
    end
  end
end
