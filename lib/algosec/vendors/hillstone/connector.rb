# frozen_string_literal: true

require_relative "../../connector"
require "net/connector/vendor/hillstone"

module Algosec
  module Vendors
    module Hillstone
      # 策略生成可能复用已有对象；仅容忍明确的 already exists 响应。
      class Connector < Net::Connector::Vendor::Hillstone
        SAVE_CONFIRMATION = /\ASaving configuration is finished\.?\z/i

        profile do
          errors do
            command(
              /^[ \t]*\^-+/i,
              /^\s*\^/,
              /^[ \t]*(?:Unknown|Invalid|Error)\s+command/i,
              /^[ \t]*Error:(?![ \t]*This[ \t]+entity[ \t]+(?:is[ \t]+)?already[ \t]+exists?\.?[ \t]*\r?$)[^\r\n]+/i
            )
          end
        end
      end
    end
  end
end
