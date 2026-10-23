# frozen_string_literal: true

require_relative "../../connector"
require "net/connector/vendor/h3c"

module Algosec
  module Vendors
    module H3c
      # 通过 Algosec 厂商注册复用 net-connector 的设备协议。
      class Connector < Net::Connector::Vendor::H3c
        SAVE_CONFIRMATION = /\ASaved the current configuration to mainboard device successfully\.\z/i
      end
    end
  end
end
