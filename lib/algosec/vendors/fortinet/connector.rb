# frozen_string_literal: true

require_relative "../../connector"
require "net/connector/vendor/fortinet"

module Algosec
  module Vendors
    module Fortinet
      # 通过 Algosec 厂商注册复用 net-connector 的设备协议。
      class Connector < Net::Connector::Vendor::Fortinet
        SAVE_CONFIRMATION = /\Aconfig saved\.\z/i
      end
    end
  end
end
