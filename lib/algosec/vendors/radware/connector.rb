# frozen_string_literal: true

require_relative "../../connector"
require "net/connector/vendor/radware"

module Algosec
  module Vendors
    module Radware
      # 通过 Algosec 厂商注册复用 net-connector 的设备协议。
      class Connector < Net::Connector::Vendor::Radware
      end
    end
  end
end
