# frozen_string_literal: true

require_relative "../../connector"
require "net/connector/vendor/huawei"

module Algosec
  module Vendors
    module Huawei
      # 通过 Algosec 厂商注册复用 net-connector 的设备协议。
      class Connector < Net::Connector::Vendor::Huawei
      end
    end
  end
end
