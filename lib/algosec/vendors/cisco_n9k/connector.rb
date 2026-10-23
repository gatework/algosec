# frozen_string_literal: true

require_relative "../../connector"
require "net/connector/vendor/cisco_nxos"

module Algosec
  module Vendors
    module CiscoN9k
      # 通过 Algosec 厂商注册复用 net-connector 的设备协议。
      class Connector < Net::Connector::Vendor::CiscoNxos
      end
    end
  end
end
