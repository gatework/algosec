# frozen_string_literal: true

require_relative "../../connector"
require "net/connector/vendor/palo_alto"

module Algosec
  module Vendors
    module PaloAlto
      # 复用 PAN-OS set 采集及采集前后的 candidate 差异检查。
      class Connector < Net::Connector::Vendor::PaloAlto
      end
    end
  end
end
