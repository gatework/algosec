# frozen_string_literal: true

require_relative "../../collector"
require_relative "predefined_services"

module Algosec
  module Vendors
    module Hillstone
      # 固件服务表与配置来自同一会话；必要查询或表格校验失败时不交付采集。
      class Collector < Algosec::Collector
        def collect(session)
          captured = super
          services = session.read("show service predefined")
          raise DeviceSession::ReadError, services.failure unless services.success?

          table = PredefinedServices.new(services.body, device_id: session.device_id)
          DeviceSession::Capture.new(content: captured.content, builtin_services: table.services, truncated_services: table.truncated_names,
            evidence: captured.evidence + services.evidence)
        end
      end
    end
  end
end
