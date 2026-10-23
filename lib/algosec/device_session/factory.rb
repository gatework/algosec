# frozen_string_literal: true

require_relative "../device_session"

module Algosec
  class DeviceSession
    # 工厂拥有会话；只有 open 返回后，部署协调器才确认命令通道退出。
    class Factory
      def initialize(vendor, options)
        @vendor, @options = vendor, options
      end

      def open(&block) = DeviceSession.open(@vendor, **@options, &block)
    end
  end
end
