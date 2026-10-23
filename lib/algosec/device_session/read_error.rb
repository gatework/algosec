# frozen_string_literal: true

module Algosec
  class DeviceSession
    class ReadError < StandardError
      attr_reader :code

      # 只公开受控失败码，不将命令回显或底层异常带入业务日志。
      def initialize(failure)
        @code = failure.fetch(:code)
        super("Device collection did not complete (#{code})")
      end
    end
  end
end
