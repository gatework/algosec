# frozen_string_literal: true

require_relative "parse_error"

module Algosec
  module Config
    class IncompleteConfiguration < ParseError
      attr_reader :result

      # 携带带诊断信息的部分结果，供宽松解析调用方继续检查。
      def initialize(result)
        @result = result
        super("Configuration has #{result.diagnostics.size} diagnostics")
      end
    end
  end
end
