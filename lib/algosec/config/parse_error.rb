# frozen_string_literal: true

module Algosec
  module Config
    class ParseError < StandardError
      attr_reader :line_number

      # 保存出错行号，并把行号附加到对外错误信息。
      def initialize(message, line_number: nil)
        @line_number = line_number
        super(line_number ? "Line #{line_number}: #{message}" : message)
      end
    end
  end
end
