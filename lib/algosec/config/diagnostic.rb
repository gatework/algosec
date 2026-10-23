# frozen_string_literal: true

require_relative "source_unavailable"

module Algosec
  module Config
    # 正文缺失与明确的 nil 不相同；来源摘要始终可以读取。
    class Diagnostic
      attr_reader :code, :line_number

      def initialize(code, message, line_number, message_present: !message.nil?)
        unless (code.is_a?(Symbol) || code.is_a?(String)) && !code.empty?
          raise ArgumentError, "Diagnostic code must be a nonempty name"
        end
        raise ArgumentError, "Diagnostic message must be text" unless message.nil? || message.is_a?(String)
        unless line_number.nil? || (line_number.is_a?(Integer) && line_number.positive?)
          raise ArgumentError, "Diagnostic line number must be a positive integer"
        end
        unless message_present == true || message_present == false
          raise ArgumentError, "Diagnostic message presence must be boolean"
        end
        raise ArgumentError, "Diagnostic message contradicts presence" if !message_present && !message.nil?
        @code = code.is_a?(String) ? code.dup.freeze : code
        @message, @line_number = message&.dup&.freeze, line_number
        @message_present = message_present
        freeze
      end

      def message_present? = @message_present
      def message_available? = !message_present? || !@message.nil?

      def message
        raise SourceUnavailable, "Diagnostic message is unavailable" unless message_available?
        @message
      end

      def cache_values = [ code, @message, line_number, message_present? ]
      def ==(other) = other.instance_of?(self.class) && cache_values == other.cache_values
      alias eql? ==
      def hash = cache_values.hash

      def to_h = { code: code, message: message, line_number: line_number }
      def as_json(*) = { code: code, line_number: line_number }
      def inspect = "#<#{self.class.name} code=#{code} line_number=#{line_number}>"
      alias to_s inspect
    end
  end
end
