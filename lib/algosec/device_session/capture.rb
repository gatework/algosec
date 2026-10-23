# frozen_string_literal: true

require "digest"
require "ctx_parser"

module Algosec
  class DeviceSession
    # 正文、服务定义和安全证据分别发布，元数据不包含设备正文。
    class Capture
      attr_reader :content, :builtin_services, :truncated_services, :evidence

      def initialize(content:, builtin_services: nil, truncated_services: [], evidence: [])
        @content = CtxParser::Input.text(content, encoding: :transcode).freeze
        @builtin_services = builtin_services&.dup&.freeze
        @truncated_services = CtxParser::Immutable.copy(truncated_services)
        @evidence = CtxParser::Immutable.copy(evidence)
        freeze
      end

      # 元数据可用于审计，设备正文只能通过 content 显式访问。
      def to_h
        { bytes: content.bytesize, sha256: Digest::SHA256.hexdigest(content), evidence: evidence,
          builtin_services: builtin_services&.size, truncated_services: truncated_services }
      end

      def as_json(*) = to_h
      def inspect = "#<#{self.class.name} bytes=#{content.bytesize} commands=#{evidence.size}>"
      alias to_s inspect
    end
  end
end
