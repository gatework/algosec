# frozen_string_literal: true

require "digest"
require "json"
require_relative "../config/source_unavailable"

module Algosec
  module Elements
    # 未支持命令的存在本身影响匹配；正文可独立缺失，不能伪装为空数组。
    module UnparsedCommands
      attr_reader :unparsed_commands_metadata

      def unparsed_commands? = unparsed_commands_metadata.fetch("count").positive?
      def unparsed_commands_available? = !@unparsed_commands.nil?

      def unparsed_commands
        raise Config::SourceUnavailable, "Unsupported command text is unavailable" unless unparsed_commands_available?
        @unparsed_commands
      end

      private

      def initialize_unparsed_commands(commands, declared:, metadata: nil)
        raise ArgumentError, "Invalid unsupported-command evidence" unless metadata.nil? || metadata.is_a?(Hash)
        if commands
          unless commands.is_a?(Array) && commands.all? { |command| command.is_a?(String) }
            raise ArgumentError, "Unsupported commands must be a text array"
          end
          commands = commands.map { |command| command.dup.freeze }.freeze
        end
        if metadata
          unless metadata.is_a?(Hash) && metadata.keys.sort == %w[count declared sha256] &&
                 [ true, false ].include?(metadata["declared"]) && metadata["count"].is_a?(Integer) && metadata["count"] >= 0 &&
                 metadata["sha256"].is_a?(String) && /\A[0-9a-f]{64}\z/.match?(metadata["sha256"])
            raise ArgumentError, "Invalid unsupported-command evidence"
          end
          raise ArgumentError, "Undeclared commands cannot be nonempty" if !metadata["declared"] && metadata["count"].positive?
          commands = [].freeze if commands.nil? && metadata["count"].zero?
          if commands && (commands.size != metadata["count"] || Digest::SHA256.hexdigest(JSON.generate(commands)) != metadata["sha256"])
            raise ArgumentError, "Unsupported command details do not match evidence"
          end
          declared = metadata.fetch("declared")
        else
          raise ArgumentError, "Missing unsupported-command evidence" unless commands
          metadata = { "declared" => declared, "count" => commands.size, "sha256" => Digest::SHA256.hexdigest(JSON.generate(commands)) }
        end
        @unparsed_commands = commands
        @unparsed_commands_metadata = { "declared" => declared, "count" => metadata.fetch("count"), "sha256" => metadata.fetch("sha256").dup.freeze }.freeze
      end
    end
  end
end
