# frozen_string_literal: true

require_relative "result"

module Algosec
  module Policy
    # 一次成功生成的命令及来源映射；不持有连接，也不执行设备操作。
    class Script
      Entry = Data.define(:result, :text, :references, :intents, :issues, :nat_evidence) do
        def initialize(result:, text:, references:, intents: [], issues: [], nat_evidence: [])
          super(result: result, text: text.dup.freeze, references: Value.immutable(references), intents: intents.dup.freeze, issues: issues.dup.freeze, nat_evidence: nat_evidence.dup.freeze)
        end
      end

      # 原生删除直接绑定被操作的快照规则，不伪造查询结果。
      OperationEntry = Data.define(:operation, :rule, :text, :intents, :issues) do
        def initialize(operation:, rule:, text:, intents:)
          super(operation: operation, rule: rule, text: text.dup.freeze, intents: intents.dup.freeze, issues: [].freeze)
        end
      end

      attr_reader :text, :entries

      def initialize(text:, entries:)
        @text, @entries = text.dup.freeze, entries.dup.freeze
        freeze
      end
    end
  end
end
