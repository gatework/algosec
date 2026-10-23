# frozen_string_literal: true

module Algosec
  module Config
    # 受控导出省略的原始文本必须显式附加后才能读取。
    class SourceUnavailable < StandardError; end
  end
end
