# frozen_string_literal: true

require_relative "../error"

module Algosec
  module Policy
    class Analysis
      # 无法证明的语义与检查失败不同，调用者必须保留未知状态。
      class Unknown < Error; end
    end
  end
end
