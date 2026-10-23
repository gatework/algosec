# frozen_string_literal: true

module Algosec
  module Policy
    # 转换等其他领域的证明扩展点。子类须运行自己的算法，不能把布尔回执当作证明器。
    class EffectProof
      def change_set = nil
      def generation? = false
      def effect = raise NotImplementedError
      def baseline = raise NotImplementedError
      def verified? = raise NotImplementedError
      def to_h = raise NotImplementedError
      def verify_readback(snapshot) = raise NotImplementedError
    end
  end
end
