# frozen_string_literal: true

module Algosec
  module Policy
    class Error < StandardError
      attr_reader :code

      def initialize(message, code: :invalid_policy)
        @code = code
        super(message)
      end
    end
  end
end
