# frozen_string_literal: true

module Algosec
  module Elements
    # 配置命名空间是不可变值；未被配置证明的维度保留 nil。
    class Scope < Data.define(:device_id, :virtual_system, :rulebase, :address_book, :zone)
      def initialize(device_id: nil, virtual_system: nil, rulebase: nil, address_book: nil, zone: nil)
        unless device_id.nil? || device_id.is_a?(Integer) || (device_id.is_a?(String) && /\A[0-9]+\z/.match?(device_id))
          raise ArgumentError, "Device ID must be a nonnegative integer"
        end
        device_id = Integer(device_id, 10) if device_id.is_a?(String)
        raise ArgumentError, "Device ID must be nonnegative" if device_id&.negative?
        values = [ virtual_system, rulebase, address_book, zone ].map do |value|
          unless value.nil? || value.is_a?(String) || value.is_a?(Symbol)
            raise ArgumentError, "Scope names must be text"
          end
          value&.to_s&.dup&.freeze
        end
        super(device_id: device_id, virtual_system: values[0], rulebase: values[1], address_book: values[2], zone: values[3])
      end
    end
  end
end
