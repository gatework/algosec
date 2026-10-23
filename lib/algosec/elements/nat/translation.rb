# frozen_string_literal: true

require_relative "../nat_pool"

module Algosec
  module Elements
    module Nat
      # 转换目标是可能地址范围；动态模式并不承诺实际会话分配。
      class Translation
        MODES = [ nil, :none, :unknown ].freeze
        attr_reader :mode, :native_mode, :addresses, :pool, :port, :services, :service, :mappings, :interface

        def initialize(mode:, native_mode: nil, addresses: nil, pool: nil, port: nil,
                       services: nil, service: nil, mappings: nil, interface: nil)
          raise ArgumentError, "Unknown translation mode: #{mode.inspect}" unless self.class::MODES.include?(mode)
          [ addresses, services ].each do |set|
            raise ArgumentError, "Translation ranges must be Sets" unless set.nil? || set.is_a?(Set)
          end
          raise ArgumentError, "Translation pool must be a NatPool" unless pool.nil? || pool.is_a?(NatPool)
          @mode, @native_mode = mode, native_mode&.to_s&.dup&.freeze
          @interface = interface&.to_s&.dup&.freeze
          @addresses, @pool, @services, @service = addresses, pool, services, service
          @port = port&.to_s&.dup&.freeze
          IPAddr.ports(@port) if @port
          # 映射由 StaticNat 校验并冻结，原始顺序不能经集合排序重建。
          if mappings && !(mappings.is_a?(Array) && mappings.frozen? && mappings.all? do |pair|
            pair.is_a?(Array) && pair.frozen? && pair.size == 2 && pair.all? { |range| range.is_a?(Range) && range.begin.is_a?(Integer) && range.end.is_a?(Integer) }
          end)
            raise ArgumentError, "Translation mappings must be immutable pairs"
          end
          @mappings = mappings
          freeze
        end

        def to_h
          { mode: mode, native_mode: native_mode, addresses: addresses, pool: pool, port: port,
            services: services, service: service, mappings: mappings, interface: interface }
        end

        def known? = !mode.nil? && mode != :unknown

        # 地址查询可返回已知的可能范围；未识别的原生命令即使带地址也不能通过。
        def address_targets_known?
          targets && !targets.empty? && (known? || (mode.nil? && native_mode.nil?)) ? true : false
        end
        def identity? = mode == :none
        def targets = addresses || pool&.set
      end
    end
  end
end
