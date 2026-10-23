# frozen_string_literal: true

require_relative "../traffic_set"

module Algosec
  module Policy
    class TrafficSet
      # 一个区域内每维可以包含多个不连续区间，各维集合保持不可变。
      class Region
        attr_reader :family
        attr_reader(*DIMENSIONS)

        def initialize(family:, source_addresses:, destination_addresses:, protocols:, source_ports:, destination_ports:)
          @family = family.is_a?(String) ? family.to_sym : family
          raise ArgumentError, "Region family must be ipv4 or ipv6" unless %i[ipv4 ipv6].include?(@family)
          @source_addresses = dimension(source_addresses, address_maximum)
          @destination_addresses = dimension(destination_addresses, address_maximum)
          @protocols = dimension(protocols, 255)
          @source_ports = dimension(source_ports, 65_535)
          @destination_ports = dimension(destination_ports, 65_535)
          @hash = [ @family, *DIMENSIONS.map { |name| public_send(name) } ].hash
          freeze
        end

        def empty? = DIMENSIONS.any? { |name| public_send(name).empty? }
        def ==(other) = other.is_a?(Region) && family == other.family && DIMENSIONS.all? { |name| public_send(name) == other.public_send(name) }
        alias_method :eql?, :==
        attr_reader :hash

        def intersection(other, budget:)
          return unless family == other.family
          dimensions = {}
          DIMENSIONS.each do |name|
            values = budget.intersection(public_send(name), other.public_send(name))
            return if values.empty?
            dimensions[name] = values
          end
          self.class.new(family:, **dimensions)
        end

        # 先固定交集前缀，再沿每一维切出不属于交集的部分。
        def subtract(other, budget:)
          return enum_for(__method__, other, budget:) unless block_given?
          shared = intersection(other, budget:)
          unless shared
            yield self
            return
          end
          remaining = DIMENSIONS.to_h { |name| [ name, public_send(name) ] }
          DIMENSIONS.each do |name|
            outside = budget.difference(remaining.fetch(name), shared.public_send(name))
            yield self.class.new(family:, **remaining.merge(name => outside)) unless outside.empty?
            remaining[name] = shared.public_send(name)
          end
        end

        private

        def address_maximum = family == :ipv4 ? ::IPAddr::IN4MASK : ::IPAddr::IN6MASK

        def dimension(value, maximum)
          unless value.is_a?(Algosec::Set) && (value.empty? || value.max <= maximum)
            raise ArgumentError, "Region dimension must be an Algosec::Set in 0..#{maximum}"
          end
          value
        end
      end
    end
  end
end
