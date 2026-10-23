# frozen_string_literal: true

require "ipaddr"

module Algosec
  module Policy
    # 具体报文只接受主机与标量；协议零始终表示实际协议号零。
    class Packet
      ATTRIBUTES = %i[source destination protocol source_port destination_port application source_user].freeze
      attr_reader(*ATTRIBUTES, :family)

      def initialize(source:, destination:, protocol:, source_port:, destination_port:, application: nil, source_user: nil)
        source_ip = address(source)
        destination_ip = address(destination)
        raise ArgumentError, "Packet addresses must have the same family" unless source_ip.family == destination_ip.family
        @family = source_ip.ipv4? ? :ipv4 : :ipv6
        @source = source_ip.to_s.freeze
        @destination = destination_ip.to_s.freeze
        @protocol = integer(protocol, 255, "Protocol")
        @source_port = integer(source_port, 65_535, "Source port")
        @destination_port = integer(destination_port, 65_535, "Destination port")
        @application = context(application)
        @source_user = context(source_user)
        @hash = ATTRIBUTES.map { |name| public_send(name) }.hash
        freeze
      end

      def contextual? = !application.nil? || !source_user.nil?
      def ==(other) = other.is_a?(Packet) && ATTRIBUTES.all? { |name| public_send(name) == other.public_send(name) }
      alias_method :eql?, :==
      attr_reader :hash

      private

      def address(value)
        unless value.is_a?(String) && value == value.strip && !value.match?(/[\/%]/)
          raise ArgumentError, "Packet address must be a single unscoped host"
        end
        ::IPAddr.new(value)
      rescue ::IPAddr::Error => error
        raise ArgumentError, error.message
      end

      def integer(value, maximum, label)
        raise ArgumentError, "#{label} must be an integer in 0..#{maximum}" unless value.is_a?(Integer) && value.between?(0, maximum)
        value
      end

      def context(value)
        return if value.nil?
        raise ArgumentError, "Packet context must be nonempty text" unless value.is_a?(String) && !value.strip.empty?
        value.dup.freeze
      end
    end
  end
end
