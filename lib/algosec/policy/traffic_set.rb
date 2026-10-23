# frozen_string_literal: true

require_relative "../set"
require_relative "packet"

module Algosec
  module Policy
    # 地址族和五维矩形的精确并集；不能独立合并每个维度而扩大配对关系。
    class TrafficSet
      include Enumerable
      DEFAULT_LIMIT = 4096
      DIMENSIONS = %i[source_addresses destination_addresses protocols source_ports destination_ports].freeze
      class LimitExceeded < ArgumentError; end

      attr_reader :regions, :limit

      def initialize(regions = [], limit: DEFAULT_LIMIT)
        @budget = Budget.new(limit)
        @limit = limit
        raise ArgumentError, "Regions must be enumerable" unless regions.respond_to?(:each)
        normalized = []
        regions.each do |input|
          region = normalize(input)
          @budget.validate(region)
          next if region.empty?
          pending = [ region ]
          normalized.each do |existing|
            remaining = []
            pending.each do |candidate|
              candidate.subtract(existing, budget: @budget) do |piece|
                @budget.append(remaining, piece)
              end
            end
            pending = remaining
            break if pending.empty?
          end
          pending.each { |piece| @budget.append(normalized, piece) }
        end
        @regions = normalized.freeze
        freeze
      end

      # 全流量仍按地址族分开，供共同谓词投影和行为比较使用。
      def self.universe(limit: DEFAULT_LIMIT)
        new(%i[ipv4 ipv6].map do |family|
          maximum = family == :ipv4 ? ::IPAddr::IN4MASK : ::IPAddr::IN6MASK
          { family: family, source_addresses: Set.new(0..maximum), destination_addresses: Set.new(0..maximum),
            protocols: Set.new(0..255), source_ports: Set.new(0..65535), destination_ports: Set.new(0..65535) }
        end, limit: limit)
      end

      # 应用和用户由 Evaluation 隔离；数值集合显式拒绝丢弃这些上下文。
      def self.from_packet(packet, limit: DEFAULT_LIMIT)
        validate_packet!(packet)
        dimensions = packet_dimensions(packet).transform_values { |value| Algosec::Set.new(value..value) }
        new([ Region.new(family: packet.family, **dimensions) ], limit:)
      end

      def self.validate_packet!(packet)
        raise ArgumentError, "Expected a Packet" unless packet.is_a?(Packet)
        raise ArgumentError, "Contextual packets require evaluation context isolation" if packet.contextual?
      end

      def self.packet_dimensions(packet)
        {
          source_addresses: ::IPAddr.new(packet.source).to_i,
          destination_addresses: ::IPAddr.new(packet.destination).to_i,
          protocols: packet.protocol, source_ports: packet.source_port, destination_ports: packet.destination_port
        }
      end
      private_class_method :validate_packet!, :packet_dimensions

      def each(&block)
        return enum_for(__method__) unless block
        regions.each(&block)
        self
      end

      def empty? = regions.empty?

      def |(other)
        validate_operand!(other)
        self.class.new(each.chain(other.each), limit: [ limit, other.limit ].min)
      end

      def &(other)
        validate_operand!(other)
        budget = Budget.new([ limit, other.limit ].min)
        pieces = []
        each do |left|
          other.each do |right|
            shared = left.intersection(right, budget:)
            budget.append(pieces, shared) if shared
          end
        end
        self.class.new(pieces, limit: budget.limit)
      end

      def -(other)
        validate_operand!(other)
        budget = Budget.new([ limit, other.limit ].min)
        pending = regions
        other.each do |removed|
          remaining = []
          pending.each do |region|
            region.subtract(removed, budget:) { |piece| budget.append(remaining, piece) }
          end
          pending = remaining
          break if pending.empty?
        end
        self.class.new(pending, limit: budget.limit)
      end

      def cover?(other)
        validate_operand!(other)
        (other - self).empty?
      end

      def include?(packet)
        self.class.send(:validate_packet!, packet)
        dimensions = self.class.send(:packet_dimensions, packet)
        any? do |region|
          region.family == packet.family && dimensions.all? { |name, value| region.public_send(name).include?(value) }
        end
      end

      def witness
        region = regions.first
        return unless region
        family = region.family == :ipv4 ? Socket::AF_INET : Socket::AF_INET6
        Packet.new(
          source: ::IPAddr.new(region.source_addresses.min, family).to_s,
          destination: ::IPAddr.new(region.destination_addresses.min, family).to_s,
          protocol: region.protocols.min, source_port: region.source_ports.min, destination_port: region.destination_ports.min
        )
      end

      private

      def normalize(input)
        return input if input.is_a?(Region)
        raise ArgumentError, "Expected a Region or its field hash" unless input.is_a?(Hash)
        Region.new(**input)
      end

      def validate_operand!(other)
        raise ArgumentError, "Expected a TrafficSet" unless other.is_a?(TrafficSet)
      end
    end
  end
end

require_relative "traffic_set/budget"
require_relative "traffic_set/region"
