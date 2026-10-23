# frozen_string_literal: true

require_relative "../ranges"
require_relative "../traffic_set"

module Algosec
  module Policy
    module Nat
      # 原始/转换服务的精确编码集合对；数值协议 0 与通配服务文本分别处理。
      class ServiceQuery
        Pair = Data.define(:original, :translated) do
          def initialize(original:, translated:)
            unless [ original, translated ].all? { |value| value.is_a?(Set) && !value.empty? && value.max <= IPAddr::SERVICE_MAX }
              raise ArgumentError, "NAT service pairs require nonempty encoded service sets"
            end
            protocols = [ original, translated ].map { |set| Set.new(*set.map { |range| (range.begin >> 16)..(range.end >> 16) }) }
            raise ArgumentError, "NAT service translation must preserve protocols" unless protocols.first == protocols.last
            super
          end

          # 保持请求声明的身份、常量和逐协议偏移；不把缩小后的原始端口配到整段目标。
          def translated_subset(before)
            return before if original == translated
            protocols = Set.new(*before.map { |range| (range.begin >> 16)..(range.end >> 16) })
            ranges = protocols.flat_map do |range|
              range.flat_map do |protocol|
                band = Set.new((protocol << 16)..((protocol << 16) + IPAddr::PORT_MAX))
                source, target, selected = [ original, translated, before ].map { |set| set & band }
                offset = target.min - source.min
                shifted = Set.new(*source.map { |ports| (ports.begin + offset)..(ports.end + offset) })
                if shifted == target
                  selected.map { |ports| (ports.begin + offset)..(ports.end + offset) }
                else
                  target.ranges
                end
              end
            end
            Set.new(*ranges)
          end
        end

        attr_reader :pairs

        def initialize(pairs:)
          unless pairs.is_a?(Array) && pairs.any? && pairs.size <= TrafficSet::DEFAULT_LIMIT
            raise ArgumentError, "NAT service query requires a bounded nonempty pair list"
          end
          intervals = 0
          @pairs = pairs.map do |value|
            raise ArgumentError, "NAT service pair requires two sets" unless value.is_a?(Array) && value.size == 2
            pair = Pair.new(original: value.first, translated: value.last)
            intervals += pair.original.size + pair.translated.size
            if intervals > TrafficSet::DEFAULT_LIMIT
              raise TrafficSet::LimitExceeded, "NAT service pair exceeds interval budget"
            end
            pair
          end.freeze
          freeze
        end

        def self.coerce(services)
          return services if services.is_a?(self)
          unless services.nil? || (services.is_a?(Hash) && services.size <= TrafficSet::DEFAULT_LIMIT)
            raise ArgumentError, "NAT services require a bounded service mapping or ServiceQuery"
          end
          pairs = (services || {}).map do |name, entry|
            normalized = Ranges.normalize_service(name)
            original = Ranges.service(Ranges.normalize_service(entry.fetch(:origin, name)))
            translated = Ranges.service(Ranges.normalize_service(entry[:translated_port] ? "#{normalized.split('/').first}/#{entry[:translated_port]}" : normalized))
            [ original, translated ]
          end
          pairs = [ [ IPAddr.service("any"), IPAddr.service("any") ] ] if pairs.empty?
          new(pairs: pairs)
        end

        def empty? = false
        def translation? = pairs.any? { |pair| pair.original != pair.translated }
        def original_set = Set.new(*pairs.flat_map { |pair| pair.original.ranges })

        # 原始编码在协议边界处分段，安全链选择和 NAT 效果证明使用同一五元组集合。
        def traffic(sources:, destinations:, source_port: nil)
          regions = original_set.flat_map do |range|
            first, last = range.begin >> 16, range.end >> 16
            low, high = range.begin & 65_535, range.end & 65_535
            bands = if first == last
              [ [ first..last, low..high ] ]
            else
              [ [ first..first, low..65_535 ], [ (first + 1)..(last - 1), 0..65_535 ], [ last..last, 0..high ] ]
            end
            bands.filter_map do |protocols, ports|
              next if protocols.begin > protocols.end
              TrafficSet::Region.new(family: :ipv4, source_addresses: sources, destination_addresses: destinations,
                protocols: Set.new(protocols), source_ports: source_port ? IPAddr.ports(source_port.to_s) : Ranges::ANY_PORTS,
                destination_ports: Set.new(ports))
            end
          end
          TrafficSet.new(regions)
        end

        # 缩小原始服务时同时缩小确定的目标关系，保留协议、孔洞和端口偏移。
        def restrict(original)
          narrowed = pairs.filter_map do |pair|
            before = pair.original & original
            next if before.empty?
            [ before, pair.translated_subset(before) ]
          end
          self.class.new(pairs: narrowed)
        end

        def to_h
          { pairs: pairs.map { |pair| { original: pair.original.map { |range| [ range.begin, range.end ] }, translated: pair.translated.map { |range| [ range.begin, range.end ] } } } }
        end
      end
    end
  end
end
