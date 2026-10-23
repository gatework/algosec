# frozen_string_literal: true

require_relative "../traffic_set"

module Algosec
  module Policy
    class TrafficSet
      # 在写入下一分段前检查预算，避免先展开超大结果再检查大小。
      class Budget
        attr_reader :limit

        def initialize(limit)
          raise ArgumentError, "Limit must be a positive integer" unless limit.is_a?(Integer) && limit.positive?
          @limit = limit
          freeze
        end

        def append(array, value)
          raise LimitExceeded, "Traffic set exceeds #{limit} regions or intervals" if array.size >= limit
          array << value
        end

        def validate(region)
          DIMENSIONS.each do |name|
            raise LimitExceeded, "#{name} exceeds #{limit} intervals" if region.public_send(name).size > limit
          end
        end

        def intersection(left, right)
          ranges = []
          first = second = 0
          while first < left.size && second < right.size
            a, b = left.ranges[first], right.ranges[second]
            low, high = [ a.begin, b.begin ].max, [ a.end, b.end ].min
            append(ranges, low..high) if low <= high
            first += 1 if a.end <= b.end
            second += 1 if b.end <= a.end
          end
          Algosec::Set.new(*ranges)
        end

        def difference(left, right)
          ranges = []
          index = 0
          left.each do |range|
            cursor = range.begin
            index += 1 while index < right.size && right.ranges[index].end < cursor
            scan = index
            while scan < right.size && right.ranges[scan].begin <= range.end
              removed = right.ranges[scan]
              append(ranges, cursor..removed.begin - 1) if removed.begin > cursor
              cursor = [ cursor, removed.end + 1 ].max
              break if cursor > range.end
              scan += 1
            end
            append(ranges, cursor..range.end) if cursor <= range.end
          end
          Algosec::Set.new(*ranges)
        end
      end
    end
  end
end
