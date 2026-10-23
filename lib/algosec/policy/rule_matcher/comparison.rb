# frozen_string_literal: true

require_relative "../ranges"

module Algosec
  module Policy
    class RuleMatcher
      # 一条候选规则持有自己的范围比较和成员差异，供匹配器选择复用或修改。
      class Comparison
        Changes = Data.define(:additions, :existing) do
          # 返回所有新增维度成员的总数，用于稳定选择最小修改方案。
          def size = additions.values.sum(&:size)
        end
        private_constant :Changes

        attr_reader :rule, :signature

        # 计算规则当前投影与请求范围的包含关系。
        def initialize(rule, snapshot:, maps:, ranges:)
          @rule, @request_maps, @signature = rule, maps, snapshot.signature(rule)
          @current_ranges = Ranges.projection(rule)
          @relations = @current_ranges.to_h { |dimension, set| [ dimension, set.relation(ranges.fetch(dimension)) ] }
        end

        # 判断当前规则能否完整覆盖请求及其时间窗口。
        def covers?(schedule:)
          @relations.values.all? { |state| %i[equal contains].include?(state) } && schedule_covers?(schedule)
        end

        # 判断当前规则能否通过只追加成员来满足请求。
        def extendable?
          rule.starts_at.nil? && rule.expires_at.nil? && rule.schedule.nil? && (@relations.values.all? { |state| %i[equal within].include?(state) } || @relations.values.count(:equal) == 2)
        end

        # 以新增成员数量和规则签名构成稳定排序键。
        def rank = [ changes.size, signature ]

        # 计算请求成员相对当前规则的新增项和已有项文本。
        def changes
          @changes ||= begin
                         additions, existing = {}, {}
                         @request_maps.each do |dimension, entries|
                           added_entries, existing_entries = entries.partition do |value, _entry|
                             requested_range = (dimension == :services) ? Ranges.service(value) : IPAddr.parse(value)
                             !@current_ranges.fetch(dimension).cover?(requested_range)
                           end
                           additions[dimension] = added_entries.to_h unless added_entries.empty?
                           existing[dimension] = existing_entries.map(&:first).sort.join(",")
                         end
                         Changes.new(additions, existing)
                       end
        end

        private

        # 判断当前规则时间窗口是否覆盖请求时间窗口。
        def schedule_covers?(requested)
          if rule.starts_at
            return false unless requested&.window && rule.starts_at.to_f <= requested.window.begin
          end
          if rule.expires_at
            return false unless requested&.window && rule.expires_at.to_f >= requested.window.end
          end
          return true unless rule.schedule
          return false unless requested && rule.schedule.resolved? && rule.schedule.kind == :once && rule.schedule.window

          window = rule.schedule.window
          window.begin <= requested.window.begin && window.end >= requested.window.end
        end
      end

      private_constant :Comparison
    end
  end
end
