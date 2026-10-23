# frozen_string_literal: true

require "active_support/time"
require_relative "base"
require_relative "unparsed_commands"

module Algosec
  module Elements
    # 表示一次性或每周重复的时间窗口，并统一在指定时区内计算。
    class Schedule < Base
      include UnparsedCommands

      ELEMENT_TYPE = :schedule
      WEEKDAYS = %w[sun mon tue wed thu fri sat].freeze
      WEEKDAY_NAMES = %w[sunday monday tuesday wednesday thursday friday saturday].each_with_index.each_with_object({}) do |(name, index), names|
        names[name] = names[WEEKDAYS.fetch(index)] = [ index ].freeze
      end.freeze
      DAYS = {
        "daily" => (0..6).to_a.freeze, "weekdays" => (1..5).to_a.freeze,
        "working-day" => (1..5).to_a.freeze, "weekend" => [ 0, 6 ].freeze,
        "off-day" => [ 0, 6 ].freeze
      }.freeze
      attr_reader :reference_time, :kind, :start_at, :end_at, :time_zone, :window, :weekly_windows, :monthly_periods

      # 解析时间和周期定义，建立一次性窗口或按星期索引的分钟窗口。
      def initialize(name:, kind: :once, start_at: nil, end_at: nil, days: nil, periods: [],
                     monthly_periods: [], time_zone: Time.zone || "UTC", reference_time: Time.current, unparsed_commands: [], unparsed_commands_metadata: nil, **context)
        commands = unparsed_commands.nil? && unparsed_commands_metadata ? nil : Array(unparsed_commands).map { |command| text(command) }
        initialize_unparsed_commands(commands, declared: true, metadata: unparsed_commands_metadata)
        raise ArgumentError, "Schedule command declaration is required" unless self.unparsed_commands_metadata.fetch("declared")
        @kind = symbol(kind, label: "Schedule kind")
        raise ArgumentError, "Schedule kind must be once, weekly, monthly, periodic or mixed" unless %i[once weekly monthly periodic mixed].include?(@kind)
        @time_zone = Time.find_zone!(time_zone)
        @reference_time = instant(reference_time)
        super(name: name, **context)
        @start_at = start_at.nil? ? nil : parse_time(start_at).freeze
        @end_at = end_at.nil? ? nil : parse_time(end_at).freeze
        @monthly_periods = normalize_monthly_periods(monthly_periods)
        @window = nil
        @weekly_windows = {}.freeze
        if @kind == :once
          element_definition.validate_schedule(@start_at, @end_at)
          complete = @end_at && (@start_at || !element_definition.schedule_requires_start?)
          @window = ((@start_at&.to_i || 0)..@end_at.to_i) if complete
        else
          @weekly_windows = weekly(days, periods)
        end
      end

      # 判断给定时刻是否落在一次性或每周窗口内。
      def active?(at: Time.current)
        raise ArgumentError, "Schedule requires complete timing semantics" unless resolved?
        time = instant(at)
        return window.cover?(time.to_r) if window
        return false if kind == :mixed && ((start_at && time < start_at) || (end_at && time > end_at))
        minute = time.hour * 60 + time.min
        weekly_windows.fetch(time.wday, []).any? { |period| period.cover?(minute) } || monthly_active?(time)
      end

      # 判断一次性窗口是否已过期；重复计划没有过期状态。
      def expired?(at: Time.current) = !!(resolved? && end_at && instant(at) > end_at)

      def resolved?
        return false if unparsed_commands?
        return !window.nil? if kind == :once
        return element_definition.mixed_schedules? && (weekly_windows.any? || monthly_periods.any?) if kind == :mixed
        true
      end

      # 返回用于报告和设备差异比较的结束时间文本。
      def end_text = end_at&.strftime("%Y-%m-%d %H:%M")

      # 厂商日期语法由定义层负责，时区统一交给 ActiveSupport。
      def parse_time(value)
        return instant(value) unless value.is_a?(String)
        parts = element_definition.schedule_components(value, reference_time: @reference_time)
        unless parts && !parts.key?(:leftover) && Date.valid_date?(*parts.values_at(:year, :mon, :mday)) &&
               parts.fetch(:hour, 0).between?(0, 23) && parts.fetch(:min, 0).between?(0, 59) && parts.fetch(:sec, 0).between?(0, 59)
          raise ArgumentError, "Invalid #{vendor} date: #{value}"
        end
        time_zone.local(*parts.values_at(:year, :mon, :mday), parts.fetch(:hour, 0), parts.fetch(:min, 0), parts.fetch(:sec, 0))
      end

      private

      # 月内不存在的日期不产生周期；不把 31 日自动滚动到下个月。
      def monthly_active?(time)
        monthly_periods.any? do |period|
          first, last = period.values_at("start_day", "end_day")
          next false unless [ first, last ].all? { |day| Date.valid_date?(time.year, time.month, day) }
          start_time = time_zone.local(time.year, time.month, first, *period.fetch("start_time").split(":").map(&:to_i))
          end_time = time_zone.local(time.year, time.month, last, *period.fetch("end_time").split(":").map(&:to_i))
          time >= start_time && time < end_time
        end
      end

      def normalize_monthly_periods(periods)
        raise ArgumentError, "Monthly periods must be an array" unless periods.is_a?(Array)
        periods.map do |raw|
          raise ArgumentError, "Monthly period must be an object" unless raw.is_a?(Hash)
          period = raw.transform_keys(&:to_s)
          raise ArgumentError, "Invalid monthly period fields" unless period.keys.sort == %w[end_day end_time start_day start_time]
          days = period.values_at("start_day", "end_day")
          unless days.all? { |day| day.is_a?(Integer) && day.between?(1, 31) } && days.first <= days.last
            raise ArgumentError, "Invalid monthly day range"
          end
          clocks = %w[start_time end_time].map do |key|
            value = period.fetch(key)
            raise ArgumentError, "Invalid monthly clock" unless value.is_a?(String) && value.match?(/\A(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d\z/)
            value.split(":").map(&:to_i).then { |h, m, s| h * 3600 + m * 60 + s }
          end
          if days.first == days.last && clocks.first >= clocks.last
            raise ArgumentError, "Monthly period must have a positive duration"
          end
          period.transform_values { |value| value.is_a?(String) ? value.dup.freeze : value }.freeze
        end.freeze
      end

      # 将时间对象或 Unix 时间戳转换到计划时区。
      def instant(value)
        case value
        when Integer, Float then time_zone.at(value)
        when Time, ActiveSupport::TimeWithZone then value.in_time_zone(time_zone)
        else raise ArgumentError, "Expected a time or Unix timestamp"
        end
      end

      # 把星期和时段展开为星期索引到分钟区间的映射。
      def weekly(days, periods)
        if periods.is_a?(Hash)
          raise ArgumentError, "Supply days or a weekday-to-periods mapping" unless days.nil?
          return periods.each_with_object({}) do |(day, windows), result|
            weekly(day, windows).each { |index, ranges| result[index] = (result.fetch(index, []) + ranges).freeze }
          end.freeze
        end
        raise ArgumentError, "Periods must be pairs of clock times" unless periods.is_a?(Array)
        return {}.freeze if days.nil? || periods.empty?
        selected = Array(days).flat_map { |day| text(day).split(/[\s,]+/) }.flat_map do |day|
          normalized = day.downcase
          DAYS[normalized] || WEEKDAY_NAMES.fetch(normalized) { raise ArgumentError, "Unknown weekday: #{day}" }
        end.uniq
        ranges = periods.map do |period|
          raise ArgumentError, "A period needs start and end" unless period.is_a?(Array) && period.size == 2
          first, last = period.map { |clock| minute_of_day(clock) }
          (first..last) # A reversed clock range does not implicitly cross midnight.
        end.freeze
        selected.to_h { |day| [ day, ranges ] }.freeze
      end

      # 将时钟文本转换为当天起始后的分钟数。
      def minute_of_day(value)
        match = /\A([0-9]{1,2}):([0-9]{1,2})\z/.match(text(value))
        unless match && match[1].to_i.between?(0, 23) && match[2].to_i.between?(0, 59)
          raise ArgumentError, "Invalid clock time: #{value}"
        end
        match[1].to_i * 60 + match[2].to_i
      end
    end
  end
end
