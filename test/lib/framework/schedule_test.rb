# frozen_string_literal: true

require "minitest/autorun"
require "algosec"

class ScheduleTest < Minitest::Test
  E = Algosec::Elements

  def test_weekdays_accept_complete_short_and_full_names_without_case_sensitivity
    %w[sunday monday tuesday wednesday thursday friday saturday].each_with_index do |day, index|
      [ day, day[0, 3], day.upcase, day[0, 3].upcase ].each do |name|
        schedule = weekly(days: name)
        assert_equal({ index => [ 540..600 ] }, schedule.weekly_windows, name)
      end
    end
  end

  def test_weekday_groups_and_separated_names_keep_their_meaning
    { "daily" => (0..6).to_a, "weekdays" => (1..5).to_a, "working-day" => (1..5).to_a,
      "weekend" => [ 0, 6 ], "off-day" => [ 0, 6 ], "MON, wednesday FRIDAY" => [ 1, 3, 5 ] }.each do |name, days|
      assert_equal days, weekly(days: name).weekly_windows.keys.sort, name
    end
    assert_equal({ 1 => [ 540..600 ], 5 => [ 660..720 ] },
                 E::Schedule.new(name: "mapped", kind: :weekly, periods: { "MONDAY" => [ [ "09:00", "10:00" ] ],
                                                                          "fri" => [ [ "11:00", "12:00" ] ] }).weekly_windows)
  end

  def test_weekdays_reject_arbitrary_prefix_matches
    %w[monkey sunday-extra tuesdayx wed123 thursday? friday! saturdayish].each do |day|
      error = assert_raises(ArgumentError, day) { weekly(days: day) }
      assert_equal "Unknown weekday: #{day}", error.message
    end
  end

  def test_fortinet_strict_parser_rejects_unknown_weekdays_with_source_context
    error = assert_raises(Algosec::Config::ParseError) do
      Algosec::Config::Parser.perform(<<~CONFIG, vendor: :fortinet, strict: true)
        config firewall schedule recurring
         edit office
          set day monkey
          set start 09:00
          set end 10:00
         next
        end
      CONFIG
    end
    assert_equal 2, error.line_number
    assert_match(/Unknown weekday: monkey/, error.message)
  end

  def test_empty_and_reversed_weekly_windows_remain_inactive
    [ E::Schedule.new(name: "empty", kind: :weekly),
      weekly(days: nil), weekly(days: "mon", periods: []),
      weekly(days: "mon", periods: [ [ "23:00", "01:00" ] ]) ].each do |schedule|
      assert schedule.resolved?
      refute schedule.active?(at: Time.utc(2026, 10, 12, 23, 30))
      refute schedule.active?(at: Time.utc(2026, 10, 13, 0, 30))
    end
  end

  def test_mixed_schedule_uses_the_explicit_definition_capability
    supported = Class.new(E::Definition) { defaults mixed_schedules?: true }
    schedule = E::Schedule.new(name: "mixed", kind: :mixed, vendor: :generic, definition: supported,
      start_at: "2026-10-12 09:30", end_at: "2026-10-12 10:30", days: "mon",
      periods: [ [ "09:00", "11:00" ] ], time_zone: "UTC")

    assert schedule.resolved?
    assert schedule.active?(at: Time.utc(2026, 10, 12, 10))
    refute schedule.active?(at: Time.utc(2026, 10, 12, 9))
    refute schedule.active?(at: Time.utc(2026, 10, 12, 11))
  end

  def test_mixed_schedule_rejects_disabled_capability_even_for_hillstone
    schedule = E::Schedule.new(name: "mixed", kind: :mixed, vendor: :hillstone, definition: E::Definition,
      days: "mon", periods: [ [ "09:00", "11:00" ] ], time_zone: "UTC")

    refute schedule.resolved?
    assert_raises(ArgumentError) { schedule.active?(at: Time.utc(2026, 10, 12, 10)) }
  end

  def test_hillstone_mixed_schedule_still_requires_parsed_periods
    [ { days: nil, periods: [] },
      { days: "mon", periods: [ [ "09:00", "11:00" ] ], unparsed_commands: [ "unknown" ] } ].each do |options|
      schedule = E::Schedule.new(name: "mixed", kind: :mixed, vendor: :hillstone, time_zone: "UTC", **options)

      refute schedule.resolved?
    end
  end

  def test_once_integer_inclusive_window_has_exact_boundaries_without_float_plateaus
    first, last = Time.utc(2030, 1, 1, 1), Time.utc(2030, 1, 1, 2)
    schedule = E::Schedule.new(name: "once", start_at: first, end_at: last, time_zone: "UTC")
    nanosecond = Rational(1, 1_000_000_000)
    assert schedule.active?(at: first)
    refute schedule.active?(at: first - nanosecond)
    assert schedule.active?(at: last)
    refute schedule.active?(at: last + nanosecond)
    fractional = E::Schedule.new(name: "fractional", start_at: first + nanosecond, end_at: last + nanosecond, time_zone: "UTC")
    assert_equal first.to_i..last.to_i, fractional.window
    assert fractional.active?(at: last)
    refute fractional.active?(at: last + nanosecond)
  end

  private

  def weekly(days:, periods: [ [ "09:00", "10:00" ] ])
    E::Schedule.new(name: "weekly", kind: :weekly, days: days, periods: periods, time_zone: "UTC")
  end
end
