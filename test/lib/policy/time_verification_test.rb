# frozen_string_literal: true

require "test_helper"
require_relative "../framework/support/policy_factory"
require_relative "../framework/support/policy_config"

class TimeVerificationTest < ActiveSupport::TestCase
  include PolicyFactory
  include PolicyConfig

  def instant = Time.utc(2030, 1, 1)

  def window(first = instant + 3600, last = instant + 7200, vendor: :palo_alto, **options)
    E::Schedule.new(**context(vendor), name: "window", start_at: first, end_at: last, time_zone: "UTC", **options)
  end

  def traffic
    P::TrafficSet.new([ { family: :ipv4, source_addresses: Algosec::IPAddr.parse("10.0.0.1"),
      destination_addresses: Algosec::IPAddr.parse("192.0.2.1"), protocols: Algosec::Set.new(6..6),
      source_ports: Algosec::Set.new(0..65535), destination_ports: Algosec::Set.new(443..443) } ])
  end

  def scheduled_change(schedule: window, requested: schedule, baseline: snapshot(:palo_alto), **attributes)
    entry = rule(:palo_alto, source: "10.0.0.1", schedule: schedule, rule_number: 10, **attributes)
    target = P::ChangeSet::Target.new(traffic_set: traffic, action: "allow", from_zone: "inside", to_zone: "outside", effective_window: requested)
    P::ChangeSet.new(snapshot: baseline, intents: [ P::ChangeSet::Intent.create(rule: entry, placement: :append) ], targets: [ target ], at: instant)
  end

  test "future once target is proved over both boundaries and all constant intervals" do
    change = scheduled_change
    assert change.verify.verified?, "fixed-time security must preserve baseline before the requested start"
    proof = P::TimeVerification.new(change_set: change)
    assert proof.verified?, proof.to_h.inspect
    assert_equal :time, proof.effect
    assert_equal change.baseline, proof.baseline
    assert_equal 6, proof.checks.size
    assert_equal [ instant, instant + 3600, instant + 7200 ], proof.checks.select { |check| check.kind == :boundary }.map(&:at)
    assert proof.checks.all? { |check| check.verification.verified? }
    assert JSON.parse(JSON.generate(proof.to_h)).fetch("verified")
    document = JSON.parse(JSON.generate(change.to_h))
    assert_equal change.at, Time.at(Rational(*document.fetch("at_epoch")))
    assert_equal [ instant.to_i + 3600, instant.to_i + 7200 ], document.fetch("targets").sole.fetch("effective_window").fetch("window")
    plan = P::Plan.new(operation: :configure, snapshot: change.snapshot, changes: [], change_set: change)
    refute plan.ready?, "fixed-time proof must never substitute for the required time proof"
    assert_includes plan.required_effects, :time
  end

  test "an earlier scheduled deny hidden at planning time is evaluated at its own boundaries" do
    deny_window = window(instant + 5400, instant + 6000)
    deny = rule(:palo_alto, name: "deny", source: "10.0.0.1", action: "deny", schedule: deny_window, rule_number: 1)
    change = scheduled_change(baseline: snapshot(:palo_alto, [ deny ]))
    proof = P::TimeVerification.new(change_set: change)
    refute proof.verified?
    assert proof.checks.any? { |check| check.at == instant + 5400 && !check.verification.verified? }
    assert proof.differences.any? { |difference| difference.kind == :target }
  end

  test "wider and shorter native windows fail including an inclusive end boundary" do
    requested = window
    [ window(instant + 3599, instant + 7200), window(instant + 3600, instant + 7201), window(instant + 3600, instant + 7199) ].each do |generated|
      proof = P::TimeVerification.new(change_set: scheduled_change(schedule: generated, requested: requested))
      refute proof.verified?, generated.window.inspect
    end
  end

  test "starts and expiry conditions split even subsecond time intervals" do
    change = scheduled_change(conditions: { starts_at: (instant + 3600.25).iso8601(2) })
    proof = P::TimeVerification.new(change_set: change)
    refute proof.verified?
    assert proof.checks.any? { |check| check.at.to_r == change.intents.sole.rule.starts_at.to_r }
    change = scheduled_change(conditions: { expires_at: (instant + 7199.75).iso8601(2) })
    proof = P::TimeVerification.new(change_set: change)
    refute proof.verified?
    assert proof.checks.any? { |check| check.at.to_r == change.intents.sole.rule.expires_at.to_r }
  end

  test "expired windows require a proof but their historical behavior is outside deployment horizon" do
    old_window = window(instant - 7200, instant - 3600)
    change = scheduled_change(schedule: old_window)
    assert_includes change.required_effects, :time
    assert P::TimeVerification.new(change_set: change).verified?
    original = rule(:palo_alto, source: "10.0.0.1", schedule: old_window, rule_number: 1)
    current = snapshot(:palo_alto, [ original ])
    removal = P::ChangeSet.new(snapshot: current, intents: [ P::ChangeSet::Intent.delete(rule_id: original.rule_id) ], targets: [], at: instant)
    assert P::TimeVerification.new(change_set: removal).verified?
  end

  test "independent readback reruns the finite partition and rejects changed window or logging outside target" do
    change = scheduled_change
    proof = P::TimeVerification.new(change_set: change)
    assert proof.verified?
    candidate = change.apply
    readback = snapshot(:palo_alto, candidate.rules.map(&:with))
    assert proof.verify_readback(readback).verified?
    widened = candidate.rules.map { |entry| entry.with(schedule: window(instant + 3599, instant + 7200)) }
    refute proof.verify_readback(snapshot(:palo_alto, widened)).verified?
    different = candidate.rules.map { |entry| entry.with(schedule: window(instant + 8000, instant + 9000)) }
    refute proof.verify_readback(snapshot(:palo_alto, different)).verified?
  end

  test "unsupported repeating and incomplete schedule domains never get a time receipt" do
    weekly = window(nil, nil, kind: :weekly, days: "daily", periods: [ [ "01:00", "02:00" ] ])
    incomplete = window(nil, nil)
    [ weekly, incomplete ].each do |schedule|
      proof = P::TimeVerification.new(change_set: scheduled_change(schedule: schedule))
      refute proof.verified?
      assert_equal :unsupported_time_proof, proof.issues.sole.evidence[:code]
    end
  end

  test "time partition budget fails closed before evaluating an unbounded number of segments" do
    original = scheduled_change
    change = P::ChangeSet.new(snapshot: original.snapshot, intents: original.intents, targets: original.targets, at: instant, proof_limit: 4)
    proof = P::TimeVerification.new(change_set: change)
    refute proof.verified?
    assert_equal :proof_budget_exceeded, proof.issues.sole.evidence[:code]
  end

  test "plans bind time proof to the exact approved change set and reject readback receipts" do
    change = scheduled_change
    other = P::ChangeSet.new(snapshot: change.snapshot, intents: [], targets: [], at: instant)
    unrelated = P::TimeVerification.new(change_set: other)
    assert unrelated.verified?
    assert_raises(ArgumentError) do
      P::Plan.new(operation: :configure, snapshot: change.snapshot, changes: [], change_set: change, effect_proofs: { time: unrelated })
    end
    proof = P::TimeVerification.new(change_set: change)
    plan = P::Plan.new(operation: :configure, snapshot: change.snapshot, changes: [], change_set: change, effect_proofs: { time: proof })
    assert plan.ready?
    assert plan.verify_readback(change.apply).verified?
    assert_raises(ArgumentError) do
      P::Plan.new(operation: :configure, snapshot: change.snapshot, changes: [], change_set: change, effect_proofs: { time: proof.verify_readback(change.apply) })
    end
  end

  test "changing a preexisting window or logging outside requested time is rejected" do
    original_window = window(instant + 3000, instant + 8000)
    original = rule(:palo_alto, source: "10.0.0.1", schedule: original_window, rule_number: 1, log_enabled: true)
    current = snapshot(:palo_alto, [ original ])
    target = P::ChangeSet::Target.new(traffic_set: traffic, action: "allow", from_zone: "inside", to_zone: "outside", effective_window: window)
    [ original.with(schedule: window), original.with(log_enabled: false) ].each do |replacement|
      change = P::ChangeSet.new(snapshot: current, intents: [ P::ChangeSet::Intent.modify(rule_id: original.rule_id, rule: replacement) ], targets: [ target ], at: instant)
      proof = P::TimeVerification.new(change_set: change)
      refute proof.verified?
      assert proof.differences.any? { |difference| difference.kind == :outside_target }
    end
  end

  test "native once renderers preserve explicit zone scope throughout future windows" do
    (VENDORS - [ :neteye ]).each do |vendor|
      settings = vendor == :h3c ? { policy_bindings: [ { name: "objects", from_zone: "inside", to_zone: "outside" } ] } : {}
      current = snapshot(vendor, settings: settings)
      if vendor == :asa
        zones = %w[inside outside].map do |name|
          interface = E::Interface.new(name: name, zone: name, **context(vendor))
          E::Zone.new(name: name, acl_name: "#{name}_acl", interfaces: [ interface ], **context(vendor))
        end
        current = current.with_catalog(E::Catalog.new(zones).seal!)
      end
      request = P::Request.new(sources: [ "10.0.0.1" ], destinations: [ "192.0.2.1" ], services: [ "tcp/443" ],
        schedule: { start_at: instant + 3600, end_at: instant + 7200, time_zone: "UTC" })
      result = P::RuleMatcher.new(current, at: instant).match(group(vendor), schedule: request.schedule)
      plan = P::Planner.new(P::Report.new(results: [ result ])).plans.sole
      if vendor == :asa
        refute plan.ready?
        refute plan.effect_proofs.fetch(:time).verified?
        assert plan.effect_proofs.fetch(:time).differences.any? { |difference| difference.kind == :outside_target }
        next
      end
      assert plan.ready?, "#{vendor}: #{plan.issues.map(&:message).join('; ')}"
      assert_same result.schedule, plan.change_set.targets.sole.effective_window
      assert result.schedule.sealed?
      assert_equal vendor, plan.proof.candidate.rules.sole.schedule.vendor
      refute_equal "request", plan.proof.candidate.rules.sole.schedule.name
      parsed = Algosec::Config::Parser.perform(saved_config(vendor, plan.script), vendor: vendor, device_id: 1)
      assert parsed.complete?, "#{vendor}: #{parsed.diagnostics.inspect}"
      # saved_config 为解析器补入原有区域/绑定；这些控制对象由原快照提供。
      declarations = parsed.catalog.reject { |element| element.is_a?(E::Zone) || element.is_a?(E::RuleBinding) }
      readback = current.with_catalog(E::Catalog.new(current.catalog.to_a + declarations).seal!)
      assert_equal readback.rules.sole.schedule.name, plan.proof.candidate.rules.sole.schedule.name
      check = plan.verify_readback(readback)
      assert check.verified?, "#{vendor}: #{check.issues.map(&:to_h).inspect}; differences=#{check.differences.size}"
    end
  end

  test "minute renderers reject seconds and fractional seconds instead of changing requested bounds" do
    %i[palo_alto huawei].each do |vendor|
      [ 1, 0.25 ].each do |offset|
        requested = window(instant + 3600 + offset, instant + 7200, vendor: vendor)
        result = P::RuleMatcher.new(snapshot(vendor), at: instant).match(group(vendor), schedule: requested)
        assert_raises(P::Error) { P::Planner.new(P::Report.new(results: [ result ])).plans }
      end
    end
  end

  test "unsupported native schedule rendering blocks the whole plan" do
    result = P::RuleMatcher.new(snapshot(:neteye), at: instant).match(group(:neteye), schedule: window(vendor: :neteye))
    assert_raises(P::Error) { P::Planner.new(P::Report.new(results: [ result ])).plans }
  end

  test "readback cannot introduce future timing to a plan with no time proof" do
    current = snapshot(:palo_alto)
    change = P::ChangeSet.new(snapshot: current, intents: [], targets: [], at: instant)
    plan = P::Plan.new(operation: :configure, snapshot: current, changes: [], change_set: change)
    assert plan.ready?
    unexpected = snapshot(:palo_alto, [ rule(:palo_alto, schedule: window, rule_number: 1) ])
    refute plan.verify_readback(unexpected).verified?
  end

  test "non UTC cross day native window roundtrips exact instants" do
    parsed = Algosec::Config::Parser.perform("", vendor: :palo_alto, device_id: 1, time_zone: "Asia/Hong_Kong")
    current = P::Snapshot.from_config(parsed)
    requested = window(Time.utc(2030, 1, 1, 15), Time.utc(2030, 1, 1, 17))
    result = P::RuleMatcher.new(current, at: instant).match(group(:palo_alto), schedule: requested)
    plan = P::Planner.new(P::Report.new(results: [ result ])).plans.sole
    assert plan.ready?, plan.issues.map(&:message).inspect
    assert_includes plan.script, "2030/01/01@23:00-2030/01/02@01:00"
    parsed = Algosec::Config::Parser.perform(saved_config(:palo_alto, plan.script), vendor: :palo_alto, device_id: 1, time_zone: "Asia/Hong_Kong")
    readback = P::Snapshot.from_config(parsed)
    assert plan.verify_readback(readback).verified?
    assert_equal requested.window, readback.rules.sole.schedule.window
  end

  test "ambiguous DST local bounds are rejected when native schedule has no UTC offset" do
    parsed = Algosec::Config::Parser.perform("", vendor: :palo_alto, device_id: 1, time_zone: "America/New_York")
    current = P::Snapshot.from_config(parsed)
    requested = window(Time.utc(2030, 11, 3, 5, 30), Time.utc(2030, 11, 3, 8))
    result = P::RuleMatcher.new(current, at: instant).match(group(:palo_alto), schedule: requested)
    assert_raises(P::Error) { P::Planner.new(P::Report.new(results: [ result ])).plans }
  end

  test "unrelated weekly zones addresses and protocols do not block once time proof" do
    weekly = window(nil, nil, kind: :weekly, days: "daily", periods: [ [ "01:00", "02:00" ] ])
    [ { from_zones: "other", to_zones: "elsewhere" }, { source: "10.99.0.1" }, { services: [ "udp/443" ] } ].each do |attributes|
      unrelated = rule(:palo_alto, name: "weekly", schedule: weekly, rule_number: 1, **attributes)
      current = snapshot(:palo_alto, [ unrelated ])
      [ window, nil ].each do |requested|
        change = scheduled_change(baseline: current, schedule: requested)
        proof = P::TimeVerification.new(change_set: change)
        assert proof.verified?, "#{attributes.inspect}: #{proof.issues.map(&:to_h).inspect}"
      end
    end
  end

  test "overlapping weekly schedule is not pruned merely because inactive now" do
    weekly = window(nil, nil, kind: :weekly, days: "daily", periods: [ [ "01:00", "02:00" ] ])
    deny = rule(:palo_alto, name: "weekly", action: "deny", schedule: weekly, rule_number: 1)
    change = scheduled_change(baseline: snapshot(:palo_alto, [ deny ]))
    proof = P::TimeVerification.new(change_set: change)
    refute proof.verified?
    assert_equal :unsupported_time_proof, proof.issues.sole.evidence[:code]
  end

  test "unknown command predicates cannot become falsely disjoint during time projection" do
    weekly = window(nil, nil, kind: :weekly, days: "daily", periods: [ [ "01:00", "02:00" ] ])
    unknown = rule(:palo_alto, name: "weekly", source: "10.99.0.1", schedule: weekly, rule_number: 1, conditions: { unparsed_commands: [ "unknown selector" ] })
    proof = P::TimeVerification.new(change_set: scheduled_change(baseline: snapshot(:palo_alto, [ unknown ])))
    refute proof.verified?
    assert_equal :unsupported_time_proof, proof.issues.sole.evidence[:code]
  end

  test "ordinary inclusive end agrees between target rule and fixed-time proof inside one Float bucket" do
    change = scheduled_change
    ending = change.targets.sole.effective_window.end_at
    probe = ending + Rational(1, 1_000_000_000)
    assert_equal ending.to_f, probe.to_f
    assert P::TimeVerification.new(change_set: change).verified?
    refute change.targets.sole.active?(at: probe)
    refute change.intents.sole.rule.active?(at: probe)
    assert change.verify(at: probe).verified?
  end

  test "fractional raw once ends retain integer window equivalence for untargeted changes" do
    ending = instant + 7200
    original = rule(:palo_alto, schedule: window, rule_number: 1)
    replacement = original.with(schedule: window(instant + 3600, ending + Rational(1, 10_000_000)))
    change = P::ChangeSet.new(snapshot: snapshot(:palo_alto, [ original ]),
      intents: [ P::ChangeSet::Intent.modify(rule_id: original.rule_id, rule: replacement) ], targets: [], at: instant)
    probe = ending + Rational(1, 1_000_000_000)
    refute original.active?(at: probe)
    refute replacement.active?(at: probe)
    proof = P::TimeVerification.new(change_set: change)
    assert proof.verified?, proof.issues.map(&:to_h).inspect
    assert change.verify(at: probe).verified?
    assert proof.verify_readback(change.apply).verified?
  end

  test "exact condition extensions inside one Float bucket are partitioned and rejected without targets" do
    ending = instant + 7200
    original = rule(:palo_alto, rule_number: 1, conditions: { expires_at: ending.iso8601(9) })
    replacement = original.with(conditions: { expires_at: (ending + Rational(1, 10_000_000)).iso8601(9) })
    change = P::ChangeSet.new(snapshot: snapshot(:palo_alto, [ original ]),
      intents: [ P::ChangeSet::Intent.modify(rule_id: original.rule_id, rule: replacement) ], targets: [], at: instant)
    probe = ending + Rational(1, 1_000_000_000)
    refute original.active?(at: probe)
    assert replacement.active?(at: probe)
    proof = P::TimeVerification.new(change_set: change)
    refute proof.verified?
    refute change.verify(at: probe).verified?
    assert proof.checks.any? { |check| check.kind == :interval && check.at > ending && check.at < replacement.expires_at && !check.verification.verified? }
    refute proof.verify_readback(change.apply).verified?
  end

  test "exact horizon clipping never includes a rounded earlier instant" do
    origin = instant + Rational(1, 1_000_000_000)
    change = P::ChangeSet.new(snapshot: snapshot(:palo_alto), intents: [], targets: [], at: origin)
    proof = P::TimeVerification.new(change_set: change)
    assert proof.verified?
    assert_equal origin, proof.checks.first.at
    assert proof.checks.all? { |check| check.at >= origin }
  end

  test "fractional starts and independent readback expiry remain distinct inside one Float bucket" do
    starts = instant + 3600 + Rational(1, 10_000_000)
    late = scheduled_change(conditions: { starts_at: starts.iso8601(9) })
    refute P::TimeVerification.new(change_set: late).verified?
    refute late.intents.sole.rule.active?(at: starts - Rational(1, 1_000_000_000))
    assert late.intents.sole.rule.active?(at: starts)

    change = scheduled_change
    proof = P::TimeVerification.new(change_set: change)
    assert proof.verified?
    early = instant + 7200 - Rational(1, 10_000_000)
    rule = change.apply.rules.sole.with(conditions: { expires_at: early.iso8601(9) })
    readback = snapshot(:palo_alto, [ rule ])
    check = proof.verify_readback(readback)
    refute check.verified?
    assert check.checks.any? { |item| item.kind == :interval && item.at > early && item.at < instant + 7200 && !item.verification.verified? }
  end
end
