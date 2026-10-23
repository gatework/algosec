# frozen_string_literal: true

require_relative "deployment_verification_test"
require "algosec/policy/plan_document"

class DeploymentTest
  TIME_ZONE_CONFIGURATION = "address host\n ip 192.0.2.1/32\nexit\n".freeze

  def timed_snapshot(zone, device_id: 1)
    parsed = Algosec::Config::Parser.perform(TIME_ZONE_CONFIGURATION, vendor: :hillstone, device_id: device_id, time_zone: zone)
    assert parsed.complete?, parsed.diagnostics.inspect
    Algosec::Policy::Snapshot.from_config(parsed, revision: Digest::SHA256.hexdigest(TIME_ZONE_CONFIGURATION))
  end

  def context_plan(target:, source: target)
    change = Algosec::Policy::ChangeSet.new(snapshot: target, intents: [], targets: [])
    Algosec::Policy::Plan.new(operation: :configure, snapshot: target, source: source,
      changes: [], commands: "configure\n", change_set: change)
  end

  def use_context_verifier(target:, source: target)
    @session.define_singleton_method(:read_config) do
      @calls << :read
      Algosec::DeviceSession::Capture.new(content: TIME_ZONE_CONFIGURATION)
    end
    @verifier = Algosec::Deployment::Verification.new(snapshot_loader: ->(**) { target }, source_loader: ->(**) { source },
      baseline_validator: ->(plan:, capture:) { Digest::SHA256.hexdigest(capture.content) == plan.target_baseline.fetch(:revision) })
  end

  test "target time zone drift rejects before writes for borrowed and owned sessions" do
    [ false, true ].each do |owned|
      setup
      approved = timed_snapshot("UTC")
      @plan = context_plan(target: approved)
      use_context_verifier(target: timed_snapshot("Asia/Hong_Kong"))
      runner = deployment(owned: owned)

      error = assert_raises(Algosec::Policy::Error) { runner.perform }
      assert_equal :stale_plan, error.code
      assert_equal :failed, runner.attempt.status
      refute runner.attempt.writes_started?
      assert_empty runner.attempt.receipts
      assert_equal owned ? [ :read, :close ] : [ :read ], @session.calls
    end
  end

  test "source time zone drift rejects before target writes" do
    target = timed_snapshot("UTC")
    @plan = context_plan(target: target, source: timed_snapshot("UTC", device_id: 2))
    use_context_verifier(target: target, source: timed_snapshot("Asia/Hong_Kong", device_id: 2))
    runner = deployment

    error = assert_raises(Algosec::Policy::Error) { runner.perform }
    assert_equal :stale_plan, error.code
    refute runner.attempt.writes_started?
    assert_equal :failed, runner.attempt.status
    assert_equal [ :read ], @session.calls
  end

  test "each device retains its own approved time zone" do
    target, source = timed_snapshot("UTC"), timed_snapshot("Asia/Hong_Kong", device_id: 2)
    @plan = context_plan(target: target, source: source)
    use_context_verifier(target: timed_snapshot("UTC"), source: timed_snapshot("Asia/Hong_Kong", device_id: 2))

    attempt = deployment.perform
    assert_equal :succeeded, attempt.status
    assert attempt.effect_confirmed?
    assert attempt.persistence_confirmed?
  end

  test "snapshot plan and effect proofs share the same time zone baseline" do
    target = timed_snapshot("Asia/Hong_Kong")
    change = Algosec::Policy::ChangeSet.new(snapshot: target, intents: [], targets: [])
    nat = Algosec::Policy::Nat::Verification.unchanged(change_set: change)
    time = Algosec::Policy::TimeVerification.new(change_set: change)
    plan = Algosec::Policy::Plan.new(operation: :configure, snapshot: target, changes: [], change_set: change,
      required_effects: [ :nat, :time ], effect_proofs: { nat: nat, time: time })

    assert plan.ready?, plan.issues.inspect
    assert_equal "Asia/Hong_Kong", target.baseline.fetch(:time_zone)
    [ plan.target_baseline, plan.source_baseline, change.baseline, nat.baseline, time.baseline ].each do |baseline|
      assert_equal target.baseline, baseline
      assert baseline.frozen?
    end
    restored = Algosec::Policy::PlanDocument.load(Algosec::Policy::PlanDocument.dump(plan), target: target)
    assert restored.ready?, restored.issues.inspect
    assert_equal plan.target_baseline, restored.target_baseline
  end

  test "approved documents bind both target and source time zones" do
    target, source = timed_snapshot("UTC"), timed_snapshot("UTC", device_id: 2)
    plan = context_plan(target: target, source: source)
    document = JSON.parse(JSON.generate(Algosec::Policy::PlanDocument.dump(plan)))

    [ [ timed_snapshot("Asia/Hong_Kong"), source ], [ target, timed_snapshot("Asia/Hong_Kong", device_id: 2) ] ].each do |actual_target, actual_source|
      error = assert_raises(Algosec::Policy::Error) do
        Algosec::Policy::PlanDocument.load(document, target: actual_target, source: actual_source)
      end
      assert_equal :stale_plan, error.code
    end
    baseline = document.fetch("target_baseline")
    assert Algosec::Policy::Plan.validate_context!(baseline, plan.target_baseline)
    assert_raises(Algosec::Policy::Error) { Algosec::Policy::Plan.validate_context!(baseline.except("time_zone"), plan.target_baseline) }
  end

  test "proposed graph cannot be restored in another time zone" do
    target = timed_snapshot("UTC")
    codec = Algosec::Policy::PlanDocument::ProposedGraph
    document = codec.dump(target.catalog.to_a, snapshot: target, at: Time.utc(2030))

    assert_raises(Algosec::Config::Document::InvalidDocument) { codec.load(document, snapshot: timed_snapshot("Asia/Hong_Kong")) }
  end

  test "time zone agnostic semantic documents require rebuilding" do
    target = timed_snapshot("UTC")
    plan = context_plan(target: target)
    old = Algosec::Policy::PlanDocument.dump(plan).merge("semantic_version" => "firewall-domain-v7")
    assert_raises(ArgumentError) { Algosec::Policy::PlanDocument.load(old, target: target) }
    parsed = Algosec::Config::Parser.perform(TIME_ZONE_CONFIGURATION, vendor: :hillstone, device_id: 1, time_zone: "UTC")
    old = Algosec::Config::Document.dump(parsed).merge("semantic_version" => "firewall-domain-v7")
    assert_raises(Algosec::Config::Document::InvalidDocument) { Algosec::Config::Document.load(old) }
  end
end
