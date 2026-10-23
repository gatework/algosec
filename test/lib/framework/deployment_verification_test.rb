# frozen_string_literal: true

require_relative "deployment_test"

class DeploymentTest
  def domain_snapshot(content: "address host\n ip 192.0.2.1/32\nexit\n", device_id: 1)
    parsed = Algosec::Config::Parser.perform(content, vendor: :hillstone, device_id: device_id)
    Algosec::Policy::Snapshot.from_config(parsed, revision: Digest::SHA256.hexdigest(content))
  end

  def domain_plan(snapshot: domain_snapshot, source: snapshot, commands: "configure\n", proof: true)
    change = Algosec::Policy::ChangeSet.new(snapshot: snapshot, intents: [], targets: []) if proof
    Algosec::Policy::Plan.new(operation: :deploy, snapshot: snapshot, source: source, changes: [], commands: commands, change_set: change)
  end

  test "concrete ungenerated and unverified Plan both reject before opening session" do
    @plan = domain_plan(commands: nil)
    refute @plan.generated?
    assert_raises(Algosec::Policy::Error) { deployment.perform }
    @plan = domain_plan(proof: false)
    refute @plan.verified?
    assert_raises(Algosec::Policy::Error) { deployment.perform }
    assert_empty @session.calls
  end

  test "actual source snapshot drift rejects before first write" do
    original = domain_snapshot(device_id: 2)
    @plan = domain_plan(source: original)
    current = domain_snapshot(content: "address host\n ip 192.0.2.2/32\nexit\n", device_id: 2)
    target = domain_snapshot
    @verifier = Algosec::Deployment::Verification.new(snapshot_loader: ->(**) { target },
      baseline_validator: ->(**) { true }, source_loader: ->(**) { current })
    error = assert_raises(Algosec::Policy::Error) { deployment.perform }
    assert_equal :stale_plan, error.code
    assert_equal [ :read ], @session.calls
  end

  test "approved raw config mismatch blocks even when loader supplies the saved database revision" do
    target = domain_snapshot
    @plan = domain_plan(snapshot: target)
    @verifier = Algosec::Deployment::Verification.new(snapshot_loader: ->(**) { target }, baseline_validator: ->(**) { false })
    runner = deployment
    error = assert_raises(Algosec::Policy::Error) { runner.perform }
    assert_equal :stale_plan, error.code
    assert_equal :failed, runner.attempt.status
    assert_equal [ :read ], @session.calls
  end

  test "source loader is mandatory for a different source device" do
    @plan = domain_plan(source: domain_snapshot(device_id: 2))
    target = domain_snapshot
    @verifier = Algosec::Deployment::Verification.new(snapshot_loader: ->(**) { target }, baseline_validator: ->(**) { true })
    error = assert_raises(Algosec::Policy::Error) { deployment.perform }
    assert_equal :missing_baseline, error.code
    assert_equal [ :read ], @session.calls
  end

  test "adapter verifies a concrete Plan through its shared readback proof" do
    target = domain_snapshot
    @plan = domain_plan(snapshot: target)
    @verifier = Algosec::Deployment::Verification.new(snapshot_loader: ->(**) { target }, baseline_validator: ->(**) { true })
    attempt = deployment.perform
    assert attempt.effect_confirmed?
    assert_equal :succeeded, attempt.status
  end

  test "readback from another device cannot prove effect" do
    @plan = domain_plan
    target, other = domain_snapshot, domain_snapshot(device_id: 2)
    reads = [ target, other ]
    @verifier = Algosec::Deployment::Verification.new(snapshot_loader: ->(**) { reads.shift }, baseline_validator: ->(**) { true })
    runner = deployment
    assert_raises(Algosec::Deployment::Uncertain) { runner.perform }
    refute runner.attempt.effect_confirmed?
    assert_equal :uncertain, runner.attempt.status
    assert runner.attempt.persistence_confirmed?
  end

  test "security proof alone cannot deploy a Plan requiring NAT effect proof" do
    target = domain_snapshot
    change = Algosec::Policy::ChangeSet.new(snapshot: target, intents: [], targets: [])
    @plan = Algosec::Policy::Plan.new(operation: :deploy, snapshot: target, changes: [], commands: "configure\n",
      change_set: change, required_effects: [ :nat ])
    assert @plan.proof.verified?
    refute @plan.verified?
    assert_raises(Algosec::Policy::Error) { deployment.perform }
    assert_empty @session.calls
  end
end
