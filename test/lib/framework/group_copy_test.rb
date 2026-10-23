# frozen_string_literal: true

require "test_helper"

class GroupCopyTest < Minitest::Test
  E = Algosec::Elements

  def group
    first = E::AddressObject.new(name: "first", member: [ { type: "host", value: "10.0.0.1" } ])
    E::AddressGroup::Negated.new(name: "excluded", members: { "first" => first }).seal!
  end

  def test_clone_preserves_the_sealed_graph
    original = group
    copy = original.clone
    second = E::AddressObject.new(name: "second", member: [ { type: "host", value: "10.0.0.2" } ])

    assert copy.sealed?
    assert_raises(FrozenError) { copy.add(second.name, second) }
    assert_equal original.members, copy.members
    assert copy.dependencies.all?(&:sealed?)
    refute second.sealed?
  end

  def test_dup_owns_mutable_members_and_seals_new_dependencies
    original = group
    copy = original.dup
    second = E::AddressObject.new(name: "second", member: [ { type: "host", value: "10.0.0.2" } ])
    copy.add(second.name, second)

    refute copy.sealed?
    assert_instance_of E::AddressGroup::Negated, copy
    assert_equal [ "first" ], original.members.keys
    assert_equal %w[first second], copy.members.keys
    assert_same original.members.fetch("first"), copy.members.fetch("first")
    copy.seal!
    assert second.sealed?
  end
end
