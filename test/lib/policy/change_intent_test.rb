# frozen_string_literal: true

require "test_helper"
require_relative "../framework/support/policy_factory"

class ChangeIntentTest < Minitest::Test
  include PolicyFactory

  def test_rejected_intents_do_not_seal_the_supplied_rule_graph
    [ { operation: :create, placement: :unknown }, { operation: :modify, rule_id: nil } ].each do |attributes|
      entry = rule(:palo_alto)

      assert_raises(ArgumentError) { P::ChangeSet::Intent.new(**attributes, rule: entry) }

      refute entry.sealed?
      refute entry.sources.sealed?
      entry.action = "deny"
      assert_equal "deny", entry.action
    end
  end

  def test_each_operation_rejects_fields_that_belong_to_another_operation
    entry = rule(:palo_alto)
    [ { operation: :create, rule: entry, placement: :append, rule_id: "unrelated" },
      { operation: :modify, rule: entry, rule_id: "original", placement: :prepend },
      { operation: :delete, rule_id: "original", rule: entry },
      { operation: :delete, rule_id: "original", before: "anchor" },
      { operation: :move, rule_id: "original", before: "anchor", rule: entry } ].each do |attributes|
      assert_raises(ArgumentError) { P::ChangeSet::Intent.new(**attributes) }
      refute entry.sealed?
    end
  end

  def test_moves_require_one_nonempty_text_anchor
    [ {}, { before: "" }, { before: 1 }, { before: "first", after: "last" } ].each do |anchors|
      assert_raises(ArgumentError) { P::ChangeSet::Intent.move(rule_id: "original", **anchors) }
    end
    id, anchor = +"original", +"anchor"
    intent = P::ChangeSet::Intent.move(rule_id: id, before: anchor)
    id.clear
    anchor.clear

    assert_equal "original", intent.rule_id
    assert_equal "anchor", intent.before
    assert intent.frozen?
  end

  def test_accepted_creation_seals_the_owned_rule_graph
    entry = rule(:palo_alto)
    intent = P::ChangeSet::Intent.create(rule: entry, placement: :append)

    assert_same entry, intent.rule
    assert entry.sealed?
    assert entry.sources.sealed?
    assert_equal :append, intent.placement
  end
end
