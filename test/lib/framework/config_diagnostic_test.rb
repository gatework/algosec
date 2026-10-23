# frozen_string_literal: true

require_relative "../../test_helper"

class ConfigDiagnosticTest < Minitest::Test
  C = Algosec::Config

  def test_diagnostic_owns_immutable_text_and_keeps_a_stable_value_hash
    code, message = +"unsupported_command", +"unknown command"
    diagnostic = C::Diagnostic.new(code, message, 1)
    values = { diagnostic => :recorded }

    code.replace("changed")
    message.clear

    assert_equal "unsupported_command", diagnostic.code
    assert_equal "unknown command", diagnostic.message
    assert_equal :recorded, values[diagnostic]
    assert_equal diagnostic, C::Diagnostic.new("unsupported_command", "unknown command", 1)
    assert diagnostic.code.frozen?
    assert diagnostic.message.frozen?
  end

  def test_source_presence_distinguishes_absent_and_redacted_messages
    absent = C::Diagnostic.new(:missing_reference, nil, nil)
    redacted = C::Diagnostic.new(:missing_reference, nil, nil, message_present: true)

    refute absent.message_present?
    assert absent.message_available?
    assert_nil absent.message
    assert redacted.message_present?
    refute redacted.message_available?
    assert_raises(C::SourceUnavailable) { redacted.message }
    refute_equal absent, redacted
  end

  def test_invalid_diagnostic_values_are_rejected_at_construction
    [ nil, 1, "" ].each do |code|
      assert_raises(ArgumentError) { C::Diagnostic.new(code, nil, nil) }
    end
    [ 0, -1, 1.5, "1" ].each do |line|
      assert_raises(ArgumentError) { C::Diagnostic.new(:missing_reference, nil, line) }
    end
    assert_raises(ArgumentError) { C::Diagnostic.new(:missing_reference, [], nil) }
    assert_raises(ArgumentError) { C::Diagnostic.new(:missing_reference, nil, nil, message_present: "yes") }
    assert_raises(ArgumentError) { C::Diagnostic.new(:missing_reference, "text", nil, message_present: false) }
  end

  def test_result_owns_the_diagnostic_collection
    diagnostic = C::Diagnostic.new(:missing_reference, "unknown object", nil)
    diagnostics = [ diagnostic ]
    result = C::Result.new(reader: C::Reader.new("", vendor: :srx), catalog: Algosec::Elements::Catalog.new,
      diagnostics: diagnostics, at: Time.utc(2026))

    diagnostics.clear

    assert_equal [ diagnostic ], result.diagnostics
    assert result.diagnostics.frozen?
    refute result.complete?
  end
end
