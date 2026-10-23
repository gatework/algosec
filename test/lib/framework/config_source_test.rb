# frozen_string_literal: true

require "minitest/autorun"
require "active_support/cache"
require "json"
require "algosec"

class ConfigSourceTest < Minitest::Test
  def test_incomplete_transport_cannot_become_complete_from_recognized_syntax
    result = Algosec::Config::Parser.perform("rule id 1\n action permit\nexit\n", vendor: :hillstone, source_complete: false)

    refute result.complete?
    assert_equal 1, result.rules.size
    assert_includes result.diagnostics.map(&:code), :incomplete_source
    assert_raises(Algosec::Config::IncompleteConfiguration) do
      Algosec::Config::Parser.perform("", vendor: :hillstone, source_complete: false, strict: true)
    end
  end

  def test_source_cursor_preserves_raw_newlines_and_existing_reader_contract
    text = "rule id 1\r\n action permit\rexit\n"
    reader = Algosec::Config::Reader.new(text, vendor: :hillstone)

    assert_instance_of CtxParser::Cursor, reader.cursor
    assert_equal text, reader.content
    assert_equal Digest::MD5.hexdigest(text), reader.md5
    assert_equal Digest::SHA256.hexdigest(text), reader.source_sha256
    assert_equal "rule id 1\r\n", reader.read
    reader.mark(0)
    assert_equal :parsed, reader.cursor.state(0)
    assert reader.unread
    assert_equal :pending, reader.cursor.state(0)
    assert_equal "rule id 1", reader.read_pending
    assert reader.parsed?(0)
    assert_equal [ " action permit\r", "exit\n" ], reader.unparsed_lines
  end

  def test_reader_completeness_survives_parsing_and_cache_round_trip
    reader = Algosec::Config::Reader.new("rule id 1\nexit\n", vendor: :hillstone, device_id: 1, source_complete: false)
    result = Algosec::Config::Parser.perform(reader)
    cache = Algosec::Config::Cache.new(store: ActiveSupport::Cache::MemoryStore.new)
    cache.save(result)
    restored = cache.load(1)

    refute restored.complete?
    refute restored.reader.source_complete?
    assert restored.reader.content.frozen?
    assert restored.reader.cursor.lines.frozen?
    assert restored.reader.cursor.lines.first.raw.frozen?
    assert_equal [ true, true ], restored.reader.parsed_flags
    restored.reader.reset!
    assert_equal [ true, true ], restored.reader.parsed_flags
    assert_equal [ false, false ], restored.reader.cursor.parsed_flags
  end

  def test_source_and_result_summaries_do_not_disclose_configuration
    result = Algosec::Config::Parser.perform("private-secret-material\n", vendor: :hillstone)

    [ result, result.reader ].each do |object|
      refute_includes object.inspect, "private-secret-material"
      refute_includes object.to_s, "private-secret-material"
      refute_includes JSON.generate(object.as_json), "private-secret-material"
    end
    assert_includes result.reader.content, "private-secret-material"
  end

  def test_completeness_is_a_boolean
    assert_raises(ArgumentError) { Algosec::Config::Reader.new("", vendor: :hillstone, source_complete: "false") }
  end

  def test_explicit_incomplete_reader_cannot_be_upgraded_by_reparsing
    original = Algosec::Config::Reader.new("rule id 1\nexit\n", vendor: :hillstone, device_id: 17, device_name: "FW")
    result = Algosec::Config::Parser.perform(original, source_complete: false)

    refute result.reader.source_complete?
    refute Algosec::Config::Parser.perform(result.reader).complete?
    assert original.source_complete?
    assert_equal [ original.device_id, original.device_name, original.created_at ],
      [ result.reader.device_id, result.reader.device_name, result.reader.created_at ]
  end

  def test_input_rejects_invalid_bytes_and_nul_and_transcodes_valid_declared_encoding
    assert_raises(EncodingError) { Algosec::Config::Reader.new("\xFF".b, vendor: :hillstone) }
    assert_raises(ArgumentError) { Algosec::Config::Reader.new("rule\0id", vendor: :hillstone) }
    text = "description café\r\n".encode(Encoding::ISO_8859_1)
    reader = Algosec::Config::Reader.new(text, vendor: :hillstone)
    assert_equal "description café\r\n", reader.content
    assert_equal Encoding::UTF_8, reader.content.encoding
  end
end
