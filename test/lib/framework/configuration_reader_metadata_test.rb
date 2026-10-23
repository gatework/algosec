# frozen_string_literal: true

require_relative "../../test_helper"
require "open3"

class ConfigurationReaderMetadataTest < Minitest::Test
  CONTENT = "private-source\r\nsecond\rthird\n".freeze

  def metadata(**changes)
    { vendor: :hillstone, device_id: 42, device_name: "firewall", created_at: Time.utc(2026, 10, 22),
      source_complete: false, source_sha256: Digest::SHA256.hexdigest(CONTENT), md5: Digest::MD5.hexdigest(CONTENT),
      line_count: 3, parsed_flags: [ true, false, true ], position: 2 }.merge(changes)
  end

  def detached(**changes)
    Algosec::Config::Reader.from_metadata(**metadata(**changes))
  end

  def test_metadata_reader_exposes_source_evidence_without_attaching_text
    reader = detached(vendor: "Hillstone")

    refute reader.source_attached?
    assert_instance_of Algosec::Config::Reader, reader
    assert_equal metadata, reader.source_metadata
    assert_equal :hillstone, reader.vendor
    assert_equal 42, reader.device_id
    assert_equal "firewall", reader.device_name
    assert_equal Time.utc(2026, 10, 22), reader.created_at
    refute reader.source_complete?
    assert_equal 3, reader.size
    assert_equal 2, reader.position
    assert_equal [ true, false, true ], reader.parsed_flags
    assert reader.parsed?(0)
    refute reader.parsed?(1)
    [ -1, 3, "0", nil ].each { |index| assert_nil reader.parsed?(index) }
    assert_equal({ vendor: :hillstone, device_id: 42, complete: false, sha256: metadata[:source_sha256], lines: 3 }, reader.as_json)
    refute_includes reader.inspect, "private-source"
    assert_equal reader.inspect, reader.to_s
  end

  def test_detached_source_operations_raise_instead_of_fabricating_empty_source
    [ detached, detached(position: 0), detached(position: 3), detached.seal! ].each do |reader|
      evidence = reader.source_metadata
      [ :content, :lines, :cursor, :read, :read_pending, :unparsed_lines, :unparsed_content,
        :reset!, :rewind, :step_back, :unread, :defer ].each do |method|
        assert_raises(Algosec::Config::SourceUnavailable) { reader.public_send(method) }
      end
      assert_raises(Algosec::Config::SourceUnavailable) { reader.mark(0) }
      assert_equal evidence, reader.source_metadata
    end
  end

  def test_metadata_and_its_mutable_values_are_owned_and_immutable
    values = metadata(device_name: +"firewall")
    reader = Algosec::Config::Reader.from_metadata(**values)
    values[:device_name].replace("changed")
    values[:source_sha256].replace("a" * 64)
    values[:md5].replace("b" * 32)
    values[:parsed_flags].clear
    values[:created_at].localtime("+08:00")

    assert_equal metadata, reader.source_metadata
    assert_equal 0, reader.created_at.utc_offset
    exported = reader.source_metadata
    assert exported.frozen?
    assert_raises(FrozenError) { exported.clear }
    [ :device_name, :created_at, :source_sha256, :md5, :parsed_flags ].each do |key|
      assert exported.fetch(key).frozen?, key
    end
  end

  def test_attached_metadata_uses_published_flags_and_position_after_cursor_reset
    reader = Algosec::Config::Reader.new(CONTENT, **metadata.slice(:vendor, :device_id, :device_name, :created_at, :source_complete))
    reader.read
    reader.read
    reader.mark(0).mark(2)
    reader.seal!
    reader.cursor.reset!

    assert reader.source_attached?
    assert_equal 0, reader.position
    assert_equal metadata, reader.source_metadata
    assert reader.source_metadata.frozen?
    assert_equal [ true, false, true ], reader.parsed_flags
  end

  def test_reattachment_preserves_raw_newlines_evidence_and_independent_cursor
    reader = detached
    content = CONTENT.dup
    attached = reader.with_source(content)
    content.replace("changed")

    refute_same reader, attached
    assert attached.source_attached?
    refute reader.source_attached?
    refute attached.sealed?
    assert_equal CONTENT, attached.content
    assert_equal [ "private-source\r\n", "second\r", "third\n" ], attached.lines
    assert_equal metadata, attached.source_metadata
    assert_equal "third\n", attached.read
    attached.mark(1)
    assert_equal [ true, false, true ], reader.parsed_flags
  end

  def test_sealed_detached_reader_can_attach_and_retain_publication_evidence
    reader = detached.seal!
    assert_same reader, reader.seal!
    assert reader.sealed?
    attached = reader.with_source(CONTENT)
    assert attached.sealed?
    attached.reset!
    assert_equal metadata, attached.source_metadata
    assert_equal [ true, false, true ], attached.parsed_flags
    assert_equal [ false, false, false ], attached.cursor.parsed_flags
    assert_equal 2, reader.position
  end

  def test_attached_reader_can_reattach_without_mutating_published_source
    reader = detached.with_source(CONTENT).seal!
    reader.reset!
    replacement = reader.with_source(CONTENT)

    assert replacement.sealed?
    assert_equal 2, replacement.position
    assert_equal metadata, replacement.source_metadata
    assert_equal 0, reader.position
  end

  def test_reattachment_checks_each_digest_line_count_and_exact_newlines
    [ { md5: "0" * 32 }, { source_sha256: "0" * 64 },
      { line_count: 4, parsed_flags: [ true, false, true, false ] } ].each do |changes|
      error = assert_raises(ArgumentError) { detached(**changes).with_source(CONTENT) }
      refute_includes error.message, "private-source"
    end
    assert_raises(ArgumentError) { detached.with_source(CONTENT.gsub(/\r\n?/, "\n")) }
  end

  def test_reattachment_uses_normal_cursor_input_validation_and_transcoding
    [ nil, 2, "private-source\0\n" ].each do |content|
      assert_raises(ArgumentError) { detached.with_source(content) }
    end
    assert_raises(EncodingError) { detached.with_source("\xFF".b) }
    text = "description café\r\n"
    reader = detached(source_sha256: Digest::SHA256.hexdigest(text), md5: Digest::MD5.hexdigest(text),
      line_count: 1, parsed_flags: [ false ], position: 0)
    assert_equal text, reader.with_source(text.encode(Encoding::ISO_8859_1)).content
  end

  def test_empty_source_is_attachable_and_distinct_from_unavailable_source
    reader = detached(source_sha256: Digest::SHA256.hexdigest(""), md5: Digest::MD5.hexdigest(""),
      line_count: 0, parsed_flags: [], position: 0)

    refute reader.source_attached?
    attached = reader.with_source("")
    assert attached.source_attached?
    assert_equal "", attached.content
    assert_equal [], attached.lines
    assert_nil attached.read
  end

  def test_metadata_rejects_bad_types_digest_formats_counts_flags_and_positions
    invalid = { vendor: [ nil, "", :unknown ], device_id: [ -1, "42", 1.2, true ],
      created_at: [ nil, "2026-10-22", Date.today ], source_complete: [ nil, 0, "false" ],
      source_sha256: [ nil, 2, "a" * 63, "g" * 64, "a" * 64 + "\n" ],
      md5: [ nil, 2, "a" * 31, "g" * 32, "a" * 32 + "\n" ],
      line_count: [ nil, -1, "3", 3.0 ], parsed_flags: [ nil, {}, [ true ], [ true, false, 1 ] ],
      position: [ nil, -1, "2", 2.0, 4 ] }
    invalid.each do |key, values|
      values.each { |value| assert_raises(ArgumentError, "#{key}=#{value.inspect}") { detached(**{ key => value }) } }
    end
  end

  def test_optional_device_metadata_and_end_position_are_supported
    reader = detached(device_id: nil, device_name: nil, source_complete: true, position: 3)
    assert_nil reader.device_id
    assert_nil reader.device_name
    assert reader.source_complete?
    assert_equal 3, reader.position
  end

  def test_detached_cache_round_trip_preserves_availability_and_publication
    [ false, true ].each do |published|
      reader = detached
      reader.seal! if published
      restored = Marshal.load(Marshal.dump(reader))
      assert_equal metadata, restored.source_metadata
      refute restored.source_attached?
      assert_equal published, restored.sealed?
      assert_raises(Algosec::Config::SourceUnavailable) { restored.content }
      assert_equal CONTENT, restored.with_source(CONTENT).content
    end
  end

  def test_attached_draft_cache_round_trip_restores_an_independent_cursor
    original = detached.with_source(CONTENT)
    restored = Marshal.load(Marshal.dump(original))

    assert restored.source_attached?
    refute restored.sealed?
    assert_equal metadata, restored.source_metadata
    assert_equal CONTENT, restored.content
    restored.reset!
    assert_equal metadata, original.source_metadata
    assert_equal [ false, false, false ], restored.parsed_flags
  end

  def test_attached_cache_round_trip_retains_full_published_cursor_states
    reader = detached.with_source(CONTENT)
    reader.cursor.mark(1, state: :ignored)
    reader.seal!
    reader.reset!
    restored = Marshal.load(Marshal.dump(reader))

    assert restored.source_attached?
    assert restored.sealed?
    assert_equal metadata, restored.source_metadata
    assert_equal :ignored, restored.cursor.state(1)
    assert_equal [], restored.unparsed_lines
    restored.reset!
    assert_equal metadata, restored.source_metadata
  end

  def test_standalone_require_supports_detached_round_trip_and_attachment
    script = <<~'RUBY_SCRIPT'
      require "algosec/config/reader"
      reader = Algosec::Config::Reader.new("first\r\nsecond\rthird\n", vendor: :hillstone)
      detached = Algosec::Config::Reader.from_metadata(**reader.source_metadata).seal!
      restored = Marshal.load(Marshal.dump(detached)).with_source(reader.content)
      abort "source evidence lost" unless restored.sealed? && restored.source_metadata == reader.source_metadata
    RUBY_SCRIPT
    output, status = Open3.capture2e(RbConfig.ruby, "-Ilib", "-e", script, chdir: TestPaths.root)
    assert status.success?, output
  end
end
