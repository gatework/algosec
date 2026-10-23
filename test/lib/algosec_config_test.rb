# frozen_string_literal: true

require "minitest/autorun"
require "tmpdir"
require "active_support/cache"
require "algosec"

class AlgosecConfigTest < Minitest::Test
  def setup
    @result = Algosec::Config::Parser.perform("", vendor: :srx, device_id: 1)
  end

  def test_file_cache_delegates_persistence_to_active_support
    Dir.mktmpdir("algosec-config-cache-") do |directory|
      cache = Algosec::Config::Cache.new(directory: directory)

      assert_instance_of ActiveSupport::Cache::FileStore, cache.store
      assert_nil cache.save(@result)

      restored = cache.load(1)

      assert_equal @result.reader.vendor, restored.reader.vendor
      assert_equal @result.reader.device_id, restored.reader.device_id
      assert restored.reader.content.frozen?
    end
  end

  def test_cache_rejects_a_store_that_did_not_write
    store = Class.new do
      def write(*) = false

      def read(*) = nil
    end.new
    cache = Algosec::Config::Cache.new(store: store)

    assert_raises(IOError) { cache.save(@result) }
  end

  def test_cache_ignores_entries_from_before_source_and_native_identity_layout
    store = ActiveSupport::Cache::MemoryStore.new
    store.write([ "algosec", "config", "algosec-config-ruby-v43", "1" ], Object.new)
    cache = Algosec::Config::Cache.new(store: store)

    assert_raises(Errno::ENOENT) { cache.load(1) }

    cache.save(@result)
    assert_equal @result.reader.content, cache.load(1).reader.content
  end

  def test_parser_validates_and_freezes_reference_time
    reference_time = Time.utc(2026, 9, 15, 12, 0, 0)
    parser_class = Algosec::Vendors.fetch(:srx, :parser)
    parser = parser_class.new(reference_time: reference_time)
    result = parser.perform("")

    assert_equal reference_time, result.reader.created_at
    assert result.reader.created_at.frozen?
    assert_raises(ArgumentError) { parser_class.new(reference_time: Object.new) }
  end

  def test_cache_ignores_results_created_before_nat_dependency_and_service_fixes
    store = ActiveSupport::Cache::MemoryStore.new
    store.write([ "algosec", "config", "algosec-config-ruby-v44", "1" ], Object.new)
    store.write([ "algosec", "config", "algosec-config-ruby-v45", "1" ], Object.new)
    store.write([ "algosec", "config", "algosec-config-ruby-v46", "1" ], Object.new)
    cache = Algosec::Config::Cache.new(store: store)

    assert_raises(Errno::ENOENT) { cache.load(1) }
    cache.save(@result)
    assert_equal @result.reader.content, cache.load(1).reader.content
  end
end
