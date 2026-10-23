# frozen_string_literal: true

require "minitest/autorun"
require "open3"
require "tmpdir"
require "rbconfig"
require "algosec"

class GemContractTest < Minitest::Test
  def test_default_cache_round_trip_needs_no_writable_installation_directory
    previous = ENV.delete("ALGOSEC_CACHE_DIR")
    cache = Algosec::Config::Cache.new
    assert_nil cache.directory
    result = Algosec::Config::Parser.perform("", vendor: :srx, device_id: 1)
    cache.save(result)
    assert_equal :srx, cache.load(1).reader.vendor
    assert result.reader.content.frozen?
    assert_raises(Errno::ENOENT) { Algosec::Config::Cache.new.load(1) }
  ensure
    ENV["ALGOSEC_CACHE_DIR"] = previous if previous
  end

  def test_explicit_directory_survives_a_new_cache_instance
    Dir.mktmpdir("algosec-cache-") do |directory|
      result = Algosec::Config::Parser.perform("", vendor: :srx, device_id: 1)
      Algosec::Config::Cache.new(directory: directory).save(result, source_key: "revision-1")
      restored = Algosec::Config::Cache.new(directory: directory).load(1, source_key: "revision-1")
      assert_equal :srx, restored.reader.vendor
      assert restored.reader.content.frozen?
      assert_raises(Algosec::Config::Cache::InvalidEntry) do
        Algosec::Config::Cache.new(directory: directory).load(1, source_key: "revision-2")
      end
    end
  end

  def test_environment_directory_is_explicit_and_rejects_ambiguous_store
    previous = ENV["ALGOSEC_CACHE_DIR"]
    Dir.mktmpdir("algosec-env-cache-") do |directory|
      ENV["ALGOSEC_CACHE_DIR"] = directory
      assert_equal directory, Algosec::Config::Cache.new.directory
      assert_raises(ArgumentError) { Algosec::Config::Cache.new(store: ActiveSupport::Cache::MemoryStore.new) }
    end
  ensure
    previous ? ENV["ALGOSEC_CACHE_DIR"] = previous : ENV.delete("ALGOSEC_CACHE_DIR")
  end
end
