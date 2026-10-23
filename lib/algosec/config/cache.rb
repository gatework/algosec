# frozen_string_literal: true

require "active_support"
require "active_support/cache"
require "fileutils"
require_relative "reader"
require_relative "result"
require_relative "cache/entry"

module Algosec
  module Config
    # 配置对象缓存。调用方注入共享缓存或显式文件目录；默认只使用内存。
    class Cache
      class InvalidEntry < StandardError; end

      CACHE_VERSION = "algosec-config-ruby-v82"
      attr_reader :directory, :store

      # 缓存位置由调用方决定，避免写入 gem 安装目录或隐式依赖宿主框架。
      def initialize(directory: nil, store: nil)
        configured_directory = directory || ENV["ALGOSEC_CACHE_DIR"]
        if store && configured_directory
          raise ArgumentError, "directory cannot be combined with a cache store"
        end

        if store
          @directory, @store = nil, store
        elsif configured_directory
          @directory = File.expand_path(configured_directory).freeze
          @store = ActiveSupport::Cache::FileStore.new(@directory)
        else
          @directory, @store = nil, ActiveSupport::Cache::MemoryStore.new
        end
      end

      # 校验结果后交给缓存保存；FileStore 自己负责原子写入。
      def save(result, source_key: nil)
        validate_result!(result)
        entry = Entry.new(result, source_key: source_key)
        prepare_directory!
        written = store.write(cache_key(result.reader.device_id), entry)
        raise IOError, "Configuration cache store rejected the write" unless written
        nil
      end

      # 从缓存读取并校验对象，然后恢复冻结状态。
      def load(device_id, source_key: nil)
        entry = store.read(cache_key(device_id))
        raise Errno::ENOENT, "Configuration cache entry not found" unless entry

        validate_entry!(entry, device_id)
        if source_key && entry.source_key != source_key
          raise InvalidEntry, "Configuration cache differs from stored parsing source key"
        end
        entry.restore
      end

      def as_json(*) = { version: CACHE_VERSION, store: store.class.name }

      def inspect = "#<#{self.class.name} store=#{store.class.name}>"
      alias to_s inspect

      private

      # 在使用 FileStore 前创建私有缓存目录；嵌套目录由 FileStore 管理。
      def prepare_directory!
        return unless directory

        FileUtils.mkdir_p(directory, mode: 0o700)
      end

      # 校验设备编号并生成带格式版本的 Rails 缓存键。
      def cache_key(device_id)
        validate_device_id!(device_id)
        [ "algosec", "config", CACHE_VERSION, device_id.to_s ]
      end

      # 将设备编号限制为正整数，避免缓存键和文件路径发生歧义。
      def validate_device_id!(device_id)
        valid = (device_id.is_a?(Integer) || device_id.is_a?(String)) && /\A[1-9][0-9]*\z/.match?(device_id.to_s)
        raise ArgumentError, "Cache device ID must be a positive integer" unless valid

        device_id
      end

      # 确认缓存包含当前版本可接受的解析结果对象图。
      def validate_result!(result)
        unless result.instance_of?(Result) && result.reader.instance_of?(Reader) &&
               result.catalog.instance_of?(Elements::Catalog) && Vendors.supports?(result.reader.vendor, :parser)
          raise InvalidEntry, "Configuration cache must contain a Config::Result"
        end
      end

      # 校验缓存条目类型和设备归属，防止跨设备复用对象图。
      def validate_entry!(entry, device_id)
        raise InvalidEntry, "Invalid configuration cache contents" unless entry.instance_of?(Entry)

        validate_result!(entry.result)
        unless entry.result.reader.device_id.to_s == device_id.to_s
          raise InvalidEntry, "Configuration cache belongs to another device"
        end
      end
    end
  end
end
