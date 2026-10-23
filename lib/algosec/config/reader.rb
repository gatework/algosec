# frozen_string_literal: true

require "digest"
require "ctx_parser"
require "active_support"
require "active_support/core_ext/object/blank"
require "active_support/core_ext/object/inclusion"
require "active_support/time"
require_relative "../vendors"
require_relative "source_unavailable"

module Algosec
  module Config
    # 源文本本身不可变，但解析游标和逐行消费状态可以独立重置。
    class Reader
      attr_reader :vendor, :device_id, :device_name, :created_at, :md5

      # 只恢复明确的来源证据，不创建空原文或触发领域解析。
      def self.from_metadata(vendor:, created_at:, source_complete:, source_sha256:, md5:, line_count:, parsed_flags:, position:,
        device_id: nil, device_name: nil)
        allocate.tap do |reader|
          reader.send(:initialize_metadata, vendor: vendor, device_id: device_id, device_name: device_name,
            created_at: created_at, source_complete: source_complete, source_sha256: source_sha256,
            md5: md5, line_count: line_count, parsed_flags: parsed_flags, position: position)
        end
      end

      # 校验编码和设备元数据，保留原始换行并建立内容校验和。
      def initialize(content, vendor:, device_id: nil, device_name: nil, created_at: Time.current, source_complete: true)
        @cursor = CtxParser::Cursor.new(content)
        @content = cursor.content
        initialize_identity(vendor: vendor, device_id: device_id, device_name: device_name,
          created_at: created_at, source_complete: source_complete)
        # 保留 LF、CRLF 和 CR，以便配置切片和校验和都对应原始内容。
        @lines = cursor.lines.map(&:raw).freeze
        @md5 = Digest::MD5.hexdigest(@content).freeze
        @source_sha256 = cursor.checksum
        @line_count = cursor.size
        reset!
      end

      # 解析完成后保存证据快照。Cursor 仍可独立读取、重置，不再改写已发布证据。
      def seal!
        return self if sealed?
        if source_attached?
          @published_states = cursor.states
          @published_unparsed_lines = cursor.unparsed_lines.map(&:raw).freeze
        end
        @published_parsed_flags = parsed_flags
        @published_position = position
        freeze
      end

      def sealed? = frozen?

      # 返回源文本的行数。
      def size = @line_count

      # 传输完整性独立于厂商语法是否全部识别。
      def source_complete? = @source_complete

      def source_sha256 = @source_sha256

      def source_attached? = !@cursor.nil?

      def content
        ensure_source!
        @content
      end

      def lines
        ensure_source!
        @lines
      end

      def cursor
        ensure_source!
        @cursor
      end

      def position = source_attached? ? cursor.position : @metadata_position

      # 显式来源字段形成不可变值，不暴露对象内部实现或重置后的发布游标。
      def source_metadata
        { vendor: vendor, device_id: device_id, device_name: device_name, created_at: created_at,
          source_complete: source_complete?, source_sha256: source_sha256, md5: md5, line_count: size,
          parsed_flags: parsed_flags, position: @published_position || position }.freeze
      end

      # 原文通过 Cursor 校验后，只在完全匹配来源证据时恢复独立读取状态。
      def with_source(content)
        metadata = source_metadata
        attached = self.class.new(content, **metadata.slice(:vendor, :device_id, :device_name, :created_at, :source_complete))
        unless attached.md5 == md5 && attached.source_sha256 == source_sha256 && attached.size == size
          raise ArgumentError, "Source does not match configuration metadata"
        end
        attached.send(:restore_cursor, metadata.fetch(:parsed_flags).map { |parsed| parsed ? :parsed : :pending }, metadata.fetch(:position))
        attached.seal! if sealed?
        attached
      end

      # 默认展示仅包含来源元数据，原文须通过 content 显式读取。
      def as_json(*) = { vendor: vendor, device_id: device_id, complete: source_complete?, sha256: source_sha256, lines: size }

      def inspect = "#<#{self.class.name} vendor=#{vendor} lines=#{size} complete=#{source_complete?}>"
      alias to_s inspect

      # Cursor 的来源行是带派生属性的 Data；缓存只保存值，读取时重建来源对象。
      def marshal_dump
        [ source_metadata, (content if source_attached?), (@published_states || cursor.states if source_attached?), sealed? ]
      end

      def marshal_load(values)
        metadata, content, states, published = values
        if content.nil?
          initialize_metadata(**metadata)
        else
          initialize(content, **metadata.slice(:vendor, :device_id, :device_name, :created_at, :source_complete))
          restore_cursor(states, metadata.fetch(:position))
        end
        seal! if published
      end

      # 返回解析标记的只读副本。
      def parsed_flags = @published_parsed_flags || (source_attached? ? cursor.parsed_flags : @metadata_parsed_flags)

      # 查询指定行是否已被消费；无效索引返回 nil。
      def parsed?(index)
        return cursor.parsed?(index) if source_attached? && !sealed?
        parsed_flags[index] if valid_index?(index)
      end

      # 设置单行消费标记，并拒绝越界或非布尔值。
      def mark(index, parsed: true)
        ensure_source!
        raise IndexError, "Line index is outside the document" unless valid_index?(index)
        raise ArgumentError, "Parsed flag must be true or false" unless parsed == true || parsed == false
        cursor.mark(index, state: parsed ? :parsed : :pending)
        self
      end

      # 将游标退回文档开头，但保留源内容不变。
      def rewind
        cursor.rewind
        self
      end

      # 清空所有消费标记并把游标退回开头。
      def reset!
        cursor.reset!
        self
      end

      # 读取下一行原文并推进游标；读完后返回 nil。
      def read
        cursor.read&.raw
      end

      # 读取下一条未消费的非空行，并在返回前标记为已消费。
      def read_pending
        ensure_source!
        while position < size
          index = position
          line = read
          next if parsed?(index)
          mark(index)
          line = line.chomp
          next if line.blank?
          return line.freeze
        end
        nil
      end

      # 只退回游标，不改变行的消费标记。
      def step_back
        cursor.step_back
      end

      # 退回上一行并撤销该行的消费标记。
      def unread
        return false unless step_back
        mark(position, parsed: false)
        true
      end

      # 保留上一行待后续解析，不移动当前游标。
      def defer
        ensure_source!
        return false if position.zero?
        mark(position - 1, parsed: false)
        true
      end

      # 返回尚未消费的原始行及其拼接内容。
      def unparsed_lines = @published_unparsed_lines || cursor.unparsed_lines.map(&:raw).freeze

      def unparsed_content = unparsed_lines.join.freeze

      private

      def ensure_source!
        raise SourceUnavailable, "Configuration source is unavailable" unless source_attached?
      end

      # 保留普通构造器已有设备 ID 兼容性；文档元数据在入口另行执行严格整数校验。
      def initialize_identity(vendor:, device_id:, device_name:, created_at:, source_complete:)
        raise ArgumentError, "Source completeness must be boolean" unless boolean?(source_complete)
        @source_complete = source_complete
        @vendor = Vendors.normalize(vendor)
        unless Vendors.supports?(@vendor, :parser)
          raise ArgumentError, "Unknown configuration vendor: #{vendor}"
        end
        if !device_id.nil? && !/\A[0-9]+\z/.match?(device_id.to_s)
          raise ArgumentError, "Device ID must be a nonnegative integer"
        end
        @device_id = device_id.nil? ? nil : Integer(device_id.to_s, 10)
        @device_name = device_name&.to_s&.dup&.freeze
        unless created_at.is_a?(Time) || created_at.is_a?(ActiveSupport::TimeWithZone)
          raise ArgumentError, "Creation time must be a Time"
        end
        @created_at = created_at.dup.freeze
      end

      def initialize_metadata(vendor:, device_id:, device_name:, created_at:, source_complete:, source_sha256:, md5:,
        line_count:, parsed_flags:, position:)
        if !device_id.nil? && !nonnegative_integer?(device_id)
          raise ArgumentError, "Device ID must be a nonnegative integer"
        end
        raise ArgumentError, "Line count must be a nonnegative integer" unless nonnegative_integer?(line_count)
        unless nonnegative_integer?(position) && position <= line_count
          raise ArgumentError, "Position must be within the source line count"
        end
        unless parsed_flags.is_a?(Array) && parsed_flags.size == line_count && parsed_flags.all? { |value| boolean?(value) }
          raise ArgumentError, "Parsed flags must contain one boolean per source line"
        end
        unless source_sha256.is_a?(String) && /\A[0-9a-f]{64}\z/.match?(source_sha256)
          raise ArgumentError, "Source SHA256 must be a hexadecimal digest"
        end
        unless md5.is_a?(String) && /\A[0-9a-f]{32}\z/.match?(md5)
          raise ArgumentError, "Source MD5 must be a hexadecimal digest"
        end
        initialize_identity(vendor: vendor, device_id: device_id, device_name: device_name,
          created_at: created_at, source_complete: source_complete)
        @source_sha256 = source_sha256.dup.freeze
        @md5 = md5.dup.freeze
        @line_count = line_count
        @metadata_parsed_flags = parsed_flags.dup.freeze
        @metadata_position = position
      end

      def restore_cursor(states, position)
        states.each_with_index { |state, index| cursor.mark(index, state: state) }
        position.times { cursor.read }
      end

      def boolean?(value) = value.equal?(true) || value.equal?(false)

      def nonnegative_integer?(value) = value.is_a?(Integer) && value >= 0

      # 判断索引是否落在文档行范围内。
      def valid_index?(index) = index.is_a?(Integer) && index.in?(0...size)
    end
  end
end
