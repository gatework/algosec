# frozen_string_literal: true

require "json"
require_relative "elements/service_object"
require_relative "vendors"

module Algosec
  # 从厂商采集表或通用 JSON 定义导入内置服务，供 Parser 和 Policy 共用。
  class BuiltinServices
    class Error < StandardError; end

    PROTOCOLS = { "AH" => "51", "ESP" => "50", "GRE" => "47", "IPv4" => "4",
                  "IPv6" => "41", "OSPFIGP" => "89" }.freeze
    TERM_FIELDS = {
      protocol: %w[protocol].freeze, destination_port: %w[destination_port destination].freeze,
      source_port: %w[source_port source].freeze, timeout: %w[timeout].freeze,
      term: %w[term].freeze, uuid: %w[uuid].freeze
    }.freeze
    TERM_KEYS = TERM_FIELDS.values.flatten.freeze

    attr_reader :services, :truncated_names

    # 读取 JSON 文件并构造以服务名为键的 Service 哈希。
    def self.load(path, vendor:, device_id:)
      return {} unless path

      document = JSON.parse(File.read(path))
      new(document, vendor: vendor, device_id: device_id).services
    rescue Errno::ENOENT, Errno::EACCES, JSON::ParserError => error
      raise Error, "内置服务文件不可读：#{path}（#{error.message}）"
    end

    # 采集元数据不参与服务语义；截断名称只保留在诊断信息中。
    def initialize(document, vendor:, device_id:)
      @vendor = Vendors.normalize(vendor)
      @device_id = device_id
      @truncated_names = Array(document.is_a?(Hash) ? document["truncated_names"] : nil).map { |name| name.to_s.dup.freeze }.freeze
      @services = service_entries(document).each_with_object({}) do |(service_name, definition), services|
        next if @truncated_names.include?(service_name)

        services[service_name] = build_service(service_name, definition)
      end.freeze
    rescue KeyError, TypeError, ArgumentError => error
      raise Error, "内置服务定义无效：#{error.message}"
    end

    private

    # 保留采集文件与通用文档形态，在规范化名称后拒绝重复定义。
    def service_entries(document)
      definitions = if document.is_a?(Hash)
                      containers = %w[records services builtin_services].select { |key| document.key?(key) }
                      raise ArgumentError, "只能提供 records、services、builtin_services 中的一个数据容器" unless containers.one?
                      document.fetch(containers.first)
      else
                      document
      end
      entries = case definitions
      when Hash then definitions.map { |name, definition| [ name.to_s, definition ] }
      when Array
        definitions.map do |entry|
          raise ArgumentError, "服务记录必须是 Hash" unless entry.is_a?(Hash)
          [ entry.fetch("name").to_s, entry.except("name") ]
        end
      else raise ArgumentError, "需要 records、services 或 builtin_services"
      end
      duplicate = entries.map(&:first).tally.find { |_name, count| count > 1 }
      raise ArgumentError, "服务 #{duplicate.first.inspect} 重复定义" if duplicate
      entries
    end

    # 多条协议和端口定义作为普通数据保存在同一个服务中。
    def build_service(service_name, definition)
      rows = if definition.is_a?(Hash) && definition.key?("terms")
               unknown = definition.keys - [ "terms" ]
               raise ArgumentError, "terms 包装包含未知字段：#{unknown.map(&:inspect).join(', ')}" if unknown.any?
               definition.fetch("terms")
      else
               definition
      end
      rows = [ rows ] if rows.is_a?(Hash)
      raise ArgumentError, "必须包含非空 terms 数组" unless rows.is_a?(Array) && !rows.empty?

      Elements::ServiceObject.new(name: service_name, vendor: @vendor, device_id: @device_id,
                            terms: rows.map { |row| build_term(row) })
    rescue KeyError, TypeError, ArgumentError => error
      raise ArgumentError, "服务 #{service_name.inspect}：#{error.message}"
    end

    # 未知字段不能被丢弃，否则拼错的限制可能变成 Any。
    def build_term(row)
      raise ArgumentError, "term 必须是 Hash" unless row.is_a?(Hash)
      unknown = row.keys.reject { |key| (key.is_a?(String) || key.is_a?(Symbol)) && TERM_KEYS.include?(key.to_s) }
      raise ArgumentError, "term 包含未知字段：#{unknown.map(&:inspect).join(', ')}" if unknown.any?

      TERM_FIELDS.to_h do |field, aliases|
        values = row.select { |key, _| aliases.include?(key.to_s) }.values
        normalized = (values.empty? ? [ nil ] : values).map { |value| normalize_field(field, value) }
        unless normalized.all? { |value| equivalent_field?(field, normalized.first, value) }
          raise ArgumentError, "term 的 #{field} 别名取值冲突"
        end
        [ field, normalized.first ]
      end
    end

    # 表格端口列也承载 ICMP type/code，显式 Any 与缺省端口保持相同语义。
    def normalize_field(field, value)
      case field
      when :protocol
        text = value.to_s
        PROTOCOLS.fetch(text, text.downcase)
      when :source_port, :destination_port
        text = value.nil? ? Elements::Definition::ANY_PORTS : value.to_s.sub(/\A(?:type|code):/i, "")
        %w[Any any -].include?(text) ? Elements::Definition::ANY_PORTS : text
      when :timeout, :term, :uuid
        return if value.nil? || (field == :timeout && value == "-")
        unless value.is_a?(String) || value.is_a?(Numeric)
          raise ArgumentError, "#{field} must be text or a number"
        end
        value.to_s
      end
    end

    # 数字/文本、端口单点/等价范围等别名可共存，但不能互相覆盖限制。
    def equivalent_field?(field, left, right)
      return true if left == right
      case field
      when :source_port, :destination_port then IPAddr.ports(left) == IPAddr.ports(right)
      when :protocol then IPAddr.protocol_number(left) == IPAddr.protocol_number(right)
      else false
      end
    end
  end
end
