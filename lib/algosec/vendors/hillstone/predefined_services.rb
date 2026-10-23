# frozen_string_literal: true

require_relative "../../elements"

module Algosec
  module Vendors
    module Hillstone
      # 导入捕获的 `show service predefined` 表格，包括续行和分页标记清理。
      # 该过程不建立连接，也不访问数据库。
      class PredefinedServices
        PROTOCOLS = { "GRE" => "47", "IPv4" => "4", "ESP" => "50", "AH" => "51",
                      "IPv6" => "41", "IPv6-ICMP" => "58", "OSPFIGP" => "89" }.freeze

        attr_reader :services, :records, :truncated_names

        # 读取服务表后构造 Service 及其内嵌定义，截断名称只保留在诊断信息中。
        def initialize(text, device_id: nil)
          @records = read_table(text)
          @truncated_names = records.keys.select { |name| name.end_with?("~") }.freeze
          @services = records.except(*truncated_names).to_h do |name, rows|
            terms = rows.map do |row|
              protocol = PROTOCOLS.fetch(row[:protocol], row[:protocol].downcase)
              { protocol: protocol, destination_port: value(row[:destination]), source_port: value(row[:source]),
                timeout: (row[:timeout] == "-") ? nil : row[:timeout] }
            end
            [ name, Algosec::Elements::ServiceObject.new(name: name, vendor: :hillstone, device_id: device_id, terms: terms) ]
          end.freeze
        end

        private

        # 跨分页和续行读取表格，并校验声明数量、行结构和重复名称。
        def read_table(text)
          records = {}
          active = false
          expected = name = nil
          text.each_line.with_index(1) do |raw, number|
            line = raw.sub(/\A\s*--More--[ \x00\x08]*/, "").delete("\x00\x08\r").strip
            if /\AName\s+Protocol\s+Dst-Port\/Type\s+Src-Port\/Code\s+Timeout\z/.match?(line)
              active = true
              next
            end
            next unless active
            break if /\A\S+[>#](?:\s|\z)/.match?(line)
            next if line.empty?
            if (count = /\ATotal configured:\s*(\d+)\z/.match(line))
              expected = count[1].to_i
              next
            end
            fields = line.split
            if fields.size == 5
              name = fields.shift
              raise ArgumentError, "Duplicate predefined service at line #{number}" if records.key?(name)
              records[name] = []
            end
            unless name && fields.size == 4
              raise ArgumentError, "Invalid predefined service table row at line #{number}"
            end
            records.fetch(name) << %i[protocol destination source timeout].zip(fields.map(&:freeze)).to_h.freeze
          end
          unless active && expected && records.size == expected
            raise ArgumentError, "Incomplete predefined service table: expected #{expected.inspect}, found #{records.size}"
          end
          records.each_value(&:freeze).freeze
        end

        # 表格的这两列也用于 ICMP 类型和编码。保留限制：PING（8/0）
        # 不能被扩大为不受限的 ICMP（Any/Any）。
        def value(text)
          text = text.sub(/\A(?:type|code):/i, "")
          %w[Any -].include?(text) ? Algosec::Elements::Definition::ANY_PORTS : text
        end
      end
    end
  end
end
