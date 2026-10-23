# frozen_string_literal: true

require "json"
require "strscan"
require_relative "../../ipaddr"

module Algosec
  module Elements
    module Service
      # 服务表达式与完整服务项之间的转换，保留源端口、ICMP 条件及元数据。
      module Expressions
        module_function

        def format(terms)
          terms.map do |item|
            term = item.transform_keys(&:to_sym)
            if IPAddr.protocol_number(term.fetch(:protocol)).zero? &&
               term[:destination_port] == "0-65535" && [ nil, "0-65535" ].include?(term[:source_port]) &&
               %i[term uuid timeout].all? { |key| term[key].nil? }
              next "any"
            end
            icmp = IPAddr.icmp?(term.fetch(:protocol))
            expression = icmp ? "#{term.fetch(:protocol)} type=#{term.fetch(:destination_port)}" : "#{term.fetch(:protocol)}/#{term.fetch(:destination_port)}"
            source = term[:source_port]
            expression += " #{icmp ? 'code' : 'source-port'}=#{source}" if source && source != "0-65535"
            %i[term uuid timeout].each do |key|
              value = term[key]
              next if value.nil?
              encoded = value.match?(/\A[\w.:-]+\z/) ? value : JSON.generate(value)
              expression += " #{key}=#{encoded}"
            end
            expression
          end
        end

        # 带空格或引号的原始名称采用 JSON 字符串转义，确保限制条件可以无损往返。
        def parse(values)
          validate_expressions!(values).map do |value|
            validate_expression!(value)
            scanner = StringScanner.new(value)
            head = scanner.scan(/[^\s]+/)
            protocol, destination = head.split("/", -1)
            protocol, destination = "any", "0-65535" if head.casecmp?("any")
            raise ArgumentError, "Invalid service expression" if head.count("/") > 1
            term = { protocol: protocol, destination_port: destination, source_port: "0-65535" }
            seen = []
            until scanner.eos?
              raise ArgumentError, "Invalid service qualifier" unless scanner.scan(/ +/)
              key = scanner.scan(/(?:source-port|type|code|term|uuid|timeout)=/)&.delete_suffix("=")
              raise ArgumentError, "Unknown or repeated service qualifier" if key.nil? || seen.include?(key)
              seen << key
              raw = scanner.scan(/"(?:[^"\\]|\\.)*"|[^\s"]+/)
              raise ArgumentError, "Missing service qualifier value" unless raw
              parsed = raw.start_with?('"') ? JSON.parse(raw) : raw
              attribute = { "source-port" => :source_port, "code" => :source_port, "type" => :destination_port }.fetch(key, key.to_sym)
              term[attribute] = parsed
            end
            icmp = IPAddr.icmp?(protocol)
            valid = icmp ? destination.nil? && seen.include?("type") && !seen.include?("source-port") : destination && !seen.intersect?(%w[type code])
            # 保留既有数据库及 HTTP 表达式支持的协议 58 端口形式。
            valid ||= IPAddr.protocol_number(protocol) == IPAddr::ICMPV6 && destination && !seen.intersect?(%w[type code])
            raise ArgumentError, "Invalid protocol qualifiers" unless valid
            term
          end
        rescue JSON::ParserError => error
          raise ArgumentError, error.message
        end

        def validate_expressions!(values)
          raise ArgumentError, "Members must be an array of expressions" unless values.is_a?(Array)
          values
        end

        def validate_expression!(value)
          raise ArgumentError, "Member expression must be nonempty text" unless value.is_a?(String) && !value.empty? && value == value.strip
        end
        private_class_method :validate_expressions!, :validate_expression!
      end
    end
  end
end
