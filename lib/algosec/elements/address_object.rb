# frozen_string_literal: true

require "time"
require_relative "group"
require_relative "address/expansion"
require_relative "../ipv6"
require_relative "../domain_name"

module Algosec
  module Elements
    # 地址保存规范叶子和引用图，计算结果由共用投影实时派生。
    class AddressObject < Base
      ELEMENT_TYPE = :address_object
      include Address::Expansion
      TYPES = %w[subnet iprange host domain ipv6 any].freeze
      attr_reader :zone, :dns_answers, :unresolved, :excluded_member

      def initialize(name:, member: [], zone: nil, references: [], unresolved: [], excluded_member: [], **context)
        @zone = text(zone, optional: true)
        @direct_member, @references, @dns_answers = [], {}, {}
        @dns_error_presence = {}.freeze
        raise ArgumentError, "Unresolved address reasons must be an array" unless unresolved.is_a?(Array)
        @unresolved = unresolved.map { |reason| text(reason) }.freeze
        raise ArgumentError, "AddressObject member must be an array" unless member.is_a?(Array)
        member.each { |leaf| add(**leaf.transform_keys(&:to_sym)) }
        super(name: name, **context)
        raise ArgumentError, "Excluded members must be an array" unless excluded_member.is_a?(Array)
        @excluded_member = if excluded_member.empty?
          [].freeze
        else
          leaves = AddressObject.new(name: name, member: excluded_member, **context).direct_member
          unless leaves.all? { |leaf| %w[host subnet iprange].include?(leaf["type"]) }
            raise ArgumentError, "Excluded members must be concrete IPv4 addresses"
          end
          Address::Expansion.normalize_member(leaves)
        end
        raise ArgumentError, "References must be an array" unless references.is_a?(Array)
        references.each { |reference| add_reference(reference) }
      end

      # 返回直接叶子；公共 member 则包含递归展开后的全部叶子。
      def direct_member = @direct_member.dup.freeze

      def references = @references.dup.freeze

      def dependencies = @references.values.compact.freeze

      # 登记规范成员并先完成校验，失败时不改变现有成员。
      def add(type:, value:)
        type, value = text(type), text(value)
        raise ArgumentError, "Unknown address member: #{type}" unless TYPES.include?(type)
        value = case type
        when "any"
                  raise ArgumentError, "Any address member must use the value any" unless value == "any"
                  value
        when "subnet" then IPAddr.network_cidr(value)
        when "host" then IPAddr.from_i(IPAddr.to_i(value))
        when "iprange"
                  endpoints = value.strip.split(/\s*-\s*|\s+/, -1)
                  raise ArgumentError, "An address range needs two endpoints" unless endpoints.size == 2
                  low, high = endpoints.map { |ip| IPAddr.to_i(ip) }
                  raise ArgumentError, "AddressObject range is reversed" if low > high
                  endpoints.map { |ip| IPAddr.from_i(IPAddr.to_i(ip)) }.join("-")
        when "ipv6"
                  IPv6.normalize(value)
        else
                  value
        end
        @direct_member << { "type" => type.freeze, "value" => value.freeze }.freeze
        self
      end

      # 对象引用始终使用名称，便于统计和按配置重新装配。
      def add_reference(name)
        @references[text(name)] ||= nil
        self
      end

      # 先验证候选引用，全部通过后才提交；缺失引用不能退化为 any。
      def resolve!(strict: true)
        raise ArgumentError, "Strict must be true or false" unless strict == true || strict == false
        raise ArgumentError, "A reference resolver is required" unless block_given?
        candidate = @references.to_h do |key, object|
          resolved = object || yield(key)
          raise Group::UnresolvedReference, "#{name} -> #{key}" if strict && resolved.nil?
          validate_reference!(resolved) if resolved
          [ key, resolved ]
        end
        return self if sealed? && candidate == @references
        @references = candidate
        self
      end

      # 保存本次 DNS 结果；解析器与查询管线注入解析服务，元素本身不联网。
      def resolve_domains!(resolver)
        raise FrozenError, "Published address cannot refresh DNS answers" if sealed?
        answers = @direct_member.select { |leaf| leaf["type"] == "domain" && !DomainName.wildcard?(leaf["value"]) }.to_h do |leaf|
          domain = leaf.fetch("value")
          [ domain, immutable_metadata(resolver.resolve(domain)) ]
        end.freeze
        @dns_answers, @dns_error_presence = answers, {}.freeze
        self
      end

      def dns_error_key?(domain)
        @dns_error_presence.key?(domain) || dns_answers.fetch(domain).key?("error")
      end

      def dns_error_present?(domain)
        @dns_error_presence.fetch(domain) { !dns_answers.fetch(domain)["error"].nil? }
      end

      def dns_error(domain)
        answer = dns_answers.fetch(domain)
        if dns_error_present?(domain) && !answer.key?("error")
          raise Config::SourceUnavailable, "DNS error text is unavailable"
        end
        answer["error"]
      end

      # 持久化证据只经声明校验恢复，不调用解析器或 DNS 网络服务。
      def restore_dns_answers!(records, errors: {})
        raise FrozenError, "Published address cannot restore DNS answers" if sealed?
        raise ArgumentError, "DNS evidence must be a mapping" unless records.is_a?(Hash) && errors.is_a?(Hash)
        domains = direct_member.select { |leaf| leaf["type"] == "domain" && !DomainName.wildcard?(leaf["value"]) }.map { |leaf| leaf["value"] }
        presence = {}
        answers = records.to_h do |domain, record|
          unless domains.include?(domain) && record.is_a?(Hash) && record.keys.sort == %w[error_key error_present evidence]
            raise ArgumentError, "Invalid DNS evidence declaration"
          end
          key, present, answer = record.values_at("error_key", "error_present", "evidence")
          unless [ true, false ].include?(key) && [ true, false ].include?(present) && (!present || key)
            raise ArgumentError, "Invalid DNS error presence"
          end
          validate_dns_evidence!(answer)
          restored = answer.dup
          if key
            presence[domain] = present
            if errors.key?(domain)
              error = errors.fetch(domain)
              raise ArgumentError, "Invalid DNS error text" unless present ? error.is_a?(String) : error.nil?
              restored["error"] = error
            elsif !present
              restored["error"] = nil
            end
          end
          [ domain, immutable_metadata(restored) ]
        end
        raise ArgumentError, "Unexpected DNS error details" unless (errors.keys - records.select { |_domain, record| record["error_key"] }.keys).empty?
        @dns_answers, @dns_error_presence = answers.freeze, presence.freeze
        self
      end

      protected

      def seal_owned_values!
        @direct_member.freeze
        @references.freeze
        @dns_answers.freeze
        super
      end

      def identity_parts = element_definition.address_identity(self)

      private

      # 历史注入器可省略时间/来源字段，已有字段不能互相矛盾。
      def validate_dns_evidence!(answer)
        allowed = %w[status addresses resolved_at expires_at source]
        unless answer.is_a?(Hash) && (answer.keys - allowed).empty? && %w[resolved unresolved unsupported].include?(answer["status"]) && answer["addresses"].is_a?(Array) && answer.key?("expires_at")
          raise ArgumentError, "Invalid DNS evidence"
        end
        addresses = answer.fetch("addresses")
        unless addresses.all? { |ip| ip.is_a?(String) && !ip.match?(/[\/%]/) && ::IPAddr.new(ip).to_s == ip } && addresses.uniq == addresses
          raise ArgumentError, "Invalid DNS addresses"
        end
        raise ArgumentError, "Inconsistent DNS status" unless (answer["status"] == "resolved") == addresses.any?
        times = %w[resolved_at expires_at].map do |field|
          next unless answer.key?(field)
          raise ArgumentError, "Invalid DNS time" unless answer[field].is_a?(String)
          Time.iso8601(answer[field])
        end
        raise ArgumentError, "Reversed DNS lifetime" if times.all? && times.last < times.first
        raise ArgumentError, "Invalid DNS source" if answer.key?("source") && !answer["source"].is_a?(Hash)
      end

      def validate_reference!(value)
        unless value.is_a?(AddressObject) || value.is_a?(AddressGroup)
          raise ArgumentError, "AddressObject reference has the wrong type"
        end
        same_device!(value)
        raise Group::CircularReference, "#{name} -> #{value.name} -> #{name}" if value.depends_on?(self)
      end
    end
  end
end
