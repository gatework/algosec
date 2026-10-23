# frozen_string_literal: true

require_relative "../domain_name"
require_relative "traffic_matcher"

module Algosec
  module Policy
    # 精确域名按当前 DNS 答案逐个查询，不枚举泛域名，也不推断反向 DNS。
    class DomainQuery
      MAX_COMBINATIONS = 256
      Report = Data.define(:status, :evidence, :matches, :reason)

      def initialize(snapshot, resolver:, at: Time.current)
        @snapshot, @resolver, @at = snapshot, resolver, at
      end

      # 名称查询只返回配置引用，是否放行仍需五元组、区域、顺序和时间判断。
      def rules(domain:, direction: :destinations)
        raise ArgumentError, "direction must be sources or destinations" unless %i[sources destinations].include?(direction)
        unless DomainName.exact?(domain) || DomainName.wildcard?(domain)
          raise ArgumentError, "Expected an exact domain or a leading wildcard domain"
        end
        @snapshot.elements(Elements::SecurityRule).select do |rule|
          rule.public_send(direction).member.any? do |leaf|
            leaf["type"] == "domain" &&
              (DomainName.normalize(leaf["value"]) == DomainName.normalize(domain) || DomainName.matches?(leaf["value"], domain))
          end
        end
      end

      # 保留每个 IP 组合的结论；多答案中任一失败不能被单个放行结果掩盖。
      def perform(source:, destination:, **traffic)
        unless [ source, destination ].all? { |value| DomainName.exact?(value) || ipv4?(value) }
          raise ArgumentError, "Traffic queries require exact domains or single IPv4 addresses"
        end
        unless @snapshot.complete?
          return Report.new(status: :unknown, evidence: {}, matches: [], reason: "配置解析不完整")
        end
        evidence, domains, endpoints = {}, {}, {}
        { source: source, destination: destination }.each do |side, value|
          if DomainName.exact?(value) && !ipv4?(value)
            name = DomainName.normalize(value)
            answer = @resolver.resolve(name)
            evidence[side] = { domain: name, answer: answer }
            unless answer["status"] == "resolved" && Time.iso8601(answer.fetch("expires_at")) > [ @at, Time.current ].max
              return Report.new(status: :unknown, evidence: evidence, matches: [], reason: "DNS 未解析或证据已过期")
            end
            domains[side] = { domain: name, answer: answer }
            endpoints[side] = answer.fetch("addresses")
          else
            endpoints[side] = [ value ]
          end
        end
        if endpoints[:source].size * endpoints[:destination].size > MAX_COMBINATIONS
          return Report.new(status: :unknown, evidence: evidence, matches: [], reason: "DNS 地址组合超过查询上限")
        end
        query_time = [ @at, Time.current ].max
        if evidence.values.any? { |entry| Time.iso8601(entry[:answer].fetch("expires_at")) <= query_time }
          return Report.new(status: :unknown, evidence: evidence, matches: [], reason: "DNS 证据在查询准备期间已过期")
        end
        matcher = TrafficMatcher.new(@snapshot, at: query_time, domains: domains)
        matches = endpoints[:source].product(endpoints[:destination]).map do |src, dst|
          { source: src, destination: dst, match: matcher.perform(source: src, destination: dst, **traffic) }
        end
        outcomes = matches.map { |entry| [ entry[:match].status, entry[:match].action ] }.uniq
        status = outcomes.size == 1 ? outcomes.first.first : :mixed
        Report.new(status: status, evidence: evidence, matches: matches, reason: nil)
      end

      private

      def ipv4?(value)
        IPAddr.parse(value).cardinality == 1
      rescue ArgumentError
        false
      end
    end
  end
end
