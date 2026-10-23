# frozen_string_literal: true

module Algosec
  module Elements
    module Address
      module Expansion
        # 单次查询或报告共享展开结果；固定时间和 DNS 证据，不跨查询缓存可变引用图。
        class Projection
          def initialize(at:, domain: nil, answer: nil, family: nil)
            unless [ nil, :ipv4, :ipv6 ].include?(family)
              raise ArgumentError, "Address family must be ipv4 or ipv6"
            end
            @at, @domain, @answer, @family = at, domain, answer, family
            @memo, @visiting, @cyclic = {}, {}, {}
          end

          def call(object)
            if @visiting[object.object_id]
              @visiting.each_key { |id| @cyclic[id] = true }
              return { member: [], set: Set.new, resolution: { "errors" => [ "circular_reference: #{object.name}" ], "dns" => {} } }
            end
            return @memo.fetch(object.object_id) if @memo.key?(object.object_id)

            @visiting[object.object_id] = true
            leaves, errors, dns, intervals = [], [], {}, []
            conditional = false
            if object.is_a?(AddressObject)
              errors.concat(object.unresolved)
              object.direct_member.each do |leaf|
                leaves << leaf
                case leaf.fetch("type")
                when "any"
                  maximum = @family == :ipv6 ? ::IPAddr::IN6MASK : ::IPAddr::IN4MASK
                  intervals << (0..maximum)
                  leaves[-1] = @family == :ipv6 ? { "type" => "ipv6", "value" => "::/0" } : { "type" => "subnet", "value" => "0.0.0.0/0" }
                when "subnet", "host", "iprange"
                  intervals.concat(IPAddr.parse(leaf.fetch("value")).ranges) unless @family == :ipv6
                when "domain"
                  domain = leaf.fetch("value")
                  evidence = if @domain && DomainName.matches?(domain, @domain)
                    @answer
                  else
                    object.dns_answers[domain]
                  end
                  dns[domain] = evidence if evidence
                  if evidence && evidence["status"] == "resolved" && Time.iso8601(evidence.fetch("expires_at")) > @at
                    evidence.fetch("addresses").each do |ip|
                      ipv6 = ::IPAddr.new(ip).ipv6?
                      next if @family == :ipv6 && !ipv6
                      next if @family == :ipv4 && ipv6
                      if ipv6 && @family.nil?
                        errors << "ipv6_requires_family_query: #{ip}"
                      else
                        intervals.concat((ipv6 ? IPv6.parse(ip) : IPAddr.parse(ip)).ranges)
                      end
                    end
                  else
                    errors << "unresolved_domain: #{domain}"
                  end
                when "ipv6"
                  if @family == :ipv6
                    intervals.concat(IPv6.parse(leaf.fetch("value")).ranges)
                  elsif @family.nil?
                    errors << "ipv6_requires_family_query: #{leaf.fetch('value')}"
                  end
                else
                  errors << "unsupported_address: #{leaf.fetch('value')}"
                end
              end
              references = object.references
            else
              references = object.members
            end
            references.each do |name, child|
              unless child
                errors << "missing_reference: #{object.name} -> #{name}"
                next
              end
              projection = call(child)
              leaves.concat(projection[:member])
              intervals.concat(projection[:set].ranges)
              errors.concat(projection[:resolution]["errors"])
              dns.merge!(projection[:resolution]["dns"])
              conditional ||= projection[:resolution]["conditional"]
            end
            if object.is_a?(AddressObject) && object.excluded_member.any?
              excluded = Set.new(*object.excluded_member.flat_map { |leaf| IPAddr.parse(leaf.fetch("value")).ranges })
              intervals = (Set.new(*intervals) - excluded).ranges unless @family == :ipv6
              concrete, other = leaves.partition { |leaf| %w[host subnet iprange].include?(leaf["type"]) }
              static = Set.new(*concrete.flat_map { |leaf| IPAddr.parse(leaf.fetch("value")).ranges }) - excluded
              leaves = static.ranges.map { |range| { "type" => "iprange", "value" => "#{IPAddr.from_i(range.begin)}-#{IPAddr.from_i(range.end)}" } } + other
              errors << "conditional_exclusion: #{object.name}" if other.any? { |leaf| leaf["type"] == "domain" }
            end
            @visiting.delete(object.object_id)
            projection = {
              member: Address::Expansion.normalize_member(leaves), set: Set.new(*intervals),
              resolution: { "complete" => errors.empty?, "conditional" => conditional || leaves.any? { |leaf| leaf["type"] == "domain" },
                            "errors" => errors.uniq, "dns" => dns }
            }
            projection = object.transform_address_projection(projection, family: @family)
            # 环诊断会截断当前路径，不能把该路径的部分结果复用给其他根。
            @memo[object.object_id] = projection unless @cyclic[object.object_id]
            projection
          end
        end
      end
    end
  end
end
