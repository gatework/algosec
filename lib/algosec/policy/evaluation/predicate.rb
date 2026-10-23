# frozen_string_literal: true

require_relative "../evaluation"

module Algosec
  module Policy
    class Evaluation
      # 规则谓词独立投影已知与潜在区域；服务项保持协议及两端口的配对。
      class Predicate
        def initialize(snapshot, rule, at:, domains:, application:, source_user:, application_definitions:)
          @snapshot, @rule, @at, @domains = snapshot, rule, at, domains
          @application, @source_user, @application_definitions = application, source_user, application_definitions
        end

        def partitions(remaining)
          if @rule.unparsed_commands?
            return [ partition(remaining, :unknown, "规则包含未解析命令") ]
          end
          return [] if context_match == false
          return [] if schedule_known? && @rule.status_known? && !@rule.active?(at: @at)

          remaining.map(&:family).uniq.flat_map do |family|
            family_traffic = TrafficSet.new(remaining.select { |region| region.family == family }, limit: remaining.limit)
            addresses = [ :sources, :destinations ].zip([ :source, :destination ]).map do |dimension, side|
              @rule.public_send(dimension).address_projection(at: @at, family: family, **@domains.fetch(side, {}))
            end
            conditions_known = @rule.status_known? && schedule_known? && context_match == true &&
              !@snapshot.behavior.unresolved_network_conditions?(@rule) && @rule.security_profiles.empty? &&
              addresses.all? { |projection| projection[:resolution]["complete"] }
            possible, proven = service_sets(family, addresses, remaining.limit)
            potential_hit = family_traffic & possible
            next [] if potential_hit.empty?
            known_hit = conditions_known ? family_traffic & proven : TrafficSet.new([], limit: remaining.limit)
            unknown_hit = potential_hit - known_hit
            pieces = []
            unless known_hit.empty?
              conditional = addresses.any? { |projection| projection[:resolution]["conditional"] }
              status = !@rule.action_known? ? :unknown : (conditional ? :conditional : :matched)
              reason = if !@rule.action_known? then "未知规则动作"
              elsif conditional then "依赖当前 DNS 映射，尚未验证设备学习状态"
              end
              pieces << partition(known_hit, status, reason)
            end
            pieces << partition(unknown_hit, :unknown, "地址、服务、状态、时间或应用上下文尚未完整解析") unless unknown_hit.empty?
            pieces
          end
        end

        private

        def partition(traffic, status, reason)
          Partition.new(traffic_set: traffic, action: status == :unknown ? nil : @rule.action,
            status: status, rule: @rule, reason: reason, default: false)
        end

        def schedule_known?
          (!@rule.schedule_name || @rule.schedule) && (!@rule.schedule || @rule.schedule.resolved?)
        end

        def context_match
          tests = [ names_match(@rule.applications, @application), names_match(@rule.source_users, @source_user) ]
          tests << nil if @rule.application_check
          return false if tests.include?(false)
          tests.all?(true) ? true : nil
        end

        def names_match(names, value)
          return true if names.empty? || names == [ "any" ]
          return unless value
          names.include?(value)
        end

        def service_sets(family, addresses, limit)
          dimensions = { source_addresses: address_values(addresses[0], family), destination_addresses: address_values(addresses[1], family) }
          service = @rule.service_selection == :application_default ? @application_definitions[@application] : @rule.services
          possible, proven = [], []
          budget = TrafficSet::Budget.new(limit)
          if !service || (service.is_a?(Elements::ServiceGroup) && !service.resolved?)
            possible << TrafficSet::Region.new(family: family, **dimensions, protocols: Set.new(0..255), source_ports: Set.new(0..65535), destination_ports: Set.new(0..65535))
          else
            service_terms(service).each do |term|
              protocol = IPAddr.protocol_number(term[:protocol])
              wildcard = protocol.zero? && %w[any ip all].include?(term[:protocol].downcase)
              # 旧服务编码的数值零没有足够声明证据；不得擅自当作实际协议零或任意协议。
              ambiguous_protocol = protocol.zero? && !wildcard
              icmp_restricted = Elements::ServiceObject.icmp_type_restricted?(protocol: term[:protocol], destination_port: term[:destination_port])
              region = TrafficSet::Region.new(family: family, **dimensions,
                protocols: Set.new((wildcard || ambiguous_protocol) ? (0..255) : (protocol..protocol)),
                source_ports: IPAddr.ports(term[:source_port] || Elements::Definition::ANY_PORTS),
                destination_ports: IPAddr.icmp?(term[:protocol]) ? Set.new(0..65535) : IPAddr.ports(term[:destination_port]))
              budget.append(possible, region)
              budget.append(proven, region) unless ambiguous_protocol || icmp_restricted || term[:uuid] || term[:timeout]
            end
          end
          [ TrafficSet.new(possible, limit: limit), TrafficSet.new(proven, limit: limit) ]
        end

        def service_terms(service, &block)
          return enum_for(__method__, service) unless block
          if service.is_a?(Elements::ServiceObject)
            service.each(&block)
          else
            service.unique_leaves { |leaf| leaf.each(&block) }
          end
        end

        def address_values(projection, family)
          return projection[:set] if projection[:resolution]["complete"]
          Set.new(0..(family == :ipv4 ? ::IPAddr::IN4MASK : ::IPAddr::IN6MASK))
        end
      end
    end
  end
end
