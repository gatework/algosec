# frozen_string_literal: true

module Algosec
  module Elements
    module Service
      # 服务投影保留完整服务项；range 只是协议和目的端口索引，不替代匹配条件。
      module Expansion
        def service_projection
          terms, intervals, errors, protocols = [], [], [], {}
          visited = {}
          walk = lambda do |object|
            return if visited[object.object_id]
            visited[object.object_id] = true
            if object.is_a?(ServiceObject)
              terms.concat(object.terms)
              intervals.concat(object.set.ranges)
            else
              protocols[object.name] = object.protocol if object.protocol
              object.members.each do |name, child|
                child ? walk.call(child) : errors << "missing_reference: #{object.name} -> #{name}"
              end
            end
          end
          walk.call(self)
          conditional = terms.any? do |term|
            IPAddr.ports(term[:source_port] || Definition::ANY_PORTS) != IPAddr.ports(Definition::ANY_PORTS) ||
              term[:uuid] || term[:timeout] ||
              ServiceObject.icmp_type_restricted?(protocol: term[:protocol], destination_port: term[:destination_port])
          end
          { member: normalized_service_member(terms), range: Set.new(*intervals).ranges.map { |r| [ r.begin, r.end ] },
            resolution: { "complete" => errors.empty?, "conditional" => conditional,
                          "errors" => errors.uniq, "group_protocols" => protocols } }
        end

        private

        # 仅合并其余条件完全相同的目的端口，避免把不同源端口组合扩成矩形。
        def normalized_service_member(terms)
          normalized = terms.map do |term|
            term.merge(source_port: port_text(IPAddr.ports(term[:source_port] || Definition::ANY_PORTS).ranges.first))
          end
          normalized.group_by { |term| term.except(:destination_port) }.flat_map do |conditions, items|
            ports = Set.new(*items.flat_map { |term| IPAddr.ports(term.fetch(:destination_port)).ranges })
            ports.map { |range| conditions.merge(destination_port: port_text(range)) }
          end
        end

        def port_text(range)
          range.begin == range.end ? range.begin.to_s : "#{range.begin}-#{range.end}"
        end
      end
    end
  end
end
