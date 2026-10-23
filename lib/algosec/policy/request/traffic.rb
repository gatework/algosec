# frozen_string_literal: true

require_relative "../traffic_set"
require_relative "../ranges"

module Algosec
  module Policy
    class Request
      # 请求地址/服务映射只在边界转换；缺口始终保留五维配对。
      module Traffic
        module_function

        def from_maps(maps)
          sources, destinations = %i[sources destinations].map { |dimension| Ranges.addresses(maps.fetch(dimension).keys) }
          TrafficSet.new(maps.fetch(:services).keys.map do |value|
            protocol, ports = Ranges.normalize_service(value).split("/", 2)
            number = IPAddr.protocol_number(protocol)
            { family: :ipv4, source_addresses: sources, destination_addresses: destinations,
              protocols: %w[any ip all].include?(protocol) ? Set.new(0..255) : Set.new(number..number),
              source_ports: Set.new(0..65535), destination_ports: [ 6, 17 ].include?(number) ? IPAddr.ports(ports) : Set.new(0..65535) }
          end)
        end

        def slices(traffic, maps)
          traffic.map do |region|
            unless region.family == :ipv4 && region.source_ports == Set.new(0..65535)
              raise Error.new("生成器无法精确表达地址族或源端口缺口", code: :unsupported_gap)
            end
            source = address_map(region.source_addresses, maps.fetch(:sources))
            destination = address_map(region.destination_addresses, maps.fetch(:destinations))
            services = service_map(region, maps.fetch(:services))
            { sources: source, destinations: destination, services: services }
          end
        end

        def address_map(set, original)
          original.each_with_object({}) do |(value, metadata), output|
            shared = set & IPAddr.parse(value)
            IPAddr.cidrs(shared).each { |address, prefix| output["#{address}/#{prefix}"] = metadata }
          end
        end

        def service_map(region, original)
          original.each_with_object({}) do |(value, metadata), output|
            maps = { sources: { "0.0.0.0" => {} }, destinations: { "0.0.0.0" => {} }, services: { value => metadata } }
            requested = from_maps(maps).regions.first
            protocols = region.protocols & requested.protocols
            ports = region.destination_ports & requested.destination_ports
            next if protocols.empty? || ports.empty?
            if protocols == Set.new(0..255) && ports == Set.new(0..65535)
              output["any"] = metadata
              next
            end
            protocols.each do |range|
              range.each do |number|
                unless [ 6, 17 ].include?(number)
                  raise Error.new("生成器无法精确表达协议缺口", code: :unsupported_gap)
                end
                ports.each do |port_range|
                  port = port_range.begin == port_range.end ? port_range.begin.to_s : "#{port_range.begin}-#{port_range.end}"
                  output["#{number == 6 ? 'tcp' : 'udp'}/#{port}"] = metadata
                end
              end
            end
          end
        end
      end
    end
  end
end
