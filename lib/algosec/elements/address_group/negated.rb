# frozen_string_literal: true

require_relative "../address_group"

module Algosec
  module Elements
    class AddressGroup
      # 取反改变匹配范围，保留成员图用于引用计数和配置回溯。
      class Negated < AddressGroup
        def transform_address_projection(projection, family:)
          resolution = projection.fetch(:resolution)
          if resolution["conditional"]
            resolution["complete"] = false
            resolution["errors"] << "negated_dynamic_address"
          end
          universe = Set.new(0..(family == :ipv6 ? ::IPAddr::IN6MASK : ::IPAddr::IN4MASK))
          set = resolution["complete"] ? universe - projection.fetch(:set) : Set.new
          leaves = set.map do |range|
            if family == :ipv6
              first, last = [ range.begin, range.end ].map { |value| ::IPAddr.new(value, Socket::AF_INET6).to_s }
              { "type" => "ipv6", "value" => first == last ? first : "#{first}-#{last}" }
            else
              value = IPAddr.format_range(range)
              { "type" => value.include?("/") ? "subnet" : (value.include?("-") ? "iprange" : "host"), "value" => value }
            end
          end
          projection.merge(set: set, member: Address::Expansion.normalize_member(leaves))
        end
      end
    end
  end
end
