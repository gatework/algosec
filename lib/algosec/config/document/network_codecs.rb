# frozen_string_literal: true

module Algosec
  module Config
    class Document
      class RouteCodec < Codec
        FIELDS = %i[subnet kind source source_set source_interface destination_interface next_hop zone distance priority vrf destination_vrf extra_conf].freeze
        EDGES = { "sources" => [ :optional, %w[address_group negated_address_group] ], "destinations" => [ :optional, %w[address_group negated_address_group] ],
                  "services" => [ :optional, %w[service_group] ] }.freeze
        def attributes(object) = super.merge("source_set" => object.sources ? nil : Value.ranges(object.source_set))
        def edges(object) = { "sources" => object.sources, "destinations" => object.destinations, "services" => object.services }
        def build(attrs, edges, common, _context, _raw)
          Value.fail! if edges["sources"] && attrs["source_set"]
          Elements::Route.new(**common, **args(attrs).merge(source_set: Value.set(attrs["source_set"])),
            sources: edges["sources"], destinations: edges["destinations"], services: edges["services"])
        end
      end

      class InterfaceCodec < Codec
        FIELDS = %i[ipaddr mode zone vrf access_mode vlans seed_reachable aggregate ipv6_addresses].freeze
        EDGES = { "routes" => [ :array, %w[route] ], "vlan_interfaces" => [ :array, %w[interface] ] }.freeze
        def attributes(object) = super.merge("seed_reachable" => Value.ranges(object.seed_reachable))
        def edges(object) = { "routes" => object.routes.values, "vlan_interfaces" => object.vlan_interfaces.values }
        def build(attrs, edges, common, _context, _raw)
          values = args(attrs)
          reachable = Value.set(values.delete(:seed_reachable))
          object = Elements::Interface.new(**common, **values, reachable: reachable, routes: edges.fetch("routes"))
          edges.fetch("vlan_interfaces").each { |child| object.add_vlan(child) }
          object
        end
      end

      class ZoneCodec < Codec
        FIELDS = %i[acl_name vrf mode seed_reachable].freeze
        EDGES = { "interfaces" => [ :array, %w[interface] ] }.freeze
        def attributes(object) = super.merge("seed_reachable" => Value.ranges(object.seed_reachable))
        def edges(object) = { "interfaces" => object.interfaces.values }
        def build(attrs, edges, common, _context, _raw)
          values = args(attrs)
          reachable = Value.set(values.delete(:seed_reachable))
          Elements::Zone.new(**common, **values, reachable: reachable, interfaces: edges.fetch("interfaces"))
        end
      end

      class NatPoolCodec < Codec
        FIELDS = %i[ip zone interface direction port mode id alias_name arp_reply].freeze
        def build(attrs, _edges, common, _context, _raw) = Elements::NatPool.new(**common, **args(attrs))
      end
    end
  end
end
