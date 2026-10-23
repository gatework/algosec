# frozen_string_literal: true

require "algosec/policy"

module PolicyFactory
  P = Algosec::Policy
  E = Algosec::Elements
  VENDORS = Algosec::Vendors.names(:policy)

  def context(vendor, device_id: 1) = { vendor: vendor, device_id: device_id }

  def rule(vendor, name: "r1", source: "10.0.0.0/24", destination: "192.0.2.1/32", services: [ "tcp/443" ], **attributes)
    common = { name: name, native_rule_id: name, from_zones: "inside", to_zones: "outside",
               action: (vendor == :fortinet) ? "accept" : "permit" }
    common.merge!(rule_set: "inside_acl", rule_number: name.delete_prefix("r").to_i) if vendor == :asa
    common[:rule_set] = "objects" if vendor == :h3c
    result = E::SecurityRule.new(**context(vendor), **common, **attributes)
    { sources: source, destinations: destination }.each do |dimension, value|
      ip, mask = value.split("/")
      address = E::AddressObject.new(**context(vendor), name: dimension.to_s, zone: (dimension == :sources) ? "inside" : "outside", member: [ { type: "subnet", value: "#{ip}/#{mask || 32}" } ])
      result.public_send(dimension).add(address.name, address)
    end
    services.each_with_index do |value, index|
      protocol, port = value.split("/")
      service = E::ServiceObject.new(**context(vendor), name: "service#{index}", protocol: protocol, source_port: "0-65535", destination_port: port || "0-65535")
      result.services.add(service.name, service)
    end
    result
  end

  def snapshot(vendor, objects = [], version: nil, device_id: 1, settings: {}, resolve_references: true)
    zones = %w[inside outside].map do |name|
      interface = E::Interface.new(name: name, zone: name, **context(vendor, device_id: device_id))
      E::Zone.new(name: name, vrf: "default", acl_name: "inside_acl", interfaces: [ interface ], **context(vendor, device_id: device_id))
    end
    P::Snapshot.new(**context(vendor, device_id: device_id), version: version, settings: settings, resolve_references: resolve_references,
                    catalog: E::Catalog.new(zones + objects, **context(vendor, device_id: device_id)))
  end

  def group(vendor, sources: [ "10.0.0.1" ], destinations: [ "192.0.2.1" ], services: [ "tcp/443" ], **attributes)
    request = P::Request.new(sources: sources, destinations: destinations, services: services)
    { device_id: 1, device_name: "fw", vendor: vendor, from_zone: "inside", to_zone: "outside",
      nat_mode: 0, hit: :source, sources: request.sources, destinations: request.destinations,
      services: request.services }.merge(attributes)
  end

  def networks(vendor, nat_mode: 0, address_type: :main, device_id: 1, protected_side: :source)
    base = { device_id: device_id, device_name: "fw#{device_id}", vendor: vendor, nat_mode: nat_mode }
    [ base.merge(zone: "inside", protected: protected_side == :source, address_type: address_type, address: "10.0.0.0/8"),
     base.merge(zone: "outside", protected: protected_side == :destination, address_type: :main, address: "0.0.0.0/0") ]
  end
end
