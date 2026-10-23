# frozen_string_literal: true

module Algosec
  module Config
    class Document
      class StaticNatCodec < Codec
        FIELDS = %i[mapped_ip real_ip real_set mapped_set destination_set mappings real_zone mapped_zone interface rule_set acl_name acl_number
          mask id nat_order interfaces declared_disabled log_enabled source_nat_enabled].freeze
        EDGES = { "match_rule" => [ :optional, %w[security_rule] ] }.freeze
        def attributes(object)
          super.merge("real_set" => object.mappings ? nil : Value.ranges(object.real_set),
            "mapped_set" => object.mappings ? nil : Value.ranges(object.mapped_set), "destination_set" => Value.ranges(object.destination_set),
            "mappings" => object.mappings&.map { |pair| pair.map { |range| { "first" => range.begin, "last" => range.end } } })
        end
        def edges(object) = { "match_rule" => object.match_rule }
        def build(attrs, edges, common, _context, _raw)
          values = args(attrs)
          values[:disabled] = values.delete(:declared_disabled)
          %i[real_set mapped_set destination_set].each { |key| values[key] = Value.set(values[key]) }
          if values[:mappings]
            Value.fail! unless values[:mappings].is_a?(Array)
            values[:mappings] = values[:mappings].map do |pair|
              Value.fail! unless pair.is_a?(Array) && pair.size == 2
              pair.map { |range| Value.set([ range ]) }
            end
          end
          Elements::StaticNat.new(**common, **values, match_rule: edges.fetch("match_rule"))
        end
      end

      class DynamicNatCodec < Codec
        FIELDS = %i[id policy_id direction rule_set acl_name nat_type pool_name from_zone to_zone interface protocol
          source_port translated_source_port destination_ip destination_port translated_destination_ip translated_destination_port destination_port_mapping
          source_set destination_set service_set translated_source_set translated_destination_set translated_service_set
          vrf extra_conf nat_order log_enabled].freeze
        SETS = %i[source_set destination_set service_set translated_source_set translated_destination_set translated_service_set].freeze
        EDGES = { "references" => [ :array, %w[address_object address_group negated_address_group service_object service_group] ],
          "source_pool" => [ :optional, %w[nat_pool] ], "destination_pool" => [ :optional, %w[nat_pool] ],
          "service" => [ :optional, %w[service_object service_group] ], "translated_service" => [ :optional, %w[service_object service_group] ],
          "match_rule" => [ :optional, %w[security_rule] ] }.freeze
        def validate(node)
          super
          panos = node.fetch("attributes").fetch("extra_conf")["panos"]
          if panos.is_a?(Hash) && panos.key?("translations")
            translations = panos.fetch("translations")
            Value.fail! unless translations.is_a?(Array) && translations.all? { |entry| entry.is_a?(Array) && entry.all? { |word| word.is_a?(String) } }
          end
        end

        def attributes(object) = super.merge(SETS.to_h { |key| [ key.to_s, Value.ranges(object.public_send(key)) ] })
        def edges(object)
          { "references" => object.references, "source_pool" => object.source_pool, "destination_pool" => object.destination_pool,
            "service" => object.service, "translated_service" => object.translated_service, "match_rule" => object.match_rule }
        end
        def build(attrs, edges, common, _context, _raw)
          values = args(attrs)
          SETS.each { |key| values[key] = Value.set(values[key], maximum: key.to_s.include?("service") ? IPAddr::SERVICE_MAX : IPAddr::IPV4_MAX) }
          Elements::DynamicNat.new(**common, **values, references: edges.fetch("references"), source_pool: edges.fetch("source_pool"),
            destination_pool: edges.fetch("destination_pool"), service: edges.fetch("service"), translated_service: edges.fetch("translated_service"),
            match_rule: edges.fetch("match_rule"))
        end
      end
    end
  end
end
