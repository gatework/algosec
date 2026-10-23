# frozen_string_literal: true

module Algosec
  module Config
    class Document
      # 各类型只声明自己的公开构造字段和带类型的引用槽。
      class Codec
        COMMON = %w[name description ref_count config_present scope].freeze
        FIELDS = [].freeze
        EDGES = {}.freeze
        ARRAYS = %w[direct_member unresolved excluded_member terms weekly_windows monthly_periods
          dst_interfaces applications source_users vlans ipv6_addresses ip].freeze
        MAPS = %w[dns_answers conditions vendor_data extra_conf unparsed_commands_metadata].freeze

        def attributes(object)
          Value.fields(object, self.class::FIELDS).merge(
            "name" => object.name, "description" => object.description, "ref_count" => object.ref_count,
            "config_present" => object.config_present?, "scope" => object.scope.to_h.transform_keys(&:to_s))
        end

        def edges(_object) = {}
        def field_names = COMMON + self.class::FIELDS.map(&:to_s)
        def edge_types = self.class::EDGES

        def validate(node)
          Value.object(node.fetch("attributes"), field_names)
          Value.object(node.fetch("edges"), edge_types.keys)
          attrs = node.fetch("attributes")
          Value.fail! unless [ true, false ].include?(attrs["config_present"])
          Value.fail! unless attrs["ref_count"].is_a?(Integer) && attrs["ref_count"] >= 0
          %w[name description].each { |key| Value.fail! unless attrs[key].nil? || attrs[key].is_a?(String) }
          self.class::FIELDS.each do |field|
            value = attrs.fetch(field.to_s)
            Value.fail! if ARRAYS.include?(field.to_s) && !value.is_a?(Array)
            Value.fail! if MAPS.include?(field.to_s) && !value.is_a?(Hash)
          end
          if attrs.key?("unparsed_commands_metadata")
            Value.object(attrs.fetch("unparsed_commands_metadata"), %w[declared count sha256])
          end
          Value.object(attrs.fetch("scope"), %w[device_id virtual_system rulebase address_book zone])
        end

        def common(attrs, context, config)
          scope = attrs.fetch("scope")
          Value.fail! unless scope.fetch("device_id") == context.fetch("device_id")
          { vendor: context.fetch("vendor"), device_id: context.fetch("device_id"),
            scope: Elements::Scope.new(**Value.keywords(scope, %i[device_id virtual_system rulebase address_book zone])),
            name: attrs.fetch("name"), description: attrs.fetch("description"), ref_count: attrs.fetch("ref_count"),
            config: config, config_present: attrs.fetch("config_present") }
        end

        def args(attrs) = Value.keywords(attrs, self.class::FIELDS)
        def slot(object) = object
        def named(mapping) = mapping.map { |name, object| { "name" => name, "node" => object } }
        def members(entries) = entries.to_h { |entry| [ entry.fetch("name"), entry.fetch("node") ] }
      end
    end
  end
end
