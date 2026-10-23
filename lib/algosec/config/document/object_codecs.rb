# frozen_string_literal: true

module Algosec
  module Config
    class Document
      class AddressCodec < Codec
        FIELDS = %i[zone direct_member unresolved excluded_member dns_answers].freeze
        EDGES = { "references" => [ :named, %w[address_object address_group negated_address_group] ] }.freeze

        def validate(node)
          super
          attrs = node.fetch("attributes")
          attrs.fetch("dns_answers").each_value do |record|
            Value.object(record, %w[evidence error_key error_present])
            Value.fail! unless record["evidence"].is_a?(Hash)
            %w[resolved_at expires_at].each do |field|
              Value.declaration_time(record.fetch("evidence").fetch(field)) if record.fetch("evidence").key?(field)
            end
            %w[error_key error_present].each { |key| Value.fail! unless [ true, false ].include?(record[key]) }
          end
          %w[direct_member excluded_member].each do |name|
            attrs.fetch(name).each do |leaf|
              Value.object(leaf, %w[type value])
              Value.fail! unless leaf.values.all? { |value| value.is_a?(String) }
            end
          end
        end

        def attributes(object)
          super.merge("dns_answers" => object.dns_answers.to_h do |domain, answer|
            [ domain, { "evidence" => answer.reject { |key, _| key == "error" },
                        "error_key" => object.dns_error_key?(domain), "error_present" => object.dns_error_present?(domain) } ]
          end)
        end

        def edges(object) = { "references" => named(object.references) }

        def build(attrs, edges, common, _context, raw)
          object = Elements::AddressObject.new(**common, zone: attrs.fetch("zone"), member: attrs.fetch("direct_member"),
            unresolved: attrs.fetch("unresolved"), excluded_member: attrs.fetch("excluded_member"), references: edges.fetch("references").map { |entry| entry.fetch("name") })
          targets = members(edges.fetch("references"))
          object.resolve!(strict: false) { |name| targets.fetch(name) }
          object.restore_dns_answers!(attrs.fetch("dns_answers"), errors: raw.fetch(:dns_errors))
          object
        end
      end

      class AddressGroupCodec < Codec
        FIELDS = %i[zone].freeze
        EDGES = { "members" => [ :named, %w[address_object address_group negated_address_group] ] }.freeze
        def edges(object) = { "members" => named(object.members) }
        def build(attrs, edges, common, _context, _raw)
          Elements::AddressGroup.new(**common, **args(attrs), members: members(edges.fetch("members")))
        end
      end

      class NegatedAddressGroupCodec < AddressGroupCodec
        def build(attrs, edges, common, _context, _raw)
          Elements::AddressGroup::Negated.new(**common, **args(attrs), members: members(edges.fetch("members")))
        end
      end

      class ServiceCodec < Codec
        FIELDS = %i[terms].freeze
        def attributes(object) = super.merge("terms" => object.terms.map { |term| term.transform_keys(&:to_s) })
        def validate(node)
          super
          terms = node.fetch("attributes").fetch("terms")
          Value.fail! unless terms.is_a?(Array)
          terms.each { |term| Value.object(term, %w[protocol source_port destination_port term uuid timeout]) }
        end
        def build(attrs, _edges, common, _context, _raw) = Elements::ServiceObject.new(**common, **args(attrs))
      end

      class ServiceGroupCodec < Codec
        FIELDS = %i[protocol].freeze
        EDGES = { "members" => [ :named, %w[service_object service_group] ] }.freeze
        def edges(object) = { "members" => named(object.members) }
        def build(attrs, edges, common, _context, _raw)
          Elements::ServiceGroup.new(**common, **args(attrs), members: members(edges.fetch("members")))
        end
      end

      class ScheduleCodec < Codec
        FIELDS = %i[kind start_at end_at time_zone reference_time weekly_windows monthly_periods unparsed_commands_metadata].freeze
        def attributes(object)
          super.merge("start_at" => Value.time(object.start_at), "end_at" => Value.time(object.end_at),
            "time_zone" => object.time_zone.name, "reference_time" => Value.time(object.reference_time),
            "weekly_windows" => object.weekly_windows.map do |day, windows|
              { "weekday" => day, "windows" => windows.map { |window| { "first_minute" => window.begin, "last_minute" => window.end } } }
            end)
        end
        def build(attrs, _edges, common, _context, raw)
          Value.fail! unless attrs["time_zone"].is_a?(String)
          periods = attrs.fetch("weekly_windows").to_h do |entry|
            Value.object(entry, %w[weekday windows])
            day = entry.fetch("weekday")
            Value.fail! unless day.is_a?(Integer) && day.between?(0, 6)
            Value.fail! unless entry["windows"].is_a?(Array)
            windows = entry.fetch("windows").map do |window|
              Value.object(window, %w[first_minute last_minute])
              window.values_at("first_minute", "last_minute").map do |minute|
                Value.fail! unless minute.is_a?(Integer) && minute.between?(0, 1439)
                format("%02d:%02d", minute / 60, minute % 60)
              end
            end
            [ Elements::Schedule::WEEKDAYS.fetch(day), windows ]
          end
          Elements::Schedule.new(**common, kind: attrs.fetch("kind"), time_zone: attrs.fetch("time_zone"),
            reference_time: Value.instant(attrs.fetch("reference_time")), start_at: attrs["start_at"] && Value.instant(attrs["start_at"]),
            end_at: attrs["end_at"] && Value.instant(attrs["end_at"]), periods: periods,
            monthly_periods: attrs.fetch("monthly_periods"), unparsed_commands: raw.fetch(:unparsed_commands),
            unparsed_commands_metadata: attrs.fetch("unparsed_commands_metadata"))
        end
      end

      class RuleCodec < Codec
        FIELDS = %i[native_rule_id rule_set rule_number rule_type native_rule_type from_zones to_zones from_interface dst_interfaces
          action native_action status log log_enabled schedule_name applications source_users service_selection conditions unparsed_commands_metadata vendor_data nat].freeze
        EDGES = { "sources" => [ :required, %w[address_group negated_address_group] ], "destinations" => [ :required, %w[address_group negated_address_group] ],
                  "services" => [ :required, %w[service_group] ], "schedule" => [ :optional, %w[schedule] ] }.freeze
        def attributes(object)
          # nat? 是显式声明；其余字段来自固定白名单。
          Value.fields(object, FIELDS - [ :nat, :conditions ]).merge(super_common(object), "nat" => object.nat?, "conditions" => object.semantic_conditions)
        end
        def super_common(object)
          { "name" => object.name, "description" => object.description, "ref_count" => object.ref_count,
            "config_present" => object.config_present?, "scope" => object.scope.to_h.transform_keys(&:to_s) }
        end
        def edges(object) = { "sources" => object.sources, "destinations" => object.destinations, "services" => object.services, "schedule" => object.schedule }
        def build(attrs, edges, common, _context, raw)
          values = args(attrs)
          Value.fail! if values.fetch(:conditions).key?("unparsed_commands")
          %w[starts_at expires_at].each do |field|
            value = values.fetch(:conditions)[field]
            Value.declaration_time(value) unless value.nil?
          end
          if values.fetch(:unparsed_commands_metadata).fetch("declared") && raw[:unparsed_commands]
            values[:conditions] = values.fetch(:conditions).merge("unparsed_commands" => raw.fetch(:unparsed_commands))
          end
          Elements::SecurityRule.new(**common, **values, sources: edges.fetch("sources"), destinations: edges.fetch("destinations"),
            services: edges.fetch("services"), schedule: edges.fetch("schedule"))
        end
      end

      class RuleBindingCodec < Codec
        FIELDS = %i[rule_type rule_set from_zone to_zone].freeze
        def build(attrs, _edges, common, _context, _raw)
          Elements::RuleBinding.new(**common, **args(attrs))
        end
      end
    end
  end
end
