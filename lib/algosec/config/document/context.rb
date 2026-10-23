# frozen_string_literal: true

module Algosec
  module Config
    class Document
      module Context
        KEYS = %w[vendor device_id device_name settings reference_time time_zone definition dns_context].freeze
        module_function

        def dump(result)
          { "vendor" => result.reader.vendor.to_s, "device_id" => result.reader.device_id, "device_name" => result.reader.device_name,
            "settings" => result.parsing_settings, "reference_time" => Value.time(result.reference_time), "time_zone" => result.time_zone,
            "definition" => result.definition_id, "dns_context" => result.dns_context }
        end

        def validate(context)
          Value.object(context, KEYS)
          vendor = context.fetch("vendor")
          Value.fail! unless vendor.is_a?(String) && Vendors.names(:parser).map(&:to_s).include?(vendor)
          Value.fail! unless context.fetch("definition") == vendor
          id = context.fetch("device_id")
          Value.fail! unless id.nil? || (id.is_a?(Integer) && id >= 0)
          Value.fail! unless context["device_name"].nil? || context["device_name"].is_a?(String)
          Value.instant(context.fetch("reference_time"))
          zone = context.fetch("time_zone")
          Value.fail! unless zone.nil? || (zone.is_a?(String) && Time.find_zone!(zone).name == zone)
          settings = context.fetch("settings")
          Value.object(settings, vendor == "fortinet" ? %w[vdom] : [])
          Value.fail! if vendor == "fortinet" && !settings["vdom"].is_a?(String)
          dns(context["dns_context"], id)
        end

        # 注入解析器的历史上下文可省略来源/设备；已有字段仍严格校验。
        def dns(value, device_id)
          return if value.nil?
          Value.fail! unless value.is_a?(Hash) && (value.keys - %w[device_id source servers]).empty?
          if value.key?("device_id")
            Value.fail! unless value["device_id"] == device_id
          end
          Value.fail! if value.key?("source") && !%w[system device].include?(value["source"])
          if value.key?("servers")
            Value.fail! unless value["servers"].is_a?(Array) && value["servers"].all? { |server| server.is_a?(String) && ::IPAddr.new(server) }
          end
        end
      end
    end
  end
end
