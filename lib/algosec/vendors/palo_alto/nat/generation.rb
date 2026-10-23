# frozen_string_literal: true

require "shellwords"
require_relative "../../../vendors"
require_relative "../../../policy/nat/generation"
require_relative "../../../config/parser"

module Algosec
  module Vendors
    module PaloAlto
      module Nat
        # 从实际发射命令装配 NAT 声明，交由共同验证器证明效果。
        class Generation
          def initialize(snapshot)
            @snapshot, @objects = snapshot, []
            @position = snapshot.dynamic_nats.map(&:position).compact.map(&:first).max || 0
          end

          def object(command)
            parsed = Algosec::Config::Parser.perform(command + "\n", vendor: :palo_alto, device_id: @snapshot.device_id)
            unless parsed.complete? && parsed.catalog.size == 1
              raise Algosec::Policy::Error.new("生成 PAN 对象声明不完整", code: :unsupported_nat_proof)
            end
            @objects << parsed.catalog.to_a.fetch(0)
          end

          def expectation(record:, direction:, result:, before_zone:, service:, original:, translated_port: nil, public_destination: nil)
            peers = direction == :source ? (public_destination ? [ public_destination ] : result.destinations.keys) : result.sources.keys
            options = { from_zone: result.from_zone, to_zone: before_zone }
            options[:original_dst] = public_destination if direction == :destination
            Algosec::Policy::Nat::Verification::Expectation.new(address: record.fetch(:real_ip), direction: direction,
              zone: direction == :source ? before_zone : result.from_zone,
              peers: peers.to_h { |address| [ address, {} ] }, services: { service => { origin: original, translated_port: translated_port }.compact },
              flow: options, allocation: record.fetch(:nat).slice(:type, :address, :interface, :direction, :pool_name, :option))
          end

          def rule(commands:, expectations:)
            fields, translations, name = {}, [], nil
            commands.each do |command|
              words = Shellwords.split(command)
              next unless words.take(4) == %w[set rulebase nat rules]
              current, field, *rest = words.drop(4)
              raise Algosec::Policy::Error.new("PAN NAT 声明混用了规则身份", code: :unsupported_nat_proof) if name && name != current
              name = current
              unless %w[from to source destination service source-translation destination-translation].include?(field)
                raise Algosec::Policy::Error.new("PAN NAT 声明字段尚无证明", code: :unsupported_nat_proof)
              end
              fields[field] = rest.reject { |value| %w[[ ]].include?(value) }
              translations << [ field, *rest ] if field.end_with?("translation")
            end
            raise Algosec::Policy::Error.new("缺少实际 PAN NAT 声明", code: :unsupported_nat_proof) unless name
            from, to = %w[from to].map { |key| fields.fetch(key).sole }
            sources, destinations = %w[source destination].map { |key| addresses(fields.fetch(key)) }
            service_name = fields.fetch("service").sole
            service = service_name == "any" ? nil : find(service_name, [ Algosec::Elements::ServiceObject, Algosec::Elements::ServiceGroup ])
            source = translations.select { |words| words.first == "source-translation" }
            destination = translations.select { |words| words.first == "destination-translation" }
            source_address = source.find { |words| words[2] == "translated-address" }
            destination_address = destination.find { |words| words[1] == "translated-address" }
            if source.any? && source_address.nil?
              raise Algosec::Policy::Error.new("PAN 接口或会话分配尚无确定地址关系证明", code: :unsupported_nat_allocation)
            end
            mode = source.first&.fetch(1)
            unless source.all? { |words| words[2] == "translated-address" || words[1, 3] == %w[static-ip bi-directional no] }
              raise Algosec::Policy::Error.new("PAN 原生反向转换尚无范围证明", code: :unsupported_nat_proof)
            end
            @position += 1
            names = fields.fetch("source") + fields.fetch("destination")
            names += source_address.drop(3) if source_address
            names += destination_address.drop(2) if destination_address
            references = names.uniq.filter_map { |entry| address_object(entry) }
            references << service if service
            nat = Algosec::Elements::DynamicNat.new(vendor: :palo_alto, device_id: @snapshot.device_id, name: name, id: name,
              direction: source.any? && destination.any? ? :bidirectional : (source.any? ? :source : :destination), nat_order: [ @position ],
              source_set: sources, destination_set: destinations, from_zone: from, to_zone: to,
              service: service, service_set: service ? service.set : IPAddr.service("any"),
              protocol: service.is_a?(Algosec::Elements::ServiceObject) ? (service.protocol || "any") : "any",
              destination_port: service.is_a?(Algosec::Elements::ServiceObject) ? service.destination_port : nil,
              nat_type: mode, translated_source_set: source_address && addresses(source_address.drop(3)),
              translated_destination_set: destination_address && addresses(destination_address.drop(2)),
              translated_destination_port: destination.find { |words| words[1] == "translated-port" }&.fetch(2),
              references: references, extra_conf: { "disabled" => false, "src_zones" => [ from ], "dst_zones" => [ to ],
                "panos" => fields.merge("translations" => translations) })
            Algosec::Policy::Nat::Generation::Evidence.new(declarations: [ nat ], expectations: expectations)
          end

          private

          def find(name, types)
            matches = (@objects + @snapshot.catalog.to_a + @snapshot.builtin_services).select { |item| item.name == name && types.any? { |type| item.is_a?(type) } }.uniq(&:identity)
            raise Algosec::Policy::Error.new("PAN NAT 引用没有唯一声明：#{name}", code: :unproven_reference) unless matches.one?
            matches.first
          end

          def address_object(name)
            (@objects + @snapshot.catalog.to_a).find { |item| item.name == name && (item.is_a?(Algosec::Elements::AddressObject) || item.is_a?(Algosec::Elements::AddressGroup)) }
          end

          def addresses(names)
            Set.new(*names.flat_map do |name|
              next [ 0..IPAddr::IPV4_MAX ] if name == "any"
              object = address_object(name)
              if object
                raise Algosec::Policy::Error.new("PAN NAT 引用地址条件未知", code: :conditional_nat) unless object.resolved? && !object.conditional?
                object.resolved_set.ranges
              else
                IPAddr.parse(name).ranges
              end
            end)
          end
        end
      end
    end
  end
end
