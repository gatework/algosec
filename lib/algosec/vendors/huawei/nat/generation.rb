# frozen_string_literal: true

require "shellwords"
require_relative "../../../vendors"
require_relative "../../../policy/nat/generation"
require_relative "../../../config/parser"
require_relative "action"
require_relative "server"
require_relative "../service_terms"

module Algosec
  module Vendors
    module Huawei
      module Nat
        # 从实际发射命令装配 NAT 声明，交由共同验证器证明效果。
        class Generation
          def self.server(snapshot:, command:, zone:, real:, mapped:)
            words = command.split
            raise ArgumentError, "Expected a Huawei nat server declaration" unless words.take(2) == %w[nat server]
            native = Server.new(words.drop(2))
            nat = Algosec::Elements::StaticNat.new(vendor: snapshot.vendor, device_id: snapshot.device_id, **native.attributes)
            # Huawei 不含 no-reverse 的 host server-map 批准并发射完整的正反两侧关系。
            common = { address: real, zone: zone, peers: { "0.0.0.0/0" => {} }, allocation: { type: :static, address: mapped } }
            targets = [ Algosec::Policy::Nat::Verification::Expectation.new(**common, direction: :source),
              Algosec::Policy::Nat::Verification::Expectation.new(**common, direction: :destination, flow: { original_dst: mapped }) ]
            Algosec::Policy::Nat::Generation::Evidence.new(declarations: [ nat ], expectations: targets)
          end

          def initialize(snapshot)
            @snapshot, @pools = snapshot, []
            @position = snapshot.dynamic_nats.filter_map { |nat| nat.position&.last }.max || 0
          end

          def pool(commands)
            text = commands.reject { |command| command == "quit" }.join("\n") + "\n"
            parsed = Algosec::Config::Parser.perform(text, vendor: :huawei, device_id: @snapshot.device_id)
            unless parsed.complete? && parsed.catalog.size == 1 && parsed.catalog.to_a.first.is_a?(Algosec::Elements::NatPool)
              raise Algosec::Policy::Error.new("生成 Huawei 地址池声明不完整", code: :unsupported_nat_proof)
            end
            @pools << parsed.catalog.to_a.first
          end

          def rule(commands:, approved:)
            attributes = { rule_set: "nat-policy", references: [], extra_conf: {} }
            actions = []
            commands.each do |command|
              words = Shellwords.split(command)
              case words.first
              when "nat-policy", "quit" then next
              when "rule" then attributes[:name] = words.fetch(2)
              when "source-zone", "destination-zone", "egress-interface"
                key = { "source-zone" => :from_zone, "destination-zone" => :to_zone, "egress-interface" => :interface }.fetch(words.first)
                raise ArgumentError, "Ambiguous NAT selector" unless words.size == 2 && !attributes.key?(key)
                attributes[key] = words.last
              when "source-address", "destination-address"
                key = words.first == "source-address" ? :source_set : :destination_set
                value = words[1] == "range" ? "#{words.fetch(2)}-#{words.fetch(3)}" : "#{words.fetch(1)}/#{words.fetch(2)}"
                attributes[key] = (attributes[key] || Set.new) | IPAddr.parse(value)
              when "service"
                raise ArgumentError, "Unsupported NAT service" unless words[1] == "protocol"
                ServiceTerms.new(words.drop(2)).terms.each do |term|
                  name = "#{term.fetch(:protocol)}/#{term.fetch(:destination_port)}:source/#{term.fetch(:source_port)}"
                  service = Algosec::Elements::ServiceObject.new(**context, name: name, **term)
                  attributes[:references] << service
                  attributes[:service_set] = (attributes[:service_set] || Set.new) | service.set
                end
              when "action" then actions << Action.new(words.drop(1))
              else raise ArgumentError, "Unsupported generated Huawei NAT field"
              end
            end
            raise ArgumentError, "Missing NAT identity or repeated actions" unless attributes[:name] && actions.any? && actions.map(&:direction).uniq.size == actions.size
            %i[source_set destination_set].each { |key| attributes[key] ||= Set.new(0..IPAddr::IPV4_MAX) }
            attributes[:extra_conf]["match"] = { "to_zone" => attributes[:to_zone], "interface" => attributes[:interface] }
            if attributes[:interface]
              interface = @snapshot.elements(Algosec::Elements::Interface).find { |item| item.name == attributes[:interface] }
              raise Algosec::Policy::Error.new("Huawei NAT 接口声明缺失", code: :unproven_reference) unless interface
              attributes[:vrf] = interface.vrf
            end
            actions.each do |action|
              unless action.target == "address-group"
                raise Algosec::Policy::Error.new("Huawei 接口或会话地址分配尚无确定配置关系证明", code: :unsupported_nat_allocation)
              end
              matches = (@pools + @snapshot.elements(Algosec::Elements::NatPool)).select { |item| item.name == action.value }
              raise Algosec::Policy::Error.new("Huawei NAT 池引用不唯一", code: :unproven_reference) unless matches.one? && matches.first.direction == action.direction
              pool = matches.first
              attributes[:pool_name] = pool.name if actions.one?
              attributes["#{action.direction}_pool".to_sym] = pool
              attributes["translated_#{action.direction}_set".to_sym] = pool.set
              attributes[:extra_conf]["source_mode"] = action.target if action.direction == :source
              next unless action.port
              terms = attributes[:references].flat_map { |service| service.service_projection[:member] }
              service = Algosec::Elements::ServiceObject.new(**context, name: "#{attributes.fetch(:name)}:translated", terms: terms.map { |term| term.merge(destination_port: action.port) })
              attributes.merge!(translated_destination_port: action.port, translated_service: service, translated_service_set: service.set)
            end
            attributes[:direction] = actions.one? ? actions.first.direction : :bidirectional
            @position += 1
            attributes[:nat_order] = [ actions.any? { |action| action.direction == :destination } ? 0 : 1, @position ]
            nat = Algosec::Elements::DynamicNat.new(**context, **attributes)
            Algosec::Policy::Nat::Generation::Evidence.new(declarations: [ nat ], expectations: expectations(approved))
          rescue ArgumentError => error
            raise Algosec::Policy::Error.new(error.message, code: :unsupported_nat_proof)
          end

          private

          def context = { vendor: :huawei, device_id: @snapshot.device_id }

          def expectations(rule)
            ranges = rule.ranges
            services = if ranges.fetch(:services) == Set.new(0..IPAddr::SERVICE_MAX)
              nil
            else
              value = ranges.fetch(:services).sole.begin
              origin = "#{value >> 16}/#{value & IPAddr::PORT_MAX}"
              { origin => { origin: origin, translated_port: rule.destination&.fetch(:port)&.to_s }.compact }
            end
            %i[source destination].flat_map do |direction|
              action = rule.public_send(direction)
              next [] unless action
              real = direction == :source ? ranges.fetch(:sources) : action.fetch(:target)
              peers = ranges.fetch(direction == :source ? :destinations : :sources).to_h { |range| [ IPAddr.format_range(range), {} ] }
              mapped = direction == :source ? action.fetch(:target) : ranges.fetch(:destinations)
              raise Algosec::Policy::Error.new("Huawei 分配目标不是单一连续范围", code: :unsupported_nat_range) unless mapped&.size == 1
              flow = { from_zone: rule.from_zone, to_zone: rule.to_zone }
              flow[:original_dst] = IPAddr.format_range(mapped.sole) if direction == :destination
              real.map do |range|
                Algosec::Policy::Nat::Verification::Expectation.new(address: IPAddr.format_range(range), direction: direction,
                  zone: direction == :source ? rule.to_zone : rule.from_zone, peers: peers, services: services, flow: flow,
                  allocation: { type: :dynamic, address: IPAddr.format_range(mapped.sole) })
              end
            end
          end
        end
      end
    end
  end
end
