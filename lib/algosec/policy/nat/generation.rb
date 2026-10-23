# frozen_string_literal: true

require_relative "verification"

module Algosec
  module Policy
    module Nat
      # 生成命令时记录实际名称及原生声明；候选从这些声明合并，不从请求伪造成功状态。
      class Generation
        Evidence = Data.define(:declarations, :expectations) do
          def initialize(declarations:, expectations:)
            unless declarations.all? { |item| item.is_a?(Elements::NatRule) } && expectations.all? { |item| item.is_a?(Nat::Verification::Expectation) }
              raise ArgumentError, "Invalid generated NAT evidence"
            end
            super(declarations: declarations.dup.each(&:seal!).freeze, expectations: expectations.dup.freeze)
          end
        end

        def self.proof(snapshot:, entries:, change_set:)
          raise ArgumentError, "NAT proof requires its baseline ChangeSet" unless change_set.snapshot.equal?(snapshot)
          security_candidate = change_set.apply
          evidence = entries.flat_map(&:nat_evidence)
          declarations = evidence.flat_map(&:declarations)
          expectations = evidence.flat_map(&:expectations)
          entries.each do |entry|
            requested = requested_expectations(entry.result)
            requested.each do |expected|
              unless expectations.any? { |target| target.direction == expected.direction &&
                IPAddr.parse(target.address).cover?(IPAddr.parse(expected.address)) &&
                target.allocation[:type] == expected.allocation[:type] && target.allocation[:address] && expected.allocation[:address] &&
                IPAddr.parse(target.allocation[:address]) == IPAddr.parse(expected.allocation[:address]) }
                raise Error.new("NAT 命令缺少对应的实际声明证明", code: :missing_nat_generation_evidence)
              end
            end
            expectations.concat(requested)
            expectations.concat(reused_expectations(entry.result))
          end
          expectations = expectations.uniq(&:to_h)
          catalog = Elements::Catalog.new(security_candidate.catalog.to_a + declarations, vendor: snapshot.vendor, device_id: snapshot.device_id)
          candidate = snapshot.with_catalog(catalog)
          Nat::Verification.new(snapshot: snapshot, candidate: candidate, expectations: expectations, change_set: change_set)
        end

        def self.requested_expectations(result)
          records = []
          (result.actions || {}).each_value do |action|
            %i[nat_sources nat_destinations].each do |dimension|
              direction = dimension == :nat_sources ? :source : :destination
              action.fetch(dimension, {}).each_value { |record| records << [ record, direction ] }
            end
          end
          %i[sources destinations].each do |side|
            result.public_send(side).each do |key, record|
              next unless record[:nat] && !record[:nat][:rule]
              real = record[:real_ip] || record[:private] || record[:origin] || key
              records << [ record.merge(real_ip: real), side == :sources ? :source : :destination ]
            end
          end
          records = records.uniq
          count = records.sum do |_record, direction|
            result.public_send(direction == :source ? :destinations : :sources).size * result.services.size
          end
          raise Error.new("NAT 目标分段超出预算", code: :query_too_complex) if count > TrafficSet::DEFAULT_LIMIT
          records.flat_map do |record, direction|
            peers = result.public_send(direction == :source ? :destinations : :sources).to_h do |key, entry|
              [ direction == :source ? (entry[:main] || entry.dig(:nat, :address) || entry[:origin] || key) : (entry[:private] || entry[:origin] || key), {} ]
            end
            flow = result.snapshot.behavior.nat_query_flow(from_zone: result.from_zone, to_zone: result.to_zone,
              vrf: result.snapshot.vrf(result.from_zone))
            flow = flow.merge(original_dst: record.dig(:nat, :address)) if direction == :destination
            peers.flat_map do |peer, value|
              result.services.map do |service, entry|
                Nat::Verification::Expectation.new(address: record.fetch(:real_ip), direction: direction,
                  zone: direction == :source ? result.to_zone : result.from_zone, peers: { peer => value },
                  services: { service => entry.slice(:origin, :translated_port) }, flow: flow,
                  allocation: record.fetch(:nat).slice(:type, :address, :interface, :direction, :pool_name, :option))
              end
            end
          end
        end
        private_class_method :requested_expectations

        def self.reused_expectations(result)
          %i[sources destinations].flat_map do |side|
            direction = side == :sources ? :source : :destination
            peers = result.public_send(side == :sources ? :destinations : :sources).to_h do |key, entry|
              [ direction == :source ? (entry[:main] || entry.dig(:nat, :address) || entry[:origin] || key) : (entry[:private] || entry[:origin] || key), {} ]
            end
            result.public_send(side).filter_map do |key, record|
              mapping = record[:nat]
              next unless mapping && mapping[:rule]
              nat = mapping.fetch(:rule)
              translation = direction == :source ? nat.source_translation : nat.destination_translation
              translation = nat.source_translation if direction == :destination && nat.is_a?(Elements::StaticNat) && translation.identity?
              mode = translation.allocation_mode
              raise Error.new("复用 NAT 的规范分配模式未知", code: :conditional_nat) unless mode
              flow = result.snapshot.behavior.nat_query_flow(from_zone: result.from_zone, to_zone: result.to_zone,
                vrf: result.snapshot.vrf(result.from_zone))
              flow = flow.merge(original_dst: mapping.fetch(:address)) if direction == :destination
              Nat::Verification::Expectation.new(address: record[:private] || record[:real_ip] || key,
                zone: direction == :source ? result.to_zone : result.from_zone, direction: direction, peers: peers,
                services: result.services.transform_values { |entry| entry.slice(:origin, :translated_port) }, flow: flow,
                allocation: { type: mode, address: mapping.fetch(:address) })
            end
          end
        end
        private_class_method :reused_expectations
      end
    end
  end
end
