# frozen_string_literal: true

require_relative "../version"
require_relative "reader"
require_relative "result"

module Algosec
  module Config
    # 版本化语义文档只恢复允许的领域声明；不执行任何配置解析或网络操作。
    class Document
      class InvalidDocument < ArgumentError; end
      SCHEMA_VERSION = 1
      SEMANTIC_VERSION = Algosec::SEMANTIC_VERSION
      MAX_NODES = 100_000
      DIAGNOSTIC_CODES = %i[
        aggregate_dependency ambiguous_nat ambiguous_nat_interface ambiguous_nat_pool ambiguous_nat_pool_zone ambiguous_policy
        ambiguous_reference ambiguous_route ambiguous_zone ambiguous_zone_mapping conditional_nat conditional_nat_acl
        conditional_nat_address conditional_policy conditional_route conditional_rule conflicting_nat_zone conflicting_pbr_next_hop
        conflicting_pbr_vrf conflicting_policy_binding conflicting_rule_modifications conflicting_vrf conflicting_zone cross_vrf_route
        duplicate_nat_action duplicate_nat_server duplicate_rule dynamic_address_group incomplete_configuration incomplete_nat
        incomplete_nat_pool incomplete_plan incomplete_query incomplete_service incomplete_source incomplete_vip_mapping
        incomplete_vip_port_forward invalid_address invalid_aggregate invalid_interface invalid_nat invalid_nat_pool
        invalid_nat_pool_header invalid_nat_server invalid_object_header invalid_pbr invalid_policy invalid_route
        invalid_rule_config invalid_rule_time invalid_schedule invalid_service missing_baseline missing_interface
        missing_nat_context missing_reference missing_zone mixed_definitions mixed_snapshots nat_in_use
        nat_interface_missing nat_missing nat_pool_mismatch nat_scope_conflict no_firewall shared_policy
        stale_plan target_not_empty uncommitted_configuration unknown_order unknown_rule_action unknown_rule_status
        unreachable unresolved_address unresolved_service unsupported_action unsupported_address unsupported_address_type
        unsupported_aggregate unsupported_application_condition unsupported_command unsupported_domain_pattern unsupported_interface_address unsupported_migration
        unsupported_nat_action unsupported_nat_condition unsupported_nat_context unsupported_nat_direction unsupported_nat_migration unsupported_nat_option unsupported_nat_pool
        unsupported_nat_pool_arp_reply unsupported_nat_pool_mode unsupported_nat_range unsupported_nat_server_option unsupported_nat_server_port unsupported_nat_server_range
        unsupported_nat_server_reverse unsupported_nat_service unsupported_nat_status unsupported_nat_vrf unsupported_operation unsupported_pbr_condition
        unsupported_policy_binding unsupported_policy_order unsupported_port_nat unsupported_protocol unsupported_route_target unsupported_rule_condition
        unsupported_rule_header unsupported_schedule unsupported_scope unsupported_service unsupported_version unsupported_vip_external_ip
        unsupported_vip_load_balance unsupported_vip_port_mapping unsupported_vip_source_nat
      ].to_h { |code| [ code.to_s, code ] }.freeze

      class << self
        def dump(result, raw: false)
          raise InvalidDocument, "Expected a configuration Result" unless result.instance_of?(Result)
          Encoder.new(result).call(raw: raw)
        rescue KeyError, TypeError, ArgumentError => error
          raise if error.is_a?(InvalidDocument)
          raise InvalidDocument, "Invalid configuration document", cause: nil
        end

        def load(hash, expected_source_sha256: nil, expected_context: nil, source_content: nil, source_details: nil)
          Decoder.new(hash, expected_source_sha256: expected_source_sha256, expected_context: expected_context,
            source_content: source_content, source_details: source_details).call
        rescue KeyError, TypeError, ArgumentError, IndexError => error
          raise if error.is_a?(InvalidDocument)
          raise InvalidDocument, "Invalid configuration document", cause: nil
        end

        def codec_for(object)
          kind, entry = CODECS.find { |_key, (type, _codec)| object.instance_of?(type) }
          Value.fail! unless entry
          [ kind, entry.last ]
        end

        def codec_named(kind) = CODECS.fetch(kind) { Value.fail! }.last
      end
    end
  end
end

require_relative "document/value"
require_relative "document/codec"
require_relative "document/context"
require_relative "document/object_codecs"
require_relative "document/network_codecs"
require_relative "document/nat_codecs"
require_relative "document/encoder"
require_relative "document/decoder"

module Algosec
  module Config
    class Document
      CODECS = {
        "address_object" => [ Elements::AddressObject, AddressCodec.new ],
        "address_group" => [ Elements::AddressGroup, AddressGroupCodec.new ],
        "negated_address_group" => [ Elements::AddressGroup::Negated, NegatedAddressGroupCodec.new ],
        "service_object" => [ Elements::ServiceObject, ServiceCodec.new ],
        "service_group" => [ Elements::ServiceGroup, ServiceGroupCodec.new ],
        "schedule" => [ Elements::Schedule, ScheduleCodec.new ],
        "security_rule" => [ Elements::SecurityRule, RuleCodec.new ],
        "rule_binding" => [ Elements::RuleBinding, RuleBindingCodec.new ],
        "route" => [ Elements::Route, RouteCodec.new ],
        "interface" => [ Elements::Interface, InterfaceCodec.new ],
        "zone" => [ Elements::Zone, ZoneCodec.new ],
        "nat_pool" => [ Elements::NatPool, NatPoolCodec.new ],
        "static_nat" => [ Elements::StaticNat, StaticNatCodec.new ],
        "dynamic_nat" => [ Elements::DynamicNat, DynamicNatCodec.new ]
      }.transform_values(&:freeze).freeze
    end
  end
end
