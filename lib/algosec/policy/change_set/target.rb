# frozen_string_literal: true

require_relative "../change_set"

module Algosec
  module Policy
    class ChangeSet
      class Target
        attr_reader :traffic_set, :action, :context, :effective_window, :metadata

        def initialize(traffic_set:, action:, from_zone:, to_zone:, rule_set: nil, application: nil, source_user: nil, effective_window: nil, metadata: {})
          raise ArgumentError, "Target requires exact traffic" unless traffic_set.is_a?(TrafficSet)
          raise ArgumentError, "Target window requires a Schedule" unless effective_window.nil? || effective_window.is_a?(Elements::Schedule)
          canonical = Elements::SecurityRule::ACTIONS[action.to_s]
          raise ArgumentError, "Target requires a known action" unless canonical
          unless metadata.is_a?(Hash) && (metadata.keys - %i[log log_enabled]).empty?
            raise ArgumentError, "Target metadata only supports explicit logging expectations"
          end
          unless !metadata.key?(:log_enabled) || [ nil, true, false ].include?(metadata[:log_enabled])
            raise ArgumentError, "Target log_enabled must be true, false or nil"
          end
          unless !metadata.key?(:log) || metadata[:log].nil? || metadata[:log].is_a?(String)
            raise ArgumentError, "Target log must be text or nil"
          end
          @metadata = Value.immutable(metadata)
          @traffic_set, @action = traffic_set, canonical
          @effective_window = effective_window&.seal!
          @context = Value.immutable(from_zone: from_zone, to_zone: to_zone, rule_set: rule_set, application: application, source_user: source_user)
          freeze
        end

        def active?(at:) = !effective_window || effective_window.active?(at: at)

        def matches?(partition)
          partition.status == :matched && partition.action == action &&
            metadata.all? { |name, expected| partition.rule&.public_send(name) == expected }
        end

        # 原生不检查的维度仍可能是批准范围；只有调用者明确给 nil 才表示不限制。
        def covers_context?(actual, behavior:)
          native = behavior.proof_context(actual)
          context.all? { |key, value| value == actual[key] || (value.nil? && native[key].nil?) }
        end

        # Rulebase 查询需要实际区域名；原生入口 ACL 的明确无出口限制可用任一真实出口代表。
        def evaluation_context(behavior:)
          representative = context.merge(to_zone: context[:from_zone])
          if context[:to_zone].nil? && behavior.proof_context(context) == behavior.proof_context(representative)
            representative
          else
            context
          end
        end

        def to_h
          { traffic: ChangeSet.traffic_document(traffic_set), action: action, context: context, metadata: metadata,
            effective_window: effective_window && { kind: effective_window.kind, name: effective_window.name,
              start_at: effective_window.start_at&.iso8601(9), end_at: effective_window.end_at&.iso8601(9),
              window: effective_window.window && [ effective_window.window.begin, effective_window.window.end ], time_zone: effective_window.time_zone.name } }
        end
      end
    end
  end
end
