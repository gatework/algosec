# frozen_string_literal: true

require_relative "translation"

module Algosec
  module Elements
    module Nat
      # 目的转换与源转换使用相同的值约束，方向由领域类型明确区分。
      class DestinationTranslation < Translation
        MODES = [ nil, :none, :static, :unknown ].freeze
        PORT_MAPPINGS = [ nil, :offset, :pool, :unknown ].freeze
        private_constant :PORT_MAPPINGS

        attr_reader :port_mapping

        def initialize(port_mapping: nil, **attributes)
          port_mapping = port_mapping.to_sym if port_mapping.is_a?(String)
          raise ArgumentError, "Unknown destination port mapping" unless PORT_MAPPINGS.include?(port_mapping)
          @port_mapping = port_mapping
          super(**attributes)
        end

        def to_h = super.merge(port_mapping: port_mapping)

        # 分配方式区分地址池与固定目标，独立于目的转换的匹配方向。
        def allocation_mode = pool ? :dynamic : (mode == :static ? :static : nil)

        # 两端包含目标端口不等于对应关系；只证明身份、固定目标或明确的等长偏移。
        def fixed_port_relation(original:, translated:, matching:, targets:)
          return unless [ original, translated, targets ].all? { |set| set.is_a?(Set) && !set.empty? && set.max <= IPAddr::PORT_MAX }
          return if mode == :unknown || port_mapping == :unknown
          return original == translated ? :identity : nil if mode == :none
          if port_mapping.nil? && port.nil? && pool&.port.nil? && services.nil? && service.nil?
            return :identity if original == translated
            return
          end
          if port_mapping == :offset
            return unless matching.is_a?(Set) && matching.size == 1 && targets.size == 1 &&
              matching.cardinality == targets.cardinality && matching.cover?(original)
            offset = targets.min - matching.min
            actual = Set.new(*original.map { |range| (range.begin + offset)..(range.end + offset) })
            :offset if actual == translated
          elsif targets.cardinality == 1 && targets == translated
            :fixed
          end
        end
      end
    end
  end
end
