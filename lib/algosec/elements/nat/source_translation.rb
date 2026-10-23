# frozen_string_literal: true

require_relative "translation"

module Algosec
  module Elements
    module Nat
      # 源转换的模式和固定端口关系；匹配条件由所属 NAT 规则持有。
      class SourceTranslation < Translation
        MODES = [ nil, :none, :static_ip, :dynamic_ip, :dynamic_ip_and_port, :unknown ].freeze

        # 缺失原生模式不证明静态或动态分配；目标集合是独立的地址证据。
        def allocation_mode
          { static_ip: :static, dynamic_ip: :dynamic, dynamic_ip_and_port: :dynamic }[mode]
        end

        # 匹配条件的 nil 不等于端口转换保证；只证明固定模式的身份或显式常量关系。
        # 地址池、接口和动态会话模式不承诺实际分配端口；范围重写尚无逐端口配对语义。
        def fixed_port_relation(original:, translated:)
          return unless [ original, translated ].all? { |value| value.is_a?(Set) && !value.empty? && value.max <= IPAddr::PORT_MAX }
          return unless %i[none static_ip].include?(mode) && pool.nil? && interface.nil?
          return :identity if port.nil? && original == translated
          return unless mode == :static_ip && port
          declared = IPAddr.ports(port)
          :fixed if declared.cardinality == 1 && declared == translated
        end
      end
    end
  end
end
