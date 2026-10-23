# frozen_string_literal: true

require_relative "../declarations"
require_relative "finding"
require_relative "assessment"
require_relative "analysis/rule_view"

module Algosec
  module Policy
    # 有限检查 DSL：声明元数据，复杂业务仍使用普通方法或代码块。
    class Analysis
      extend Declarations

      # true/证据 Hash 表示命中问题，false 表示未命中，未知必须显式抛出。
      def self.check(name, severity: :warning, message:, using: nil, remediation: nil, &block)
        unless name.is_a?(Symbol) && %i[info warning critical].include?(severity) &&
               [ using, block ].compact.one? && (using.nil? || using.is_a?(Symbol)) &&
               [ nil, :remove_rule ].include?(remediation)
          raise ArgumentError, "检查需要唯一标识、有效级别和一个处理器"
        end
        declare(name, severity: severity, message: Value.text(message), handler: using || block, remediation: remediation)
      end

      # 声明可在启动和测试时检查，继承不会修改父类的检查集合。
      def self.validate_declarations!
        raise ArgumentError, "至少声明一项检查" if declarations.empty?
        declarations.each_value do |declaration|
          handler = declaration.options[:handler]
          if handler.is_a?(Symbol) && !method_defined?(handler) && !private_method_defined?(handler)
            raise ArgumentError, "#{self}: missing check handler #{handler}"
          end
        end
      end

      # 时间在一次调用中固定；事实参数留给自定义统计和业务检查。
      def initialize(snapshot, at: Time.current, facts: {})
        raise ArgumentError, "分析需要配置快照" unless snapshot.is_a?(Snapshot)
        self.class.validate_declarations!
        @snapshot, @at, @facts = snapshot, at, Value.immutable(Value.hash(facts))
      end

      # 每条检查独立保留结果；程序错误不伪装成不合规或未知。
      def perform
        unless @snapshot.complete?
          finding = Finding.new(check: :configuration, rule_id: nil, status: :unknown, severity: :critical,
                                message: "配置解析不完整，无法完成策略分析", evidence: { code: :incomplete_configuration })
          return Assessment.new(snapshot: @snapshot, at: @at, findings: [ finding ])
        end
        views = @snapshot.rules.map { |rule| Analysis::RuleView.new(@snapshot, rule, at: @at) }
        chains = views.group_by(&:scope).transform_values { |rules| rules.sort_by { |view| [ view.rule_number || -1, view.id ] }.freeze }.freeze
        context = { rules: views.freeze, chains: chains, facts: @facts }.freeze
        findings = views.flat_map do |view|
          self.class.declarations.map do |name, declaration|
            evaluate(name, declaration.options, view, context)
          end
        end
        Assessment.new(snapshot: @snapshot, at: @at, findings: findings)
      end

      private

      # 转换受约束的检查返回值；空 Hash 仍表示已命中的问题。
      def evaluate(name, options, view, context)
        handler = options.fetch(:handler)
        result = handler.is_a?(Symbol) ? send(handler, view, context) : handler.call(view, context)
        unless result == true || result == false || result.is_a?(Hash)
          raise ArgumentError, "#{name} 检查必须返回 true、false 或证据 Hash"
        end
        Finding.new(check: name, rule_id: view.id, status: result == false ? :pass : :fail,
                    severity: options[:severity], message: options[:message],
                    evidence: result.is_a?(Hash) ? result : {}, remediation: options[:remediation])
      rescue Analysis::Unknown, Elements::Group::UnresolvedReference => error
        Finding.new(check: name, rule_id: view.id, status: :unknown, severity: options[:severity],
                    message: error.message, evidence: { code: error.respond_to?(:code) ? error.code : :unresolved_reference })
      end
    end
  end
end
