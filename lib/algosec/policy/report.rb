# frozen_string_literal: true

require_relative "result"

module Algosec
  module Policy
    class Report
      attr_reader :results, :comment, :error, :skipped

      # 创建成功或失败报告；失败报告不允许同时携带部分结果。
      def initialize(results: [], error: nil, comment: nil, skipped: [], expected: nil)
        raise ArgumentError, "查询报告只能包含 Result" unless results.is_a?(Array) && results.all? { |item| item.is_a?(Result) }
        raise ArgumentError, "失败报告不能包含部分结果" if error && !results.empty?
        raise ArgumentError, "跳过记录必须是数组" unless skipped.is_a?(Array)
        raise ArgumentError, "失败报告不能包含部分覆盖记录" if error && !skipped.empty?
        @results, @error = results.dup.freeze, error
        omissions = Value.copy(skipped)
        @complete = success? && !results.empty?
        if expected
          evaluated = evaluated_combinations
          expected.each do |combination, devices|
            missing = devices - evaluated.fetch(combination, [])
            @complete = false if devices.empty? || !missing.empty?
            missing.each do |device_id|
              omissions << { device_id: device_id, source: combination[0], destination: combination[1], service: combination[2], reason: :unmatched }
            end
          end
        else
          @complete &&= omissions.empty?
        end
        @skipped = Value.immutable(omissions)
        @comment = (comment || error&.message || "正常").dup.freeze
        freeze
      end

      # 判断报告是否没有错误。
      def success? = error.nil?

      # 成功只表示计算未失败；完整还要求原始组合在所有实际经过的设备上得到评估。
      def complete? = @complete

      # 返回领域错误码，普通异常统一归为查询失败。
      def error_code
        return unless error
        error.respond_to?(:code) ? error.code : :search_failed
      end

      private

      # 依据 origin 核对需求，NAT 后地址和端口不能代替原始查询身份。
      def evaluated_combinations
        results.each_with_object({}) do |result, combinations|
          origins = Result::DIMENSIONS.map { |dimension| result.public_send(dimension).values.map { |entry| entry[:origin] }.uniq }
          origins.first.product(*origins.drop(1)) do |combination|
            (combinations[combination] ||= []) << result.device_id
          end
        end
      end
    end
  end
end
