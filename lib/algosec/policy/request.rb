# frozen_string_literal: true

require "active_support/core_ext/hash/except"
require "active_support/time"
require_relative "value"
require_relative "ranges"
require_relative "../elements"

module Algosec
  module Policy
    class Request
      # Any 地址的规范文本，避免在输入归一化中直接散落网络字面量。
      ANY_IPV4 = "0.0.0.0/0".freeze
      attr_reader :sources, :destinations, :services, :schedule

      # 复制并冻结地址、服务和时间条件，保证一次查询期间输入不再变化。
      def initialize(sources:, destinations:, services:, schedule: nil)
        @sources = Value.immutable(addresses(sources))
        @destinations = Value.immutable(addresses(destinations))
        @services = Value.immutable(service_map(services))
        @schedule = normalize_schedule(schedule)
        freeze
      end

      # 判断查询是否没有时间限制。
      def permanent? = schedule.nil?

      private

      # 同一条分配中的多个地址共享业务分组编号，各自持有独立的 NAT 元数据。
      def addresses(input)
        list!(input, "地址")
        input.each_with_index.each_with_object({}) do |(address_input, group), addresses|
          address_entry = address_input.is_a?(String) ? { addresses: [ address_input ] } : Value.hash(address_input)
          unknown!(address_entry, %i[addresses nat])
          values = address_entry.fetch(:addresses)
          list!(values, "地址")
          nat = normalize_nat(address_entry[:nat], multiple: values.size > 1, group: group)
          values.each do |value|
            key = address(value)
            address_record = { origin: key }
            address_record[:nat] = Value.copy(nat) if nat
            register!(addresses, key, address_record)
          end
        end
      end

      # 规范化服务列表，建立原始服务到可选转换端口的映射。
      def service_map(input)
        list!(input, "服务")
        input.each_with_object({}) do |service_input, services|
          service_entry = service_input.is_a?(String) ? { services: [ service_input ] } : Value.hash(service_input)
          unknown!(service_entry, %i[services translated_port])
          values = service_entry.fetch(:services)
          values = [ values ] if values.is_a?(String)
          list!(values, "服务")
          translated = service_entry[:translated_port]
          translated = Ranges.normalize_ports(translated.to_s) unless translated.nil?
          values.each do |value|
            key = Ranges.normalize_service(value)
            if translated && ![ IPAddr::TCP, IPAddr::UDP ].include?(IPAddr.protocol_number(key.split("/", 2).first))
              raise ArgumentError, "只有 TCP/UDP 服务能请求端口转换"
            end
            service_record = { origin: key }
            service_record[:translated_port] = translated unless translated.nil?
            register!(services, key, service_record)
          end
        end
      end

      # 规范化静态或动态 NAT 请求，并把同组地址标记为同一分配批次。
      def normalize_nat(nat_input, multiple:, group:)
        return if nat_input.nil?
        nat = Value.hash(nat_input)
        unknown!(nat, %i[type address option direction interface pool_name])
        nat[:type] = Value.symbol(nat.fetch(:type), label: "NAT 类型")
        raise ArgumentError, "NAT 类型必须是 static 或 dynamic" unless %i[static dynamic].include?(nat[:type])
        if multiple && nat[:type] == :static
          raise ArgumentError, "多地址静态 NAT 必须分别声明原始地址与转换地址配对"
        end
        nat[:address] = address(nat[:address]) if nat[:address]
        raise ArgumentError, "静态 NAT 必须指定转换地址" if nat[:type] == :static && !nat[:address]
        nat[:group] = group
        nat
      end

      # 把时间对象或时间字段转换为完整的一次性计划。
      def normalize_schedule(schedule_input)
        return if schedule_input.nil?
        if schedule_input.is_a?(Elements::Schedule)
          raise ArgumentError, "查询期限必须是完整的一次性时间段" unless schedule_input.kind == :once && schedule_input.window && !schedule_input.window.begin.negative? && schedule_input.window.begin <= schedule_input.window.end
          return schedule_input
        end
        fields = Value.hash(schedule_input)
        unknown!(fields, %i[start_at end_at time_zone])
        zone = Time.find_zone!(fields.fetch(:time_zone, "UTC"))
        dates = %i[start_at end_at].to_h do |key|
          field_value = fields.fetch(key)
          [ key, field_value.is_a?(String) ? zone.iso8601(field_value) : field_value ]
        end
        normalize_schedule(Elements::Schedule.new(name: "request", time_zone: zone, **dates))
      end

      # 规范化地址文本并拒绝空范围。
      def address(expression)
        text = Value.text(expression, label: "地址").strip
        text = ANY_IPV4 if text.casecmp?("any")
        set = IPAddr.parse(text)
        raise ArgumentError, "请求地址不能为空" if set.empty?
        IPAddr.format_range(set.first)
      end

      # 登记请求项，并拒绝同一键对应的冲突 NAT 或请求属性。
      def register!(map, key, record)
        if map.key?(key) && map[key].except(:nat) == record.except(:nat)
          previous = map[key][:nat]&.except(:group)
          current = record[:nat]&.except(:group)
          raise ArgumentError, "#{key} 存在互相冲突的 NAT 请求" unless previous == current
        elsif map.key?(key) && map[key] != record
          raise ArgumentError, "#{key} 存在互相冲突的请求"
        end
        map[key] ||= record
      end

      # 校验输入是非空数组。
      def list!(value, label)
        raise ArgumentError, "#{label}必须是非空数组" unless value.is_a?(Array) && !value.empty?
      end

      # 拒绝未声明的请求字段，避免静默忽略调用方错误。
      def unknown!(fields, allowed)
        unknown_fields = fields.keys - allowed
        raise ArgumentError, "未知请求字段：#{unknown_fields.join(", ")}" unless unknown_fields.empty?
      end
    end
  end
end
