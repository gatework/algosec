# frozen_string_literal: true

require "json"
require_relative "../version"
require_relative "value"
require_relative "definition"
require_relative "../elements"

module Algosec
  module Policy
    class Snapshot
      attr_reader :device_id, :vendor, :version, :software_version, :revision, :catalog, :builtin_services, :settings, :definition, :time_zone

      # 校验配置快照和内建服务的设备范围，并完成目录引用解析。
      def initialize(device_id:, vendor:, catalog:, version: nil, software_version: version, revision: nil, builtin_services: [], settings: {}, definition: nil, resolve_references: true, time_zone: nil, parsed: false, complete: nil)
        raise ArgumentError, "设备编号必须为正整数" unless device_id.is_a?(Integer) && device_id.positive?
        raise ArgumentError, "解析来源标志必须为布尔值" unless parsed == true || parsed == false
        complete = true if complete.nil? && !parsed
        raise ArgumentError, "配置完整性必须为布尔值，解析快照需显式提供" unless complete == true || complete == false
        @parsed, @complete = parsed, complete
        @vendor, @definition = Definition.resolve(vendor, explicit: definition)
        @device_id, @version = device_id, version&.to_s&.freeze
        @time_zone = time_zone && Time.find_zone!(time_zone).name.freeze
        @software_version = software_version&.to_s&.dup&.freeze
        @revision = revision && Value.text(revision, label: "配置修订标识").dup.freeze
        raise ArgumentError, "配置快照必须使用 Catalog" unless catalog.is_a?(Elements::Catalog)
        unless builtin_services.is_a?(Array) && builtin_services.all? { |service| service.is_a?(Elements::ServiceObject) }
          raise ArgumentError, "内置服务必须是 Service 数组"
        end
        @catalog, @builtin_services = catalog, builtin_services.dup.freeze
        @settings = Value.immutable(Value.hash(settings))
        (catalog.to_a + builtin_services).each do |element|
          if element.vendor != @vendor || (element.device_id && element.device_id != device_id)
            raise ArgumentError, "配置快照包含其他设备或厂商的对象"
          end
        end
        return unless resolve_references && !catalog.sealed?
        service_index = services.to_h { |service| [ behavior.service_name_key(service.name), service ] }
        catalog.resolve! do |_owner, name, types|
          service_index[behavior.service_name_key(name)] if types.include?(Elements::ServiceObject)
        end
      end

      # 候选目录使用相同设备、解析完整性和上下文；不重建未修改的对象图。
      def with_catalog(catalog)
        self.class.new(device_id: device_id, vendor: vendor, catalog: catalog,
          version: version, software_version: software_version, revision: revision,
          builtin_services: builtin_services, settings: settings, definition: definition,
          time_zone: time_zone, parsed: parsed?, complete: complete?, resolve_references: false)
      end

      # 延迟创建当前快照对应的查询行为对象。
      def behavior = @behavior ||= definition.behavior(self)

      # 配置中的缺失也是证据，不能让人工设置为实际未绑定的规则链补造作用域。
      def parsed? = @parsed

      # 对象目录可以供检查，但已知子集不能替代完整配置证据。
      def complete? = @complete

      # 计划、效果证明和执行预检共享快照上下文，时区也参与审批绑定。
      def baseline
        Value.immutable(device_id: device_id, vendor: vendor, revision: revision,
          software_version: software_version, settings: settings, time_zone: time_zone, semantic_version: Algosec::SEMANTIC_VERSION)
      end

      def require_complete!
        raise Error.new("配置解析不完整，不能据此判断策略或生成命令", code: :incomplete_configuration) unless complete?
        self
      end

      # 返回指定类型的目录对象。
      def elements(type) = catalog.select { |element| element.is_a?(type) }

      # 返回按稳定签名排序的规则。
      def rules = elements(Elements::SecurityRule).reject(&:container?).sort_by { |rule| signature(rule) }

      # 规则库引用本快照对象；作用域筛选不凭规则名推断执行位置。
      def rulebase(from_zone:, to_zone:, rule_set: nil, scope: nil)
        require_complete!
        selected = rules
        selected = selected.select { |rule| behavior.rule_chain(rule) == rule_set || behavior.rule_set_matches?(rule, rule_set) } if rule_set
        if scope
          raise ArgumentError, "Rulebase scope must be a Scope" unless scope.is_a?(Elements::Scope)
          if scope.device_id && scope.device_id != device_id
            raise ArgumentError, "Rulebase scope belongs to another device"
          end
          selected = selected.select { |rule| scope.to_h.all? { |key, value| value.nil? || rule.scope.public_send(key) == value } }
        end
        bindings = elements(Elements::RuleBinding).select do |binding|
          binding.from_zone == from_zone && binding.to_zone == to_zone && (!rule_set || binding.rule_set == rule_set)
        end
        Elements::Rulebase.new(rules: selected, scope: scope || Elements::Scope.new(device_id: device_id),
          behavior: behavior, from_zone: from_zone, to_zone: to_zone, native_bindings: bindings, rule_set: rule_set)
      end

      # 返回地址对象。
      def addresses = elements(Elements::AddressObject)

      # 按厂商优先级返回可引用服务名称；同层歧义不能任取一项。
      def services
        names = {}
        sources = { service: elements(Elements::ServiceObject), service_group: elements(Elements::ServiceGroup), builtin: builtin_services }
        behavior.service_priority.each do |source|
          objects = sources.fetch(source)
          objects.group_by { |service| behavior.service_name_key(service.name) }.each do |key, candidates|
            next if names.key?(key)
            candidates = candidates.uniq(&:identity)
            if candidates.size > 1
              raise Elements::Catalog::AmbiguousReference, "Service #{key.inspect} matches #{candidates.size} objects"
            end
            names[key] = candidates.first
          end
        end
        names.values
      end

      # 共同协议返回目录中的同一 NAT 实例，保持引用和发布状态。
      def nat_rules = elements(Elements::NatRule)

      # 返回静态 NAT 对象。
      def static_nats = elements(Elements::StaticNat)

      # 禁用映射保留在目录中供依赖审查，查询和分配只使用生效映射。
      def active_static_nats = static_nats.reject(&:disabled?)

      # 返回动态 NAT 对象。
      def dynamic_nats = elements(Elements::DynamicNat)

      # 匹配只使用启用的 NAT；依赖和迁移检查仍需保留禁用记录。
      def active_dynamic_nats = dynamic_nats.reject(&:disabled?)

      # 返回路由对象。
      def routes = elements(Elements::Route)

      # 按名称取得区域。
      def zone(name) = catalog.fetch(Elements::Zone, name: name)

      # 路由域由区域中的接口决定；安全域名称不能替代入口 VRF。
      def vrf(zone_name)
        scope = zone(zone_name)
        vrfs = scope.interfaces.values.map(&:vrf).uniq
        if vrfs.size > 1
          raise Error.new("安全域 #{zone_name} 包含多个路由域，需要明确流量入口", code: :conditional_route)
        end
        vrfs.first || scope.vrf
      end

      # 递归跨域路由的 destination_vrf 是首个目标，最终出口由接口决定。
      def egress_vrf(route)
        return route.destination_vrf || route.vrf unless route.destination_interface

        target = catalog.find(Elements::Interface, name: route.destination_interface) ||
          elements(Elements::Zone).flat_map { |scope| scope.interfaces.values }.find { |item| item.name == route.destination_interface }
        unless target && (!target.zone || !route.zone || target.zone == route.zone)
          raise Error.new("路由出口接口 #{route.destination_interface} 不存在或所属区域不一致", code: :conditional_route)
        end
        target.vrf
      end

      # 按名称取得接口。
      def interface(name) = catalog.fetch(Elements::Interface, name: name)

      # 为规则生成稳定排序签名。
      def signature(element) = element.is_a?(Elements::SecurityRule) ? element.rule_id : JSON.generate(element.identity_fields)

      # 部分配置只开放检查；来源、完整性和时区始终从同一解析结果传入。
      def self.from_config(result, version: nil, software_version: version, revision: nil, builtin_services: [], settings: {}, definition: nil, allow_incomplete: false)
        raise ArgumentError, "allow_incomplete 必须是布尔值" unless allow_incomplete == true || allow_incomplete == false
        raise ArgumentError, "快照需要配置解析结果" unless result.respond_to?(:complete?)
        complete = result.complete?
        unless complete || allow_incomplete
          raise Error.new("配置解析不完整，不能据此判断策略或生成命令", code: :incomplete_configuration)
        end
        new(device_id: result.reader.device_id, vendor: result.reader.vendor,
            catalog: result.catalog, version: version, software_version: software_version, revision: revision, builtin_services: builtin_services, settings: settings,
            definition: definition, time_zone: result.time_zone || "UTC", parsed: true, complete: complete, resolve_references: complete && !result.catalog.sealed?)
      end
    end
  end
end
