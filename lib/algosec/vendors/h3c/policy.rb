# frozen_string_literal: true

require_relative "../../policy"

module Algosec
  module Vendors
    module H3c
      # 统一 H3C 规则链绑定、可修改范围和 NAT 区域判断。
      class Policy < Algosec::Policy::Behavior
        ADDRESS_MAPPING = { plain: :fallback, source_interface: true, destination_interface: :all,
                            keep_source: true, always_destination: true }.freeze

        def candidate?(rule, from_zone:, to_zone:)
          rule.action == "allow" && rule_in_zones?(rule, from_zone: from_zone, to_zone: to_zone)
        end

        def rule_in_zones?(rule, from_zone:, to_zone:)
          active_bindings(from_zone: from_zone, to_zone: to_zone).any? do |binding|
            binding.rule_type == rule.native_rule_type && binding.rule_set.casecmp?(rule.rule_set.to_s)
          end
        end

        def proof_zone_pairs(rule)
          bindings.select { |entry| entry.rule_type == rule.native_rule_type && entry.rule_set.casecmp?(rule.rule_set.to_s) }
            .map { |entry| [ [ entry.from_zone ], [ entry.to_zone ] ] }
        end

        # ACL 与对象策略即使同名也属于不同执行链。
        def rule_chain(rule) = [ rule.native_rule_type, rule.rule_set&.downcase ]

        def rule_set_matches?(rule, name) = !!rule.rule_set&.casecmp?(name)

        def service_name_key(name) = name.downcase

        def rule_scope(rule) = [ rule.scope, rule.rule_type, *rule_chain(rule), rule_pairs(rule.native_rule_type, rule.rule_set) ]

        def editable_rule?(rule, from_zone:, to_zone:)
          rule.native_rule_type == :object && exclusive_policy?(rule.rule_set, from_zone: from_zone, to_zone: to_zone) &&
            rule_in_zones?(rule, from_zone: from_zone, to_zone: to_zone)
        end

        # 单区域请求不能修改其他区域对共用的策略，也不能扩大 any 绑定。
        def exclusive_policy?(name, from_zone:, to_zone:)
          rule_pairs(:object, name) == [ [ from_zone.downcase, to_zone.downcase ] ] && ![ from_zone, to_zone ].any? { |zone| zone.casecmp?("any") }
        end

        # 配置中的精确绑定优先于人工设置；空策略同样参与选择和遮蔽判断。
        def bindings
          parsed = snapshot.elements(Algosec::Elements::RuleBinding)
          return parsed if snapshot.parsed? || !parsed.empty?

          declared = Array(snapshot.settings[:policy_bindings]).map do |entry|
            entry = Algosec::Policy::Value.hash(entry)
            binding(:object, entry.fetch(:name), entry.fetch(:from_zone), entry.fetch(:to_zone))
          end
          inferred = snapshot.rules.flat_map do |rule|
            next [] if declared.any? { |entry| entry.rule_type == rule.native_rule_type && entry.rule_set.casecmp?(rule.rule_set.to_s) }
            from, to = Array(rule.from_zones), Array(rule.to_zones)
            next [] if from.empty? || to.empty?
            unless from.one? && to.one?
              raise Algosec::Policy::Error.new("规则链 #{rule.rule_set} 缺少精确的区域对绑定", code: :conditional_policy)
            end
            [ binding(rule.native_rule_type, rule.rule_set, from.first, to.first) ]
          end
          (declared + inferred).uniq(&:identity)
        end

        # 具体区域对优先于 any-any；同一区域对的对象策略优先于 packet-filter。
        # 多条仍然冲突的链不能凭规则数量或名称排序猜选，空链也不能被忽略。
        def active_bindings(from_zone:, to_zone:)
          matches = bindings.select do |entry|
            wildcard = entry.from_zone.casecmp?("any") || entry.to_zone.casecmp?("any")
            next false if wildcard && (zone_equal?(from_zone, to_zone) || [ from_zone.downcase, to_zone.downcase ].sort == %w[local management])
            zone_matches?([ entry.from_zone ], from_zone) && zone_matches?([ entry.to_zone ], to_zone)
          end
          exact = matches.select { |entry| zone_equal?(entry.from_zone, from_zone) && zone_equal?(entry.to_zone, to_zone) }
          unless exact.empty?
            matches = matches.reject { |entry| entry.from_zone.casecmp?("any") && entry.to_zone.casecmp?("any") }
          end
          matches = matches.group_by { |entry| [ entry.from_zone.downcase, entry.to_zone.downcase ] }.flat_map do |_, entries|
            objects = entries.select { |entry| entry.rule_type == :object }
            objects.empty? ? entries : objects
          end
          if matches.map { |entry| [ entry.rule_type, entry.rule_set.downcase ] }.uniq.size > 1
            raise Algosec::Policy::Error.new("安全域 #{from_zone} 到 #{to_zone} 存在无法确定优先级的规则链", code: :unknown_order)
          end
          matches
        end

        # 映射端未声明区域时允许当前区域，否则必须精确相等。
        def static_nat_zone?(nat, zone)
          return nat.mapped_zone.nil? || nat.mapped_zone == zone if nat.interfaces.nil?

          zone_interfaces = snapshot.zone(zone).interfaces.values.map(&:name)
          !(nat.interfaces & zone_interfaces).empty?
        end

        private

        def zone_equal?(actual, requested) = actual.casecmp?(requested)

        def rule_pairs(type, name)
          bindings.select { |entry| entry.rule_type == type && entry.rule_set.casecmp?(name.to_s) }
                  .map { |entry| [ entry.from_zone.downcase, entry.to_zone.downcase ] }.uniq.sort
        end

        def binding(type, name, from_zone, to_zone)
          Algosec::Elements::RuleBinding.new(vendor: snapshot.vendor, device_id: snapshot.device_id,
            rule_type: type, rule_set: name, from_zone: from_zone, to_zone: to_zone)
        end
      end
    end
  end
end
