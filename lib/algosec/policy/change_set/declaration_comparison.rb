# frozen_string_literal: true

require_relative "../../config/document"

module Algosec
  module Policy
    class ChangeSet
      # 独立读回按类型拥有者的声明协议比较，不用 Ruby 对象身份，也不把未知动作当相等。
      # 这只证明原有声明与相对顺序未变；所有变更区域仍交给 Evaluation。
      class DeclarationComparison
        def initialize(before, after)
          @before, @after = before, after
          @signatures = {}.compare_by_identity
          @nat_signatures = {}.compare_by_identity
        end

        def changed_rules
          left, right = @before.rules, @after.rules
          before = left.to_h { |rule| [ rule.identity, rule ] }
          after = right.to_h { |rule| [ rule.identity, rule ] }
          changed = left.reject { |rule| after[rule.identity] && signature(rule) == signature(after.fetch(rule.identity)) } +
            right.reject { |rule| before[rule.identity] && signature(rule) == signature(before.fetch(rule.identity)) }
          scopes = (left + right).group_by { |rule| [ @before.behavior.rule_chain(rule), rule.scope ] }
          scopes.each_value do |rules|
            ids = rules.map(&:identity) & before.keys & after.keys
            previous = left.select { |rule| ids.include?(rule.identity) }.sort_by { |rule| [ rule.rule_number || -1, rule.rule_id ] }.map(&:identity)
            current = right.select { |rule| ids.include?(rule.identity) }.sort_by { |rule| [ rule.rule_number || -1, rule.rule_id ] }.map(&:identity)
            ordered_before = left.select { |rule| ids.include?(rule.identity) }.map(&:rule_number)
            ordered_after = right.select { |rule| ids.include?(rule.identity) }.map(&:rule_number)
            order_known = [ ordered_before, ordered_after ].all? { |numbers| numbers.size < 2 || (numbers.none?(&:nil?) && numbers.uniq.size == numbers.size) }
            changed.concat(rules) unless order_known && previous == current
          end
          changed.uniq.freeze
        end

        def same_control_context?
          controls(@before) == controls(@after)
        end

        def declaration_digest(object) = signature(object)

        # NAT 的绝对源码行号不是执行语义；阶段和相对序列由调用方另行保留。
        def nat_declaration_digest(object) = signature(object, nat_root: true)

        private

        def controls(snapshot)
          snapshot.catalog.select { |element| element.is_a?(Elements::Zone) || element.is_a?(Elements::Interface) || element.is_a?(Elements::RuleBinding) }
            .map { |element| signature(element) }.sort
        end

        def signature(object, depth = 0, nat_root: false)
          cache = nat_root ? @nat_signatures : @signatures
          return cache[object] if cache.key?(object)
          raise ArgumentError, "Declaration graph exceeds comparison depth" if depth > 64
          kind, codec = Config::Document.codec_for(object)
          attributes = codec.attributes(object).reject { |name, _value| %w[description ref_count config_present rule_number reference_time].include?(name) }
          if nat_root
            attributes.delete("nat_order")
            attributes["native_stage"] = object.stage
            # 多段 position 的前缀保留原生阶段，最后一项由实际相对序列证明。
            attributes["native_order_prefix"] = object.position&.take(object.position.size - 1)
          end
          # action 是规范语义；原生命令别名不改变动作，但其他厂商条件必须保持。
          attributes.delete("native_action") if object.is_a?(Elements::SecurityRule) && object.action_known?
          edges = codec.edges(object).to_h do |name, edge|
            shape = codec.edge_types.fetch(name).first
            value = case shape
            when :named
              edge.map { |entry| [ entry.fetch("name"), entry["node"] && signature(entry["node"], depth + 1) ] }.sort_by(&:first)
            when :array then edge.map { |child| signature(child, depth + 1) }.sort
            else edge && signature(edge, depth + 1)
            end
            [ name, value ]
          end
          cache[object] = Config::Document::Value.digest({ "kind" => kind, "attributes" => attributes, "edges" => edges })
        end
      end
    end
  end
end
