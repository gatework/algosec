# frozen_string_literal: true

require_relative "../security_rule"

module Algosec
  module Elements
    class Catalog
      # 一次装配持有独立的遍历状态；所有引用检查完成后，按子对象优先顺序应用。
      class ReferenceResolver
        # 保存一次解析的访问状态和待提交计划，避免部分引用先写入对象。
        def initialize(catalog, strict:, on_missing:, &resolver)
          @catalog, @strict, @on_missing, @resolver = catalog, strict, on_missing, resolver
          @visit_states, @resolution_plan = {}, []
        end

        # 遍历目录、检查循环和缺失引用，最后按子对象优先顺序提交结果。
        def resolve
          @catalog.each { |object| visit_object(object, []) }
          @resolution_plan.each do |object, resolved_value|
            if object.is_a?(SecurityRule)
              object.schedule = resolved_value
            else
              object.resolve!(strict: @strict) { |name| resolved_value.fetch(name) }
            end
          end
        end

        private

        # 以三色状态遍历对象图，访问中再次遇到同一对象即为循环。
        def visit_object(object, path, zone = nil)
          object_key = object.object_id
          raise Group::CircularReference, (path + [ object_label(object) ]).join(" -> ") if @visit_states[object_key] == :visiting
          return if @visit_states[object_key] == :done

          @visit_states[object_key] = :visiting
          chain = path + [ object_label(object) ]
          case object
          when SecurityRule then visit_rule(object, chain)
          when Group, AddressObject then visit_members(object, chain, zone)
          else object.dependencies.each { |child| visit_object(child, chain, zone) }
          end
          @visit_states[object_key] = :done
        end

        # 访问规则引用的各个组，并安排规则计划引用的延迟绑定。
        def visit_rule(rule, chain)
          visit_object(rule.sources, chain, rule.from_zones&.one? ? rule.from_zones.first : nil)
          visit_object(rule.destinations, chain, rule.to_zones&.one? ? rule.to_zones.first : nil)
          visit_object(rule.services, chain)
          if rule.schedule_name && !rule.schedule
            @resolution_plan << [ rule, resolve_reference(rule, rule.schedule_name, [ Schedule ], nil) ]
          end
        end

        # 访问组或地址的成员，先递归子对象，再记录本对象的提交计划。
        def visit_members(object, chain, zone)
          references = object.is_a?(Group) ? object.members : object.references
          types = object.is_a?(Group) ? [ object.member_class, object.group_class ] : [ AddressObject, AddressGroup ]
          zone = object.zone if object.respond_to?(:zone) && object.zone && object.zone != Base::ANY_ZONE
          candidate = references.to_h do |name, child|
            child ||= resolve_reference(object, name, types, zone)
            visit_object(child, chain, zone) if child
            [ name, child ]
          end
          object.dependencies.each { |child| visit_object(child, chain, zone) }
          @resolution_plan << [ object, candidate ]
        end

        # 在外部解析器和目录作用域中查找引用，并校验类型及设备归属。
        def resolve_reference(owner, name, types, zone)
          scope = { vendor: owner.vendor }
          scope[:device_id] = owner.device_id unless owner.device_id.nil?
          zones = if types.include?(AddressObject)
                    owner.address_reference_zones(zone)
          else
                    [ nil ]
          end
          found = @resolver&.call(owner, name, types.freeze)
          zones.each do |candidate_zone|
            break if found
            scoped = candidate_zone.nil? ? scope : scope.merge(zone: candidate_zone)
            found = types.lazy.map { |type| @catalog.find(type, name: name, **scoped) }.find(&:itself)
          end
          unless found
            raise Group::UnresolvedReference, "#{object_label(owner)} -> #{name}" if @strict
            @on_missing&.call(owner, name)
            return nil
          end
          raise ArgumentError, "Reference has the wrong type" unless types.any? { |type| found.is_a?(type) }
          raise ArgumentError, "Reference belongs to another vendor" if owner.vendor != found.vendor
          if owner.device_id && found.device_id && owner.device_id != found.device_id
            raise ArgumentError, "Reference belongs to another device"
          end
          found
        end

        # 用类型和身份字段生成稳定、可读的循环或缺失引用路径。
        def object_label(object) = "#{object.class.name.split("::").last}(#{object.identity_fields.join(", ")})"
      end

      private_constant :ReferenceResolver
    end
  end
end
