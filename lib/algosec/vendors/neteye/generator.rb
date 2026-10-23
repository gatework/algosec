# frozen_string_literal: true

require_relative "../../policy"

module Algosec
  module Vendors
    module Neteye
      # Neteye 生成对象、策略和 NAT 命令。
      class Generator < Algosec::Policy::Generator
        command_policy placement: :append, permit: "permit", deny: "deny"
        command_frame before: [ "configure mode" ], after: [ "save config" ]
        command_fields sources: "sourceip object", destinations: "desip object", services: "protocol protocol-object"

        # 根据新规则结果生成该厂商的完整策略命令。
        def create_rule
          unsupported_schedule!
          members = prepare(result.actions.fetch(:new))
          require_members!(members)
          name = identifier(rule_name)
          left, right = %i[sources destinations].map do |dimension|
            member = members[dimension].first
            (member == "any") ? "any" : "object #{identifier(member)}"
          end
          service = members[:services].first
          service = (service == "any") ? "any" : "protocol-object #{identifier(service)}"
          emit("policy access #{name} #{identifier(result.from_zone)} #{left} #{identifier(result.to_zone)} #{right} #{service} #{policy_action} enable")
          append_members(name, members.transform_values { |values| values.is_a?(Array) ? values.drop(1) : values })
          emit("exit")
          record_created_rule(name: name)
        end

        # 把新增成员或 NAT 变更追加到已有策略，保留原规则范围。
        def modify_rule
          members = prepare(result.actions[:add])
          create_nat_only
          if Algosec::Policy::Result::DIMENSIONS.any? { |dimension| !members[dimension].empty? }
            append_members(identifier(result.rule.native_rule_id), members)
            emit("exit")
          end
        end

        # 按厂商语法创建或复用地址对象，并返回命令引用。
        def create_address(value, dimension:)
          parts = address_parts(value)
          return "any" if parts[:prefix] == 0
          definition = case parts[:prefix]
          when 32 then parts[:first]
          when nil then "#{parts[:first]}-#{parts[:last]}"
          else "subnet #{parts[:first]} #{IPAddr.netmask(parts[:prefix])}"
          end
          define_object(:address, parts[:set], address_name(parts), type: [ Algosec::Elements::AddressObject, Algosec::Elements::AddressGroup ]) do |name|
            emit("object ipaddr #{identifier(name)} #{definition}", "exit")
          end
        end

        # 按厂商语法创建或复用服务对象，并返回命令引用。
        def create_service(value)
          return "any" if %w[any 0].include?(value.downcase)
          parts = service_parts(value)
          preferred = "#{parts[:protocol].upcase}_#{parts[:text].tr("-", "_")}"
          define_object(:service, parts, preferred, type: [ Algosec::Elements::ServiceObject, Algosec::Elements::ServiceGroup ]) do |name|
            emit("object service #{identifier(name)} #{parts[:protocol]} #{ANY_PORTS} #{parts[:text]}", "exit")
          end
        end

        # 校验静态 NAT 范围后生成转换命令，并登记可复用对象。
        def create_static_nat(record, direction:)
          unsupported_port_nat!
          real, mapped = equal_nat_ranges!(record)
          key = [ real[:set], mapped[:set] ]
          define_object(:static_nat, key, "nat_#{mapped[:text]}", occupied: snapshot.static_nats.map(&:id)) do |name|
            emit("policy mip #{identifier(name)} #{real[:text]} #{mapped[:text]} enable")
          end
        end

        # 按方向和分配组生成动态 NAT 命令，保持请求分组边界。
        def create_dynamic_nat(groups, direction:)
          unsupported_port_nat!
          groups.flatten.each do |record|
            real = endpoint(record[:real_ip])
            mapped = record[:nat][:address] && endpoint(record[:nat][:address])
            nat_direction = (direction == :nat_sources) ? "snat" : "dnat"
            arguments = if direction == :nat_sources
                          target = mapped ? "iplist #{mapped}" : "interface #{identifier(record[:nat].fetch(:interface) { raise Algosec::Policy::Error, "源 NAT 缺少出口接口" })}"
                          "iplist #{real} #{target}"
            else
                          "#{mapped} #{real} enable"
            end
            key = [ nat_direction, arguments ]
            preferred = "#{nat_direction}_#{Digest::SHA256.hexdigest("#{nat_direction} #{arguments}")[0, 20]}"
            define_object(:dynamic_nat, key, preferred, occupied: snapshot.dynamic_nats.map(&:id)) do |name|
              emit("policy #{nat_direction} #{identifier(name)} #{arguments}", "exit")
            end
          end
          nil
        end

        private

        def append_members(name, members)
          command_fields.each do |dimension, field|
            members.fetch(dimension, []).each do |member|
              suffix = (member == "any") ? "#{field.split.first} any" : "#{field} #{identifier(member)}"
              emit("policy access #{name} #{suffix}")
            end
          end
        end

        def endpoint(value)
          parts = address_parts(value)
          (parts[:set].cardinality == 1) ? parts[:first] : "#{parts[:first]}-#{parts[:last]}"
        end
      end
    end
  end
end
