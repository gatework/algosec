# frozen_string_literal: true

require_relative "../../policy"
require_relative "nat/generation"

module Algosec
  module Vendors
    module PaloAlto
      # 生成本地安全策略与地址/端口 NAT；区域和原始流量范围必须能明确确定。
      class Generator < Algosec::Policy::Generator
        command_policy placement: :append, permit: "allow", deny: "deny"
        command_frame before: [ "configure" ], after: [ "commit" ]
        command_operation :remove_rule, using: :remove_rule

        def create_rule
          members = prepare(result.actions.fetch(:new))
          require_members!(members)
          prefix = "set rulebase security rules #{quoted(rule_name)}"
          emit("#{prefix} from #{quoted(result.from_zone)}", "#{prefix} to #{quoted(result.to_zone)}")
          write_members(prefix, members)
          emit("#{prefix} application any", "#{prefix} action #{policy_action}")
          schedule = create_schedule
          emit("#{prefix} schedule #{quoted(schedule)}") if schedule
          blocker = result.conflicting_rules.find { |rule| metadata(rule)["family"] != "default-security-rules" }
          if blocker
            ensure_local!(blocker)
            emit("move rulebase security rules #{quoted(rule_name)} before #{quoted(blocker.name)}")
          end
          local = snapshot.rules.select { |rule| [ nil, "vsys1/rulebase" ].include?(rule.rule_set) }
          manual = !snapshot.parsed? && local.map { |rule| [ rule.rule_set, rule.scope ] }.uniq.one?
          record_created_rule(name: rule_name, placement: :before_terminal, rule_set: manual ? local.first.rule_set : "vsys1/rulebase",
            scope: manual ? local.first.scope : Algosec::Elements::Scope.new(device_id: snapshot.device_id, virtual_system: "vsys1", rulebase: "rulebase"), before: blocker)
        end

        def modify_rule
          ensure_local!(result.rule)
          members = prepare(result.actions[:add])
          create_nat_only
          write_members("set rulebase security rules #{quoted(result.rule.name)}", members)
        end

        def remove_rule(rule)
          ensure_local!(rule)
          emit("delete rulebase security rules #{quoted(rule.name)}")
        end

        def create_address(value, dimension:)
          parts = address_parts(value)
          # PAN 的原生 any 同时匹配 IPv6；IPv4 请求保留显式 0.0.0.0/0 对象。
          define_object(:address, parts[:set], "addr_#{parts[:text]}", type: [ Algosec::Elements::AddressObject, Algosec::Elements::AddressGroup ]) do |name|
            field = parts[:prefix] ? "ip-netmask" : "ip-range"
            command = "set address #{quoted(name)} #{field} #{parts[:text]}"
            emit(command)
            @nat_builder.object(command)
          end
        end

        def create_service(value)
          return "any" if %w[any 0].include?(value.downcase)
          parts = service_parts(value)
          unless %w[tcp udp].include?(parts[:protocol])
            raise Algosec::Policy::Error, "PAN-OS 非 TCP/UDP 服务需要 App-ID，不能生成纯端口规则"
          end
          define_object(:service, parts, "#{parts[:protocol]}_#{parts[:text]}", type: [ Algosec::Elements::ServiceObject, Algosec::Elements::ServiceGroup ]) do |name|
            command = "set service #{quoted(name)} protocol #{parts[:protocol]} port #{parts[:text]}"
            emit(command)
            @nat_builder.object(command)
          end
        end

        def create_schedule
          schedule_name do |name, schedule|
            emit("set schedule #{quoted(name)} schedule-type non-recurring #{schedule.start_at.strftime('%Y/%m/%d@%H:%M')}-#{schedule.end_at.strftime('%Y/%m/%d@%H:%M')}")
          end
        end

        def create_static_nat(_record, direction:)
          real, mapped = equal_nat_ranges!(_record)
          unless real[:set].cardinality == 1 && mapped[:set].cardinality == 1
            raise Algosec::Policy::Error, "PAN-OS 静态源 NAT 设计目前需要单个原地址和转换地址"
          end
          write_source_nat(_record, direction: direction, mode: "static-ip")
        end

        def create_dynamic_nat(groups, direction:)
          groups.flatten.each { |record| write_source_nat(record, direction: direction, mode: "dynamic-ip-and-port") }
        end

        protected

        def prepare_batch(results)
          @nat_builder = Nat::Generation.new(snapshot)
        end

        private

        def record_pan_nat(offset, expectations)
          @nat_evidence << @nat_builder.rule(commands: commands.drop(offset), expectations: expectations)
        rescue Algosec::Policy::Error, ArgumentError => error
          record_proof_issue(error)
        end

        # 同一 PAN-OS NAT 规则同时执行源、目的转换，不能生成两条依次匹配的规则。
        def create_nat(records, direction)
          action = result.actions&.fetch(:new, {}) || {}
          return super unless action[:nat_destinations]&.any?
          once([ :destination_nat, action, result.sources, result.destinations, result.services ]) do
            write_destination_nat(action)
          end
        end

        # 发布单主机服务；NAT 区域来自公网地址路由，安全策略仍使用服务器区域。
        def write_destination_nat(action)
          raise Algosec::Policy::Error, "PAN-OS NAT 不支持时间计划" if result.schedule
          records = action.fetch(:nat_destinations).values
          public_set = Algosec::Policy::Ranges.addresses(records.map { |record| record.fetch(:nat).fetch(:address) })
          unless public_set == Algosec::Policy::Ranges.addresses(result.destinations.keys)
            raise Algosec::Policy::Error, "目的 NAT 请求必须使用转换前地址，混合目标需分别设计"
          end
          sources = Algosec::Policy::Ranges.addresses(result.sources.keys)
          source_records = action.fetch(:nat_sources, {}).values
          source_record = source_records.first
          if source_records.size > 1 || (source_record && address_parts(source_record.fetch(:real_ip))[:set] != sources)
            raise Algosec::Policy::Error, "组合 NAT 需要完整且唯一的源转换分配"
          end
          if result.sources.values.any? { |entry| entry[:nat] } && !source_record
            raise Algosec::Policy::Error, "不能将已有源 NAT 与新目的 NAT 当作两条连续转换规则"
          end
          if source_record
            nat = source_record.fetch(:nat)
            unless %i[static dynamic].include?(nat[:type]) && !nat[:option] && !nat[:pool_name]
              raise Algosec::Policy::Error, "组合 NAT 的源转换分配不受支持"
            end
            if nat[:type] == :static
              real, mapped = equal_nat_ranges!(source_record)
              unless real[:set].cardinality == 1 && mapped[:set].cardinality == 1
                raise Algosec::Policy::Error, "组合静态源 NAT 需要单主机映射"
              end
            end
          end
          records.each do |record|
            nat = record.fetch(:nat)
            unless %i[static dynamic].include?(nat[:type]) && !nat[:option] && !nat[:pool_name]
              raise Algosec::Policy::Error, "目的 NAT 分配包含不支持的转换条件"
            end
            real, mapped = [ record.fetch(:real_ip), nat.fetch(:address) ].map { |ip| address_parts(ip) }
            unless [ real, mapped ].all? { |part| part[:set].cardinality == 1 }
              raise Algosec::Policy::Error, "目的 NAT 设计目前需要单个公网地址与服务器地址"
            end
            before_zone = routed_zone(mapped[:text])
            unless routed_zone(real[:text]) == result.to_zone
              raise Algosec::Policy::Error, "目的 NAT 服务器路由与安全策略目的区域不一致"
            end
            result.services.sort.each do |value, service|
              original = Algosec::Policy::Ranges.normalize_service(service.fetch(:origin, value))
              translated_port = service[:translated_port]
              translated_port = Algosec::Policy::Ranges.normalize_ports(translated_port.to_s) unless translated_port.nil?
              if translated_port
                ports = [ service_parts(original), service_parts("#{original.split('/').first}/#{translated_port}") ]
                unless ports.all? { |part| part[:first] == part[:last] }
                  raise Algosec::Policy::Error, "目的端口转换需要单个原端口和目标端口"
                end
              end
              validate_nat_overlap!(sources, [ mapped[:text] ], original, to_zone: before_zone)
              registry.claim(:panos_publication, [ result.from_zone, before_zone, mapped[:text], original ],
                [ real[:text], translated_port, source_record&.fetch(:nat) ],
                message: "同一公网地址和服务存在不同 NAT 分配，需要拆分并明确优先级") { nil }
              key = [ result.from_zone, before_zone, result.sources.keys.sort, mapped[:text], real[:text], original, translated_port, source_record ]
              define_object(:nat, key, stable_name("dnat", key), type: Algosec::Elements::DynamicNat) do |name|
                offset = commands.size
                src_names = result.sources.keys.sort.map { |ip| reusable_address(ip, dimension: :sources) }
                destination = reusable_address(mapped[:text], dimension: :destinations)
                service_name = create_service(original)
                prefix = "set rulebase nat rules #{quoted(name)}"
                emit("#{prefix} from #{quoted(result.from_zone)}", "#{prefix} to #{quoted(before_zone)}",
                  "#{prefix} source [ #{src_names.map { |item| quoted(item) }.join(' ')} ]",
                  "#{prefix} destination #{quoted(destination)}", "#{prefix} service #{quoted(service_name)}",
                  "#{prefix} destination-translation translated-address #{real[:text]}")
                emit("#{prefix} destination-translation translated-port #{translated_port}") if translated_port
                write_combined_source(prefix, source_record) if source_record
                translated_service = translated_port ? "#{original.split('/').first}/#{translated_port}" : original
                options = { result: result, before_zone: before_zone, service: translated_service,
                  original: original, translated_port: translated_port, public_destination: mapped[:text] }
                targets = [ @nat_builder.expectation(record: record, direction: :destination, **options) ]
                targets << @nat_builder.expectation(record: source_record, direction: :source, **options) if source_record
                record_pan_nat(offset, targets)
              end
            end
          end
        end

        # 使用入口 VRF 的最长前缀路由；等价多出口、跨 VRF、PBF 均不猜测。
        def routed_zone(address)
          vrf = snapshot.zone(result.from_zone).vrf
          raise Algosec::Policy::Error, "NAT 设计缺少入口 VRF" unless vrf
          routes = snapshot.routes.select { |route| route.vrf == vrf }
          raise Algosec::Policy::Error, "NAT 设计需要先解析策略路由" if routes.any?(&:policy?)
          candidates = routes.select { |route| route.covers?(address) }
          rank = ->(route) { [ -(route.prefix || 32), route.distance, route.priority ] }
          best = candidates.min_by(&rank)
          winners = best ? candidates.select { |route| rank.call(route) == rank.call(best) } : []
          zones = winners.map(&:zone).uniq
          unless winners.any? && zones.one? && zones.first && winners.none? { |route| route.destination_vrf && route.destination_vrf != vrf }
            raise Algosec::Policy::Error.new("NAT 地址 #{address} 缺少唯一可用的出口区域", code: :ambiguous_zone)
          end
          snapshot.zone(zones.first).name
        end

        def write_combined_source(prefix, record)
          nat = record.fetch(:nat)
          mode = nat[:type] == :static ? "static-ip" : "dynamic-ip-and-port"
          if nat[:address]
            emit("#{prefix} source-translation #{mode} translated-address #{address_parts(nat[:address])[:text]}")
          else
            interface = nat[:interface] || Algosec::Policy::Nat::Resolver.new(snapshot).interface(result.to_zone)
            unless snapshot.zone(result.to_zone).interfaces.values.any? { |item| item.name == interface }
              raise Algosec::Policy::Error, "组合 NAT 源转换接口不属于服务器出口区域"
            end
            emit("#{prefix} source-translation #{mode} interface-address interface #{quoted(interface)}")
          end
          emit("#{prefix} source-translation static-ip bi-directional no") if mode == "static-ip"
        end

        # 源 NAT 使用当前请求的全部匹配维度；不同服务拆成独立 NAT 规则。
        def write_source_nat(record, direction:, mode:)
          unless direction == :nat_sources && result.destinations.values.none? { |entry| entry[:nat] || entry[:translated_port] }
            raise Algosec::Policy::Error, "PAN-OS 目的或组合 NAT 设计需要明确转换前出口区域"
          end
          unsupported_port_nat!
          raise Algosec::Policy::Error, "PAN-OS NAT 不支持时间计划，不能自动生成限时转换" if result.schedule
          if record[:nat][:option] || record[:nat][:pool_name]
            raise Algosec::Policy::Error, "PAN-OS 源 NAT 不支持该厂商转换选项"
          end
          real = address_parts(record.fetch(:real_ip))
          unless Algosec::Policy::Ranges.addresses(result.sources.keys).cover?(real[:set])
            raise Algosec::Policy::Error, "源 NAT 地址超出请求范围"
          end
          mapped = record[:nat][:address]
          interface = record[:nat][:interface]
          interface ||= Algosec::Policy::Nat::Resolver.new(snapshot).interface(result.to_zone) unless mapped
          if interface && !snapshot.zone(result.to_zone).interfaces.values.any? { |item| item.name == interface }
            raise Algosec::Policy::Error, "源 NAT 接口不属于出口区域"
          end
          destinations = result.destinations.keys.sort
          result.services.keys.sort.each do |service|
            validate_nat_overlap!(real[:set], destinations, service)
            key = [ result.from_zone, result.to_zone, real[:text], destinations, service, mode, mapped, interface ]
            define_object(:nat, key, stable_name("snat", key), type: Algosec::Elements::DynamicNat) do |name|
              offset = commands.size
              source_name = reusable_address(real[:text], dimension: :sources)
              target_names = destinations.map { |ip| reusable_address(ip, dimension: :destinations) }
              service_name = create_service(service)
              prefix = "set rulebase nat rules #{quoted(name)}"
              emit("#{prefix} from #{quoted(result.from_zone)}", "#{prefix} to #{quoted(result.to_zone)}",
                "#{prefix} source #{quoted(source_name)}", "#{prefix} destination [ #{target_names.map { |item| quoted(item) }.join(' ')} ]",
                "#{prefix} service #{quoted(service_name)}")
              if mapped
                emit("#{prefix} source-translation #{mode} translated-address #{address_parts(mapped)[:text]}")
              else
                emit("#{prefix} source-translation #{mode} interface-address interface #{quoted(interface)}")
              end
              emit("#{prefix} source-translation static-ip bi-directional no") if mode == "static-ip"
              target = @nat_builder.expectation(record: record, direction: :source, result: result,
                before_zone: result.to_zone, service: service, original: service)
              record_pan_nat(offset, [ target ])
            end
          end
        end

        # 已有转换或免转换规则可能先命中；不擅自把新 NAT 插到它们之前。
        def validate_nat_overlap!(source, destinations, service, to_zone: result.to_zone)
          target = Algosec::Policy::Ranges.addresses(destinations)
          services = Algosec::Policy::Ranges.services([ service ])
          overlapping = snapshot.active_dynamic_nats.any? do |nat|
            from = nat.extra_conf.fetch("src_zones", [ nat.from_zone || "any" ])
            to = nat.extra_conf.fetch("dst_zones", [ nat.to_zone || "any" ])
            next false unless (from.include?("any") || from.include?(result.from_zone)) && (to.include?("any") || to.include?(to_zone))
            (!nat.source_set || nat.source_set.overlap?(source)) &&
              (!nat.destination_set || nat.destination_set.overlap?(target)) &&
              (!nat.service_set || nat.service_set.overlap?(services))
          end
          if overlapping || snapshot.static_nats.any?
            raise Algosec::Policy::Error.new("已有 NAT 与请求可能重叠，需要明确执行顺序", code: :nat_scope_conflict)
          end
        end

        def metadata(rule) = JSON.parse(rule.vendor_data.fetch("panos", "{}"))

        def write_members(prefix, members)
          { sources: "source", destinations: "destination", services: "service" }.each do |dimension, field|
            names = Array(members[dimension])
            emit("#{prefix} #{field} [ #{names.map { |name| quoted(name) }.join(' ')} ]") unless names.empty?
          end
        end

        def ensure_local!(rule)
          if rule.rule_set && rule.rule_set != "vsys1/rulebase"
            raise Algosec::Policy::Error, "PAN-OS 非本地规则不能使用本地修改命令"
          end
          if metadata(rule)["family"] == "default-security-rules" ||
             %w[negate-source negate-destination].any? { |key| metadata(rule)[key] == [ "yes" ] }
            raise Algosec::Policy::Error, "默认规则或地址取反规则不能通过普通成员增删修改"
          end
        end
      end
    end
  end
end
