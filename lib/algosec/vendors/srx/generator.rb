# frozen_string_literal: true

require_relative "../../policy"

module Algosec
  module Vendors
    module Srx
      # SRX 生成地址簿、应用、策略、时间和 NAT 命令。
      class Generator < Algosec::Policy::Generator
        command_policy placement: :append, permit: "permit", deny: "deny"
        command_operation :remove_rule, using: :remove_rule
        command_frame before: [ "configure" ], after: [ "commit check", "commit", "exit" ]
        command_fields sources: "source-address", destinations: "destination-address", services: "application"

        # SRX 的规则身份包含区域对，不能只按策略名称删除。
        def remove_rule(rule)
          unless rule.from_zones&.one? && rule.to_zones&.one?
            raise Algosec::Policy::Error, "SRX 回收需要明确的区域对"
          end
          from, to, name = [ rule.from_zones.first, rule.to_zones.first, rule.name ].map { |value| literal_identifier(value) }
          emit("delete security policies from-zone #{from} to-zone #{to} policy #{name}")
        end

        # 根据新规则结果生成该厂商的完整策略命令。
        def create_rule
          members = prepare(result.actions.fetch(:new))
          require_members!(members)
          schedule = create_schedule
          prefix = policy_prefix(rule_name)
          write_members(prefix, members)
          emit("#{prefix} then #{policy_action}")
          emit("#{prefix} scheduler-name #{identifier(schedule)}") if schedule
          record_created_rule(name: rule_name)
        end

        # 把新增成员或 NAT 变更追加到已有策略，保留原规则范围。
        def modify_rule
          members = prepare(result.actions[:add])
          create_nat_only
          write_members(policy_prefix(result.rule.name), members)
        end

        # 按厂商语法创建或复用地址对象，并返回命令引用。
        def create_address(value, dimension:)
          parts = address_parts(value)
          return "any" if parts[:prefix] == 0
          zone = (dimension == :sources) ? result.from_zone : result.to_zone
          definition = parts[:prefix] ? parts[:text] : "range-address #{parts[:first]} to #{parts[:last]}"
          define_object(:address, [ zone, parts[:set] ], address_name(parts), type: [ Algosec::Elements::AddressObject, Algosec::Elements::AddressGroup ], zone: zone) do |name|
            emit("set security zones security-zone #{identifier(zone)} address-book address #{identifier(name)} #{definition}")
          end
        end

        # 按厂商语法创建或复用服务对象，并返回命令引用。
        def create_service(value)
          return "any" if %w[any 0].include?(value.downcase)
          parts = service_parts(value)
          preferred = "#{parts[:protocol].upcase}_#{parts[:text]}"
          define_object(:service, parts, preferred, type: [ Algosec::Elements::ServiceObject, Algosec::Elements::ServiceGroup ]) do |name|
            prefix = "set applications application #{identifier(name)} term #{identifier(name)}"
            emit("#{prefix} protocol #{parts[:protocol]}", "#{prefix} source-port #{ANY_PORTS}", "#{prefix} destination-port #{parts[:first]}-#{parts[:last]}")
          end
        end

        # 把一次性时间条件转换为厂商计划命令。
        def create_schedule
          schedule_name do |name, schedule|
            emit("set schedulers scheduler #{identifier(name)} start-date #{schedule.start_at.strftime("%Y-%m-%d.%H:%M")} stop-date #{schedule.end_at.strftime("%Y-%m-%d.%H:%M")}")
          end
        end

        # 校验静态 NAT 范围后生成转换命令，并登记可复用对象。
        def create_static_nat(record, direction:)
          unsupported_port_nat!
          real, mapped = equal_nat_ranges!(record)
          unless real[:prefix] && mapped[:prefix]
            raise Algosec::Policy::Error.new("SRX 静态 NAT 需要对齐的等长网段", code: :unsupported_nat_range)
          end
          external_zone = (direction == :nat_sources) ? result.to_zone : result.from_zone
          rule_set = nat_rule_set(:static, record[:rule_set], external_zone)
          key = [ rule_set, real[:set], mapped[:set] ]
          define_object(:static_nat, key, stable_name("host", key), occupied: snapshot.static_nats.map(&:name)) do |name|
            prefix = "set security nat static rule-set #{identifier(rule_set)} rule #{identifier(name)}"
            emit("#{prefix} match destination-address #{mapped[:text]}", "#{prefix} then static-nat prefix #{real[:text]}")
          end
        end

        # 按方向和分配组生成动态 NAT 命令，保持请求分组边界。
        def create_dynamic_nat(groups, direction:)
          kind = (direction == :nat_sources) ? :source : :destination
          groups.each do |records|
            nat = records.first[:nat]
            rule_set = nat_rule_set(kind, records.first[:rule_set], result.from_zone)
            ports = (kind == :destination && (nat[:option].to_s.include?("p") || result.services.values.any? { |record| record[:translated_port] })) ? port_mappings : [ nil ]
            ports.each do |port|
              target = if kind == :source
                         nat[:address] && Algosec::Policy::Ranges.addresses([ nat[:address] ])
              else
                         Algosec::Policy::Ranges.addresses(records.map { |record| record[:real_ip] })
              end
              pool = target ? "pool #{identifier(create_pool(kind, target, port: port&.fetch(:after)))}" : "interface"
              key = [ kind, rule_set, records.map { |record| record[:real_ip] }.sort, nat.except(:rule), port,
                     result.sources.keys.sort, result.destinations.keys.sort ]
              define_object(:dynamic_nat, key, stable_name("rule", key), occupied: snapshot.dynamic_nats.map(&:name)) do |name|
                prefix = "set security nat #{kind} rule-set #{identifier(rule_set)} rule #{identifier(name)}"
                if kind == :source
                  emit_matches(prefix, "source-address", Algosec::Policy::Ranges.addresses(records.map { |record| record[:real_ip] }))
                  emit_matches(prefix, "destination-address", Algosec::Policy::Ranges.addresses(result.destinations.keys)) if nat[:option].to_s.include?("d")
                else
                  emit_matches(prefix, "destination-address", Algosec::Policy::Ranges.addresses([ nat.fetch(:address) ]))
                  emit_matches(prefix, "source-address", Algosec::Policy::Ranges.addresses(result.sources.keys)) if nat[:option].to_s.include?("s")
                  emit("#{prefix} match protocol #{port[:protocol]}", "#{prefix} match destination-port #{port[:before]}") if port
                end
                emit("#{prefix} then #{kind}-nat #{pool}")
              end
            end
          end
          nil
        end

        protected

        def reusable_address_in_zone?(object, zone) = [ zone, "Global" ].include?(object.zone)

        private

        def policy_prefix(name)
          "set security policies from-zone #{identifier(result.from_zone)} to-zone #{identifier(result.to_zone)} policy #{identifier(name)}"
        end

        def write_members(prefix, members)
          emit(*member_commands(members, prefix: "#{prefix} match", quote: :identifier))
        end

        def nat_rule_set(kind, requested, from_zone)
          return identifier(requested) if requested
          key = [ kind, from_zone, (kind == :source) ? result.to_zone : nil ]
          occupied = (snapshot.static_nats + snapshot.dynamic_nats).map(&:rule_set).compact
          define_object(:rule_set, key, "#{from_zone}_#{(kind == :source) ? result.to_zone : kind}", occupied: occupied) do |name|
            prefix = "set security nat #{kind} rule-set #{identifier(name)}"
            emit("#{prefix} from zone #{identifier(from_zone)}")
            emit("#{prefix} to zone #{identifier(result.to_zone)}") if kind == :source
          end
        end

        def emit_matches(prefix, field, set)
          cidrs(set).each { |ip, mask| emit("#{prefix} match #{field} #{ip}/#{mask}") }
        end

        def create_pool(kind, set, port: nil)
          existing = snapshot.elements(Algosec::Elements::NatPool).sort_by(&:name).find do |pool|
            pool.direction == kind && pool.set == set && pool.port == port
          end
          return existing.name if existing
          key = [ kind, set, port ]
          define_object(:pool, key, stable_name("#{kind}nat_pool", key), type: Algosec::Elements::NatPool) do |name|
            prefix = "set security nat #{kind} pool #{identifier(name)} address"
            set.each do |range|
              emit("#{prefix} #{IPAddr.from_i(range.begin)}/32 to #{IPAddr.from_i(range.end)}/32")
            end
            emit("#{prefix} port #{port}") if port
          end
        end
      end
    end
  end
end
