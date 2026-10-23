# frozen_string_literal: true

require_relative "../snapshot"
require_relative "../ranges"
require_relative "service_query"
require_relative "embedded_selection"

module Algosec
  module Policy
    module Nat
      class Resolver
        attr_reader :snapshot

        # 保存当前配置快照，所有 NAT 查询都从同一份对象图读取。
        def initialize(snapshot)
          snapshot.require_complete!
          @snapshot = snapshot
        end

        # 返回内网地址对应的转换地址，保留原 NAT 对象供设计器判断复用。
        def find(address, zone:, peers: nil, direction: nil, services: nil, source_port: nil, mapped_source_port: nil, flow: {}, allocation: nil)
          target = IPAddr.parse(address)
          peer_set = peers && Ranges.addresses(peers.keys)
          options = { direction: direction, services: services, source_port: source_port, mapped_source_port: mapped_source_port }
          policies = snapshot.behavior.nat_policy_rules
          original = nat_flow(target, peer_set, zone, direction, flow, allocation: allocation) if policies && direction
          group_flow = nat_flow(target, peer_set, zone, direction, flow, allocation: allocation) if !policies && direction
          discovering = direction == :destination && (original || group_flow)[:destination].nil?
          aliases = []
          snapshot.behavior.nat_groups.each do |group|
            matches = group.filter_map do |nat|
              if original && direction == :destination && original[:destination]
                public_set = nat.is_a?(Elements::StaticNat) ? nat.mapped_set : nat.destination_set
                next unless public_set&.overlap?(original[:destination])
              end
              if nat.is_a?(Elements::StaticNat)
                static_match(nat, target, peer_set, zone, **options.slice(:direction, :services))
              elsif direction
                if group_flow
                  next if discovering && aliases.any? { |mapping| nat.destination_set && IPAddr.parse(mapping[:address]).cover?(nat.destination_set) }

                  group_dynamic_mapping(nat, target, peer_set, zone, flow: group_flow, **options)
                else
                  dynamic_match(nat, target, peer_set, zone, **options)
                end
              end
            end
            next aliases.concat(matches) if discovering
            next if matches.empty?

            mapping = unique_mapping(matches)
            validate_nat_allocation!(mapping, allocation, original, direction) if original
            validate_group_allocation!(mapping, allocation, group_flow, direction) if group_flow
            return mapping
          end
          if group_flow && discovering
            mapping = unique_mapping(aliases)
            validate_group_allocation!(mapping, allocation, group_flow, direction) if mapping
            return mapping
          end
          return unless policies && direction

          mapping = policy_mapping(policies, target, original, aliases: aliases, **options)
          mapping = unique_mapping([ *aliases, mapping ].compact) if discovering
          validate_nat_allocation!(mapping, allocation, original, direction) if mapping
          mapping
        end

        # 终结策略已选定时，另行分配不能使后置的新规则越过该规则。
        def terminal?(mapping)
          rules = snapshot.behavior.nat_policy_rules || snapshot.behavior.nat_groups.flatten
          mapping && rules.include?(mapping[:rule])
        end

        # 新建范围也须核对完整原始条件，不能覆盖已有转换或被它遮挡。
        def validate_new_policy!(sources:, destinations:, services:, from_zone:, to_zone:)
          policies = snapshot.behavior.nat_policy_rules
          return unless policies

          flow = { source: sources, destination: destinations, from_zone: from_zone, to_zone: to_zone, vrf: nil }.freeze
          ensure_server_clear!(flow, services: services, source_port: nil)
          nat = first_policy(policies, flow, services: services, source_port: nil)
          if nat
            raise Error.new("新建 NAT 范围与已有规则 #{snapshot.signature(nat)} 相交，需要明确合并或修改原规则", code: :nat_scope_conflict)
          end
        end

        # 身份还原等快捷路径没有消费转换动作，必须证明被跳过的一侧确实不转换。
        def guard_unchanged!(source:, destination:, directions:, services:, flow:, mappings: {})
          policies = snapshot.behavior.nat_policy_rules
          return if policies.nil? || directions.empty?

          original = nat_flow(IPAddr.parse(destination), IPAddr.parse(source), flow[:from_zone], :destination, flow.merge(original_dst: destination))
          consumed = mappings.reject { |side, mapping| directions.include?(side) || !mapping&.dig(:rule) }
          selected = consumed.values.map { |mapping| mapping[:rule] }.uniq
          servers = snapshot.behavior.nat_groups.flatten
          if selected.any? { |nat| servers.include?(nat) }
            unless selected.all? { |nat| servers.include?(nat) }
              raise Error.new("服务器映射与原生策略的组合转换尚未证明", code: :conditional_nat)
            end
            consumed.each { |side, mapping| verify_server_mapping!(mapping, original, direction: side, services: services) }
            ensure_server_clear!(original, services: services, source_port: nil, rules: servers - selected)
            ensure_server_clear!(original, services: services, source_port: nil, rules: selected, directions: directions)
            return
          end
          ensure_server_clear!(original, services: services, source_port: nil)
          nat = first_policy(policies, original, services: services, source_port: nil)
          if selected.any? { |rule| rule != nat }
            raise Error.new("两侧地址未使用同一条原始流量命中的 NAT 策略", code: :conditional_nat)
          end
          return unless nat && (nat.direction == :bidirectional || directions.include?(nat.direction))

          raise Error.new("当前地址路径未处理首条 NAT #{snapshot.signature(nat)} 的完整转换动作", code: :conditional_nat)
        end

        # 将映射地址反向还原为真实地址，并处理多映射歧义。
        def reverse(address, zone: nil, direction: nil)
          unless [ nil, :source, :destination ].include?(direction)
            raise ArgumentError, "Invalid reverse NAT direction"
          end
          target = IPAddr.parse(address)
          matches = snapshot.active_static_nats.filter_map do |nat|
            next if direction == :source && !snapshot.behavior.static_nat_source?(nat)
            next if zone && !snapshot.behavior.reverse_nat_zone?(nat, zone)

            overlap = nat.mapped_set & target
            validate_reverse!(nat) unless overlap.empty?
            [ nat, overlap ] unless overlap.empty?
          end
          unless matches.empty?
            covered = matches.reduce(Set.new) { |set, (_, overlap)| set | overlap }
            if covered != target || matches.map { |nat, _| nat.real_zone }.uniq.size > 1
              raise Error.new("地址 #{address} 的静态 NAT 映射不完整或跨越多个内部区域", code: :ambiguous_nat)
            end
            matches.combination(2) do |(left, left_range), (right, right_range)|
              shared = left_range & right_range
              next if shared.empty? || same_reverse_mapping?(left, right, shared)
              raise Error.new("地址 #{address} 对应多个内部 NAT 映射", code: :ambiguous_nat)
            end
            translated = matches.reduce(Set.new) { |set, (nat, overlap)| set | nat.reverse_translate(overlap) }
            return [ address_text(translated), matches.first.first.real_zone ]
          end
          if snapshot.behavior.strict_reverse_nat? || target.cardinality == 1
            raise Error.new("无法从静态 NAT 映射还原内部地址：#{address}", code: :nat_missing)
          end
          [ nil, nil ]
        end

        # 判断地址是否已经被静态 NAT 映射占用。
        def used?(address, zone:)
          target = IPAddr.parse(address)
          snapshot.active_static_nats.any? do |nat|
            snapshot.behavior.static_nat_zone?(nat, zone) && nat.mapped_set.overlap?(target)
          end
        end

        # 返回覆盖给定地址的动态 NAT 地址池。
        def pools(address, zone:)
          target = IPAddr.parse(address)
          snapshot.active_dynamic_nats.select do |nat|
            (nat.to_zone == zone && nat.source_set&.cover?(target)) ||
              (nat.from_zone == zone && nat.destination_targets&.cover?(target))
          end
        end

        # 判断某条策略是否使用给定 NAT 地址。
        def policy_uses?(address, direction:, nat:)
          target = IPAddr.parse(address)
          from = nat.respond_to?(:from_zone) ? nat.from_zone : nat.real_zone
          to = nat.respond_to?(:to_zone) ? nat.to_zone : nat.mapped_zone
          snapshot.rules.any? do |rule|
            next false unless rule.from_zones == [ from ] && rule.to_zones == [ to ]
            group = (direction == :source) ? rule.sources : rule.destinations
            group.resolved_set.cover?(target)
          end
        end

        # 返回指定区域和方向使用的设备规则集编号。
        def rule_set(direction, zone:, type:)
          if type == :static
            snapshot.active_static_nats.find { |nat| nat.mapped_zone == zone }&.rule_set
          else
            snapshot.active_dynamic_nats.find do |nat|
              ((direction == :source) ? nat.to_zone : nat.from_zone) == zone &&
                (nat.direction.nil? || nat.direction == direction)
            end&.rule_set
          end
        end

        # 取得区域唯一的 NAT 接口；零个或多个都会报告配置错误。
        def interface(zone)
          names = snapshot.zone(zone).interfaces.values.map(&:name).uniq.sort
          raise Error, "区域 #{zone} 缺少 NAT 接口" if names.empty?
          raise Error, "区域 #{zone} 存在多个 NAT 接口，需要明确指定" unless names.one?
          names.first
        end

        # 判断对端地址是否全部落在可推断的私网范围内。
        def private_peers?(peers)
          return false unless snapshot.behavior.infer_private_peers?
          private_ranges = Ranges.addresses(%w[10.0.0.0/8 172.16.0.0/12 192.168.0.0/16])
          private_ranges.cover?(Ranges.addresses(peers.keys))
        end

        # 把单段地址集合转换为文本，拒绝无法唯一表示的范围。
        def address_text(set)
          unless set && set.size == 1
            raise Error.new("NAT 范围不能表示为单个连续地址段", code: :ambiguous_nat)
          end
          IPAddr.format_range(set.first)
        end

        private

        # 地址只从 target/peers 派生；flow 补充查询本身不携带的原始目的和区域。
        def nat_flow(target, peers, zone, direction, context, allocation: nil)
          context = Value.hash(context)
          unknown = context.keys - %i[original_dst from_zone to_zone vrf to_zone_stage]
          raise ArgumentError, "未知 NAT 流量字段：#{unknown.join(", ")}" unless unknown.empty?
          unless [ nil, :original, :security ].include?(context[:to_zone_stage])
            raise ArgumentError, "未知 NAT 出口区域阶段"
          end

          original_dst = context[:original_dst] || allocation&.dig(:address)
          { source: direction == :source ? target : peers,
            destination: direction == :source ? peers : original_dst && IPAddr.parse(original_dst),
            from_zone: context[:from_zone] || (zone if direction == :destination),
            to_zone: context[:to_zone] || (zone if direction == :source), vrf: context[:vrf], to_zone_stage: context[:to_zone_stage] }.freeze
        end

        # 正查先选择整条规则；反查的每个公网候选也必须通过相同的正向选择。
        def policy_mapping(policies, target, flow, aliases:, **options)
          if options[:direction] == :destination && flow[:destination].nil?
            candidates = policies.select { |nat| nat.destination_targets&.overlap?(target) }
            mappings = candidates.filter_map do |candidate|
              public_set = candidate.destination_set
              proposed = flow.merge(destination: public_set).freeze
              next unless policy_matches?(candidate, proposed, **options.slice(:services, :source_port), relation: :overlap?)

              if public_set.nil? || public_set == Set.new(0..IPAddr::IPV4_MAX)
                raise Error.new("NAT #{snapshot.signature(candidate)} 没有可确定的公网别名", code: :conditional_nat)
              end
              # 已按相同请求证明的 Server-map 别名无需再由被覆盖的策略重复证明。
              next if aliases.any? { |mapping| IPAddr.parse(mapping[:address]).cover?(public_set) }

              selected_policy_mapping(policies, target, proposed, discovery: true, **options)
            end
            return unique_mapping(mappings)
          end
          selected_policy_mapping(policies, target, flow, **options)
        end

        # 逆查中的不同公网地址代表不同原始报文，不能按规则优先级任选一个。
        def unique_mapping(mappings)
          if mappings.map { |mapping| mapping_signature(mapping) }.uniq.size > 1
            raise Error.new("请求对应多个 NAT 映射或公网别名，无法确定转换结果", code: :ambiguous_nat)
          end
          mappings.first
        end

        def selected_policy_mapping(policies, target, flow, direction:, services:, source_port:, mapped_source_port:, discovery: false)
          ensure_server_clear!(flow, services: services, source_port: source_port)
          nat = first_policy(policies, flow, services: services, source_port: source_port)
          return unless nat

          unless [ direction, :bidirectional ].include?(nat.direction)
            return if discovery

            raise Error.new("首条命中 NAT #{snapshot.signature(nat)} 不转换请求方向，不能追加另一条规则覆盖", code: :conditional_nat)
          end
          valid = if direction == :source
                    port_matches?(nat.translated_source_port, mapped_source_port)
          else
                    destination_result(nat, target, services: services, source_port: source_port)
          end
          return if discovery && valid == false

          unless valid
            raise Error.new("首条命中 NAT #{snapshot.signature(nat)} 的转换结果无法满足请求", code: :conditional_nat)
          end
          snapshot.behavior.validate_nat_target!(nat, flow: flow)
          translated = direction == :source ? nat.source_targets : flow[:destination]
          unless translated && !translated.empty?
            raise Error.new("NAT #{snapshot.signature(nat)} 缺少确定的转换目标", code: :conditional_nat)
          end
          nat_info(nat, translated, :dynamic)
        end

        # false 表示确定不产生目标；nil 表示分配或部分覆盖未知，反查不能跳过。
        def destination_result(nat, target, services:, source_port:)
          targets = nat.destination_targets
          return unless targets
          return false unless targets.overlap?(target)
          # 动态池仅证明可用目标集合，不证明池中某个地址的固定分配。
          return unless target.cardinality == 1 && targets == target
          if port_translation?(services) && !nat.translated_service_set && !nat.translated_service && !nat.translated_destination_port && !nat.destination_pool&.port
            return false
          end
          return false unless service_matches?(nat, services, translated: true, source_port: source_port, relation: :overlap?)
          return unless service_matches?(nat, services, translated: true, source_port: source_port, relation: :cover?)

          destination_ports_match?(nat, services)
        end

        # 原生选择完成后比较每个协议内的端口关系，不能用目标集合包含替代转换函数。
        def destination_ports_match?(nat, services)
          original = nat_services(nat)
          targets = nat_services(nat, translated: true)
          matches = Nat::ServiceQuery.coerce(services).pairs.all? do |pair|
            protocols = Set.new(*pair.original.map { |range| (range.begin >> 16)..(range.end >> 16) })
            protocols.all? do |range|
              range.all? do |protocol|
                before, after, matching, translated = [ pair.original, pair.translated, original, targets ].map do |set|
                  selected = set & Set.new((protocol << 16)..((protocol << 16) + IPAddr::PORT_MAX))
                  Set.new(*selected.map { |ports| (ports.begin & IPAddr::PORT_MAX)..(ports.end & IPAddr::PORT_MAX) })
                end
                matching = IPAddr.ports(nat.destination_port) if nat.destination_port
                nat.destination_translation.fixed_port_relation(original: before, translated: after, matching: matching, targets: translated)
              end
            end
          end
          # 未证明不能视为不可能，逆向发现必须保留可能的别名。
          true if matches
        end

        # 命中只使用转换前条件；不因目标、转换端口或所查询方向不同而跳过。
        def first_policy(policies, flow, services:, source_port:)
          policies.each do |nat|
            next unless policy_matches?(nat, flow, services: services, source_port: source_port, relation: :overlap?)
            unless policy_matches?(nat, flow, services: services, source_port: source_port, relation: :cover?)
              raise Error.new("前置 NAT #{snapshot.signature(nat)} 部分命中或缺少原始流量条件", code: :conditional_nat)
            end
            return nat
          end
          nil
        end

        def policy_matches?(nat, flow, services:, source_port:, relation:)
          return false if nat.disabled?
          return false unless nat_range_matches?(nat.source_set, flow[:source], relation: relation) &&
                              nat_range_matches?(nat.destination_set, flow[:destination], relation: relation)
          return false unless port_matches?(nat.source_port, source_port, relation: relation)
          return false unless service_matches?(nat, services, translated: false, source_port: source_port, relation: relation)
          if nat.match_rule
            raise Error.new("原生 NAT 策略的关联安全规则条件尚未展开", code: :conditional_nat)
          end
          snapshot.behavior.nat_flow_matches?(nat, flow: flow, relation: relation)
        end

        def nat_range_matches?(condition, requested, relation:)
          return relation == :overlap? unless condition
          return condition.public_send(relation, requested) if requested

          relation == :overlap? || condition == Set.new(0..IPAddr::IPV4_MAX)
        end

        # 逆向目标没有命中服务器映射，不代表候选公网没有被该层接管。
        def ensure_server_clear!(flow, services:, source_port:, rules: snapshot.behavior.nat_groups.flatten, directions: %i[source destination])
          rules.each do |nat|
            overlap = if nat.is_a?(Elements::StaticNat)
                        destination = directions.include?(:destination) && nat_range_matches?(nat.mapped_set, flow[:destination], relation: :overlap?) &&
                                      (flow[:from_zone].nil? || snapshot.behavior.static_nat_zone?(nat, flow[:from_zone]))
                        source = directions.include?(:source) && snapshot.behavior.static_nat_source?(nat) && nat_range_matches?(nat.real_set, flow[:source], relation: :overlap?) &&
                                 (flow[:to_zone].nil? || snapshot.behavior.static_nat_zone?(nat, flow[:to_zone]))
                        source || destination
            else
                        (nat.direction.nil? || nat.direction == :bidirectional || directions.include?(nat.direction)) &&
                          nat_range_matches?(nat.source_set, flow[:source], relation: :overlap?) &&
                          nat_range_matches?(nat.destination_set, flow[:destination], relation: :overlap?) &&
                          (flow[:from_zone].nil? || snapshot.behavior.dynamic_nat_zone?(nat, flow[:from_zone], direction: :destination)) &&
                          port_matches?(nat.source_port, source_port, relation: :overlap?) &&
                          service_matches?(nat, services, translated: false, source_port: source_port, relation: :overlap?)
            end
            next unless overlap

            raise Error.new("原始流量可能先命中服务器映射 #{snapshot.signature(nat)}，不能按后续策略推定转换", code: :conditional_nat)
          end
        end

        # 仅实际消费且与本次原始流量一致的映射，才能证明 Server-map 层已接管。
        def verify_server_mapping!(mapping, flow, direction:, services:)
          nat = mapping.fetch(:rule)
          if direction == :destination
            unless IPAddr.parse(mapping[:address]) == flow[:destination]
              raise Error.new("已消费的服务器映射与原始目的不一致", code: :conditional_nat)
            end
            target = nat.is_a?(Elements::StaticNat) ? nat.reverse_translate(flow[:destination]) : nat.destination_targets
            peers, zone = flow.values_at(:source, :from_zone)
          else
            target = flow[:source]
            peers, zone = flow.values_at(:destination, :to_zone)
          end
          verified = if nat.is_a?(Elements::StaticNat)
                       static_match(nat, target, peers, zone, direction: direction, services: services)
          else
                       dynamic_match(nat, target, peers, zone, direction: direction, services: services, source_port: nil, mapped_source_port: nil, flow: flow)
          end
          unless verified && mapping_signature(verified) == mapping_signature(mapping)
            raise Error.new("已消费的服务器映射缺少相同原始流量证明", code: :conditional_nat)
          end
        end

        # 仅比较请求声明的分配条件；已有首条命中不允许被后置新建静默替换。
        def validate_nat_allocation!(mapping, allocation, flow, direction)
          if direction == :destination && flow[:destination] && IPAddr.parse(mapping[:address]) != flow[:destination]
            raise Error.new("已有 NAT 不对应请求的原始目的地址", code: :conditional_nat)
          end
          return unless allocation

          nat = mapping.fetch(:rule)
          valid = allocation_attributes_match?(mapping, allocation, direction)
          if nat.is_a?(Elements::DynamicNat)
            valid &&= nat.extra_conf["source_mode"] == "easy-ip" if direction == :source && !allocation[:address]
            if allocation[:option]
              option = allocation[:option]
              valid &&= option.is_a?(String) && /\A[sd]*\z/.match?(option)
              if valid
                expected_source = direction == :source || option.include?("s") ? flow[:source] : Set.new(0..IPAddr::IPV4_MAX)
                expected_destination = direction == :destination || option.include?("d") ? flow[:destination] : Set.new(0..IPAddr::IPV4_MAX)
                valid &&= nat.source_set == expected_source && nat.destination_set == expected_destination
              end
            end
          elsif allocation[:pool_name] || allocation[:option]
            valid = false
          end
          raise Error.new("请求分配与已有首条命中 NAT 不一致，需明确修改原规则", code: :conditional_nat) unless valid
        end

        # 独立映射只验证已建模的分配属性，不套用 Huawei Easy-IP 或范围选项语义。
        def validate_group_allocation!(mapping, allocation, flow, direction)
          if direction == :destination && flow[:destination] && IPAddr.parse(mapping[:address]) != flow[:destination]
            raise Error.new("已有 NAT 不对应请求的原始目的地址", code: :conditional_nat)
          end
          return unless allocation
          return if allocation_attributes_match?(mapping, allocation, direction) && allocation[:option].nil?

          raise Error.new("请求分配与已有首条命中 NAT 不一致或包含未证明的分配选项", code: :conditional_nat)
        end

        def allocation_attributes_match?(mapping, allocation, direction)
          nat = mapping.fetch(:rule)
          translation = direction == :source ? nat.source_translation : nat.destination_translation
          # 已选中的固定映射可作目的反查；其分配证据来自原固定关系，不是前向同时 DNAT。
          if direction == :destination && nat.is_a?(Elements::StaticNat) && translation.identity? && nat.source_translation.allocation_mode == :static
            translation = nat.source_translation
          end
          return false if translation.allocation_mode.nil?
          valid = allocation[:type] == translation.allocation_mode
          valid &&= IPAddr.parse(allocation[:address]) == IPAddr.parse(mapping[:address]) if allocation[:address]
          valid &&= allocation[:interface] == mapping[:interface] if allocation[:interface]
          valid &&= allocation[:direction].to_s == direction.to_s if allocation[:direction]
          if allocation[:pool_name]
            nat = mapping.fetch(:rule)
            pool = nat.is_a?(Elements::DynamicNat) && (direction == :source ? nat.source_pool : nat.destination_pool)
            valid &&= allocation[:pool_name] == (pool && pool.name)
          end
          valid
        end

        # 同层比较完整映射关系；同一查询地址相等不代表整段映射或端口转换等价。
        def mapping_signature(entry)
          nat = entry.fetch(:rule)
          mapping = if nat.is_a?(Elements::StaticNat)
                      [ nat.real_set, nat.mapped_set, nat.mappings ]
          else
                      [ nat.source_set, nat.destination_set, nat.source_targets, nat.destination_targets,
                       nat.source_port, nat.translated_source_port, nat_services(nat), nat_services(nat, translated: true) ]
          end
          [ entry.except(:rule), mapping ]
        end

        # 反查只收到映射地址，没有对端或服务条件，不能把条件 NAT 当作全局别名。
        def validate_reverse!(nat)
          snapshot.behavior.validate_reverse_nat!(nat)
          any_address = Set.new(0..IPAddr::IPV4_MAX)
          unrestricted = nat.destination_set.nil? || nat.destination_set == any_address
          if nat.match_rule
            unrestricted &&= [ nat.match_rule.sources, nat.match_rule.destinations ].all? do |group|
              group.members.empty? || (group.resolved? && !group.conditional? && group.resolved_set == any_address)
            end
          end
          unless unrestricted && matching_rule?(nat, nil)
            raise Error.new("静态 NAT #{snapshot.signature(nat)} 的反查需要完整流量条件", code: :conditional_nat)
          end
        end

        def static_match(nat, target, peers, zone, direction:, services:)
          return if nat.disabled?
          return if direction == :source && !snapshot.behavior.static_nat_source?(nat)
          return if direction == :destination && port_translation?(services)
          return unless snapshot.behavior.static_nat_zone?(nat, zone)
          options = { direction: direction, services: services }
          return unless static_mapping(nat, target, peers, **options, relation: :overlap?)
          translated = static_mapping(nat, target, peers, **options, relation: :cover?)
          unless translated
            raise Error.new("静态 NAT #{snapshot.signature(nat)} 仅覆盖部分请求，请拆分查询", code: :ambiguous_nat)
          end
          nat_info(nat, translated, :static)
        end

        # 独立映射阶段仍须以原始报文证明候选，不能用期望目标越过前置规则。
        def group_dynamic_mapping(nat, target, peers, zone, flow:, **options)
          direction = options.fetch(:direction)
          return unless nat.direction.nil? || [ direction, :bidirectional ].include?(nat.direction)

          proposed = flow[:destination] || direction == :source ? flow : flow.merge(destination: nat.destination_set)
          predicate = options.slice(:services, :source_port)
          return unless group_original_matches?(nat, proposed, **predicate, relation: :overlap?)

          covered = group_original_matches?(nat, proposed, **predicate, relation: :cover?)
          mapping = if direction == :source && covered
                      unless nat.source_targets && !nat.source_targets.empty? && port_matches?(nat.translated_source_port, options[:mapped_source_port])
                        raise Error.new("首条原始流量命中 NAT #{snapshot.signature(nat)} 缺少所请求的源转换", code: :conditional_nat)
                      end
                      nat_info(nat, nat.source_targets, :dynamic)
          else
                      dynamic_match(nat, target, peers, zone, flow: proposed, **options)
          end
          unless mapping
            if direction == :source || flow[:destination]
              raise Error.new("首条原始流量命中 NAT #{snapshot.signature(nat)} 无法满足转换请求", code: :conditional_nat)
            end
            return
          end
          unless covered
            raise Error.new("NAT #{snapshot.signature(nat)} 仅覆盖部分原始流量，不能证明完整转换", code: :conditional_nat)
          end
          preceding = snapshot.behavior.nat_groups.flatten.take_while { |rule| rule != nat }
          preceding.each do |rule|
            if rule.is_a?(Elements::StaticNat)
              ensure_server_clear!(proposed, **predicate, rules: [ rule ], directions: [ direction ])
            elsif (rule.direction.nil? || [ direction, :bidirectional ].include?(rule.direction)) &&
                  group_original_matches?(rule, proposed, **predicate, relation: :overlap?)
              raise Error.new("候选 NAT 被前置规则 #{snapshot.signature(rule)} 遮挡，不能证明正向转换", code: :conditional_nat)
            end
          end
          # 显式原始目的可以只是规则谓词的子集，返回值不能扩大安全策略范围。
          mapping = mapping.merge(address: address_text(flow[:destination])) if direction == :destination && flow[:destination]
          mapping
        end

        # ACL 与关联规则保留厂商谓词，原始两侧地址和服务单独参与选择。
        def group_original_matches?(nat, flow, services:, source_port:, relation:)
          nat_range_matches?(nat.original_packet.source_addresses, flow[:source], relation: relation) &&
            nat_range_matches?(nat.original_packet.destination_addresses, flow[:destination], relation: relation) &&
            port_matches?(nat.source_port, source_port, relation: relation) &&
            service_matches?(nat, services, translated: false, source_port: source_port, relation: relation) &&
            snapshot.behavior.nat_flow_matches?(nat, flow: flow, relation: relation) &&
            matching_rule?(nat, services, relation: relation, flow: flow, source_port: source_port) &&
            snapshot.behavior.nat_acl_matches?(nat, sources: flow[:source], destinations: flow[:destination], services: services, relation: relation)
        end

        def dynamic_match(nat, target, peers, zone, direction:, services:, source_port:, mapped_source_port:, flow: nil)
          return if nat.disabled?
          return unless nat.direction.nil? || nat.direction == direction || nat.direction == :bidirectional
          options = { direction: direction, services: services, source_port: source_port, mapped_source_port: mapped_source_port, flow: flow }
          return unless dynamic_matches?(nat, target, peers, zone, **options, relation: :overlap?)
          if flow
            return unless snapshot.behavior.nat_flow_matches?(nat, flow: flow, relation: :overlap?)
            unless snapshot.behavior.nat_flow_matches?(nat, flow: flow, relation: :cover?)
              raise Error.new("NAT #{snapshot.signature(nat)} 缺少完整原始区域或路由域条件", code: :conditional_nat)
            end
          end
          unless dynamic_matches?(nat, target, peers, zone, **options, relation: :cover?)
            sides = [ nat_service_objects(nat) ]
            sides << nat_service_objects(nat, translated: true) if direction == :destination
            limited_terms = sides.map { |objects| nat_service_terms(objects) }.reject do |terms|
              terms.empty? || terms.any? { |term| Ranges.unrestricted_term?(term) }
            end
            missing_ports = source_port.nil? && limited_terms.flatten.any? do |term|
              IPAddr.ports(term[:source_port] || Elements::Definition::ANY_PORTS) != Ranges::ANY_PORTS
            end
            missing_ports ||= nat.source_port && source_port.nil?
            missing_ports ||= direction == :source && nat.translated_source_port && mapped_source_port.nil?
            missing_services = (services.nil? || services.empty?) && (limited_terms.any? ||
                              nat_services(nat) != IPAddr.service("any") ||
                              (direction == :destination && nat_services(nat, translated: true) != IPAddr.service("any")))
            code = peers.nil? || missing_ports || missing_services ? :conditional_nat : :ambiguous_nat
            raise Error.new("NAT #{snapshot.signature(nat)} 仅覆盖部分请求或缺少匹配上下文，请拆分查询或补齐条件", code: code)
          end
          if direction == :destination && destination_result(nat, target, services: services, source_port: source_port) != true
            raise Error.new("NAT #{snapshot.signature(nat)} 无法证明固定的目的转换分配", code: :conditional_nat)
          end
          translated = direction == :source ? nat.source_targets : nat.destination_set
          unless translated && !translated.empty?
            raise Error.new("NAT #{snapshot.signature(nat)} 缺少可确定的转换地址", code: :conditional_nat)
          end
          nat_info(nat, translated, :dynamic)
        end

        # 相同的地址并集不保证逐地址映射相同；在两条映射的端点处切分后比较。
        def same_reverse_mapping?(left, right, shared)
          ranges = [ left, right ].flat_map { |nat| nat.mappings ? nat.mappings.map(&:last) : nat.mapped_set.ranges }
          cuts = (ranges + shared.ranges).flat_map { |range| [ range.begin, range.end + 1 ] }.uniq.sort
          cuts.each_cons(2).all? do |first, last|
            segment = Set.new(first..(last - 1)) & shared
            segment.empty? || left.reverse_translate(segment) == right.reverse_translate(segment)
          end
        end

        # 静态映射先识别相交条件，再证明覆盖；厂商 ACL 判断仍由行为适配器负责。
        def static_mapping(nat, target, peers, direction:, services:, relation:)
          return unless nat.real_set.public_send(relation, target)
          return unless snapshot.behavior.static_nat_peers?(nat, peers, relation: relation)
          if nat.match_rule
            return if nat.match_rule.disabled?
            if peers
              group = direction == :source ? nat.match_rule.destinations : nat.match_rule.sources
              return unless group.members.empty? || group.resolved_set.public_send(relation, peers)
            end
          end
          return unless matching_rule?(nat, services, relation: relation)
          return unless snapshot.behavior.nat_acl_matches?(nat, sources: target, destinations: peers, services: services, relation: relation)
          snapshot.behavior.static_nat_translation(nat, target & nat.real_set, peers: peers, relation: relation)
        end

        # NAT 的关联规则仍有完整匹配条件，范围投影不能替代时间和服务约束。
        def matching_rule?(nat, services, relation: :cover?, flow: nil, source_port: nil)
          rule = nat.match_rule
          return true unless rule
          if snapshot.behavior.policy_embeds_nat?
            return Nat::EmbeddedSelection.new(snapshot).matches?(nat, flow: flow, services: services, source_port: source_port)
          end
          return false if rule.disabled?
          if rule.schedule || rule.schedule_name || rule.starts_at || rule.expires_at ||
             rule.application_check || rule.unparsed_commands? || !rule.security_profiles.empty? ||
             snapshot.behavior.unresolved_network_conditions?(rule) ||
             !rule.services.resolved? || rule.services.unique_leaves.flat_map(&:terms).any? { |term| !Ranges.unrestricted_term?(term) }
            raise Error.new("NAT 关联规则 #{rule.rule_id} 包含无法确定的匹配条件", code: :conditional_nat)
          end
          # 未声明 matching service 的静态 NAT 使用空组表示不限制服务。
          return true if nat.is_a?(Elements::StaticNat) && rule.services.members.empty?
          ranges = Ranges.rule_services(rule)
          return true if ranges == IPAddr.service("any")
          unless services && !services.empty?
            raise Error.new("NAT 关联规则 #{rule.rule_id} 需要服务上下文", code: :conditional_nat)
          end
          ranges.public_send(relation, Nat::ServiceQuery.coerce(services).original_set)
        end

        # 组装 NAT 查询返回值，并附带规则集和接口信息。
        def nat_info(rule, set, type)
          unless [ rule.source_translation, rule.destination_translation ].all? { |translation| translation.known? || translation.address_targets_known? }
            raise Error.new("NAT #{snapshot.signature(rule)} 包含未知转换模式", code: :conditional_nat)
          end
          details = { address: address_text(set), type: type, rule: rule, acl_name: rule.acl_name }
          interface = rule.interface || (rule.is_a?(Elements::DynamicNat) && rule.source_pool&.interface)
          details[:interface] = interface if interface
          details
        end

        # 先判断是否可能命中，再证明整体覆盖；前置部分命中不能跳过到后置映射。
        def dynamic_matches?(nat, target, peers, zone, direction:, services:, source_port:, mapped_source_port:, relation:, flow: nil)
          return false unless snapshot.behavior.dynamic_nat_zone?(nat, zone, direction: direction)
          return false unless port_matches?(nat.source_port, source_port, relation: relation)
          if direction == :source
            return false unless nat.source_set&.public_send(relation, target) && (peers.nil? || nat.destination_set&.public_send(relation, peers))
            return false unless port_matches?(nat.translated_source_port, mapped_source_port, relation: relation)
          else
            return false unless (peers.nil? || nat.source_set&.public_send(relation, peers)) && nat.destination_targets&.public_send(relation, target)
            return false if port_translation?(services) && !nat.translated_service_set && !nat.translated_service && !nat.translated_destination_port && !nat.destination_pool&.port
          end
          sources, destinations = direction == :source ? [ target, peers ] : [ peers, target ]
          service_matches?(nat, services, translated: direction == :destination, source_port: source_port, relation: relation) &&
            matching_rule?(nat, services, relation: relation, flow: flow, source_port: source_port) &&
            snapshot.behavior.nat_acl_matches?(nat, sources: sources, destinations: destinations, services: services, relation: relation) &&
            (!peers.nil? || relation == :overlap?)
        end

        # 每个原始/转换服务对独立匹配，避免把不同条目的两侧拼成不存在的转换。
        def service_matches?(nat, services, translated:, source_port:, relation:)
          service_objects = nat_service_objects(nat)
          terms = nat_service_terms(service_objects)
          translated_objects = translated ? nat_service_objects(nat, translated: true) : []
          translated_terms = nat_service_terms(translated_objects)
          before_set = nat_services(nat)
          after_set = translated ? nat_services(nat, translated: true) : IPAddr.service("any")
          return false if before_set.empty? || after_set.empty?
          if services.nil? || services.empty?
            return false unless service_terms_match?(service_objects, before_set, source_port, terms: terms, relation: relation)
            return false unless service_terms_match?(translated_objects, after_set, source_port, terms: translated_terms, relation: relation)
            return relation == :overlap? unless before_set == IPAddr.service("any") && after_set == IPAddr.service("any")
            return true
          end
          quantifier = relation == :cover? ? :all? : :any?
          Nat::ServiceQuery.coerce(services).pairs.public_send(quantifier) do |pair|
            before, after = pair.original, pair.translated
            before_set.public_send(relation, before) && after_set.public_send(relation, after) &&
              service_terms_match?(service_objects, before, source_port, terms: terms, relation: relation) &&
              service_terms_match?(translated_objects, after, source_port, terms: translated_terms, relation: relation)
          end
        end

        # 两侧服务分别约束转换前后流量，转换目标不能当作原始端口条件。
        def nat_service_objects(nat, translated: false)
          return [ nat.translated_service ].compact if translated

          [ nat.service, *nat.references ].compact.select do |object|
            object.is_a?(Elements::ServiceObject) || object.is_a?(Elements::ServiceGroup)
          end.uniq
        end

        # 按源端口切分后合并服务范围，证明完整项的并集，避免跨项拼接协议或端口。
        def service_terms_match?(services, requested, source_port, terms:, relation:)
          return true if services.empty?
          source = source_port.nil? ? Ranges::ANY_PORTS : IPAddr.ports(source_port.to_s)
          terms = terms.filter_map do |term|
            sources = IPAddr.ports(term[:source_port] || Elements::Definition::ANY_PORTS) & source
            destinations = Ranges.service("#{term[:protocol]}/#{term[:destination_port]}") & requested
            next if sources.empty? || destinations.empty?
            if term[:uuid] || term[:timeout]
              names = services.map(&:name).uniq.join(", ")
              raise Error.new("NAT 服务 #{names} 包含无法确定的匹配条件", code: :conditional_nat)
            end
            [ sources, destinations ]
          end
          return !terms.empty? if relation == :overlap?

          boundaries = terms.flat_map { |sources, _destinations| sources.ranges.flat_map { |range| [ range.begin, range.end + 1 ] } }
          source.all? do |range|
            cuts = [ range.begin, range.end + 1, *boundaries.select { |point| point > range.begin && point <= range.end } ].uniq.sort
            cuts.each_cons(2).all? do |first, last|
              segment = Set.new(first..(last - 1))
              covered = terms.reduce(Set.new) do |set, (sources, destinations)|
                sources.cover?(segment) ? set | destinations : set
              end
              covered.cover?(requested)
            end
          end
        end

        # 服务与嵌套服务组共用完整项投影；缺失引用不能退化为已知子集。
        def nat_service_terms(services)
          services.flat_map do |service|
            projection = service.service_projection
            unless projection[:resolution]["complete"]
              raise Error.new("NAT 服务 #{service.name} 包含未解析引用", code: :conditional_nat)
            end
            projection[:member]
          end
        end

        # 将同一侧的协议、端口和服务约束求交；不能分别重叠后误认为有共同流量。
        def nat_services(nat, translated: false)
          services = (translated ? nat.translated_service_set : nat.service_set) || IPAddr.service("any")
          services &= nat.translated_service.set if translated && nat.translated_service
          services &= IPAddr.service("#{nat.protocol}/0-65535") unless IPAddr.protocol_number(nat.protocol).zero?
          port = translated ? (nat.destination_pool&.port || nat.translated_destination_port) : nat.destination_port
          if port
            ports = IPAddr.ports(port.to_s)
            mask = Set.new(*(0..255).flat_map { |protocol| ports.map { |range| ((protocol << 16) + range.begin)..((protocol << 16) + range.end) } })
            services &= mask
          end
          services
        end

        # 未提供端口不能排除前置 NAT，亦不能证明它覆盖整个请求。
        def port_matches?(expected, actual, relation: :cover?)
          return true if expected.nil?
          return relation == :overlap? if actual.nil?
          IPAddr.ports(expected).public_send(relation, IPAddr.ports(actual.to_s))
        end

        # 判断请求服务中是否发生了端口转换。
        def port_translation?(services)
          return services.translation? if services.is_a?(Nat::ServiceQuery)
          (services || {}).any? do |service, entry|
            entry[:translated_port] && entry[:translated_port] != entry.fetch(:origin, service).split("/", 2).last
          end
        end
      end
    end
  end
end
