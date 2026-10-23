# frozen_string_literal: true

require "digest"
require_relative "../effect_proof"
require_relative "../analysis"
require_relative "resolver"
require_relative "../traffic_set"
require_relative "../change_set/declaration_comparison"
require_relative "../rule_order"

module Algosec
  module Policy
    module Nat
      # 证明实际候选的 NAT 关系；持久化结果仅供审阅，回读始终重跑解析语义。
      class Verification < EffectProof
        ANY_ADDRESS = Set.new(0..IPAddr::IPV4_MAX)
        ANY_SERVICE = Set.new(0..IPAddr::SERVICE_MAX)
        private_constant :ANY_ADDRESS, :ANY_SERVICE

        attr_reader :snapshot, :candidate, :expectations, :baseline, :issues, :observations, :change_set, :require_untranslated

        def initialize(snapshot:, candidate:, expectations:, change_set: nil, require_untranslated: false)
          raise ArgumentError, "NAT proof ChangeSet baseline differs" if change_set && !change_set.snapshot.equal?(snapshot)
          unless [ true, false ].include?(require_untranslated) && (!require_untranslated || change_set.is_a?(ChangeSet))
            raise ArgumentError, "Untranslated NAT requirement must be boolean and bound to a ChangeSet"
          end
          @change_set, @require_untranslated = change_set, require_untranslated
          unless snapshot.is_a?(Snapshot) && candidate.is_a?(Snapshot) && expectations.is_a?(Array) && expectations.all? { |item| item.is_a?(Expectation) }
            raise ArgumentError, "NAT proof requires snapshots and typed expectations"
          end
          raise Error.new("NAT 目标分段超出预算", code: :query_too_complex) if expectations.size > TrafficSet::DEFAULT_LIMIT
          if change_set && ChangeSet::DeclarationComparison.new(change_set.apply, candidate).changed_rules.any?
            raise ArgumentError, "NAT candidate security rules differ from its ChangeSet"
          end
          @snapshot, @candidate, @expectations = snapshot, candidate, expectations.dup.freeze
          [ snapshot, candidate ].each do |item|
            item.catalog.seal!
            item.builtin_services.each(&:seal!)
          end
          @baseline = snapshot.baseline
          @issues, @observations = order_issues(candidate), []
          @approved = issues.empty? ? declarations(candidate) : []
          @environment = environment(candidate)
          @issues.concat(context_issues(candidate))
          @issues << finding(:stale_plan, "NAT 候选配置修订与基线不同") unless snapshot.revision == candidate.revision
          prove_outside_target if issues.empty?
          @issues.concat(prove_targets(candidate, @observations)) if issues.empty?
          @issues.concat(prove_untranslated(candidate, @observations)) if issues.empty? && require_untranslated
          @issues.freeze
          @observations = Value.immutable(@observations)
          freeze
        end

        def self.unchanged(change_set:, require_untranslated: false)
          new(snapshot: change_set.snapshot, candidate: change_set.apply, expectations: [], change_set: change_set, require_untranslated: require_untranslated)
        end

        def generation? = !change_set.nil?
        def effect = :nat
        def verified? = issues.empty?
        def differences = []
        def to_h
          { effect: effect, baseline: baseline, expectations: expectations.map(&:to_h), require_untranslated: require_untranslated, verified: verified?,
            observations: observations, declarations_sha256: Digest::SHA256.hexdigest(JSON.generate(@approved)), issues: issues.map(&:to_h) }
        end

        Readback = Data.define(:issues, :observations) do
          def verified? = issues.empty?
          def differences = []
          def to_h = { effect: :nat, verified: verified?, observations: observations, issues: issues.map(&:to_h) }
        end

        def verify_readback(readback)
          raise ArgumentError, "NAT readback requires a Snapshot" unless readback.is_a?(Snapshot)
          readback.catalog.seal!
          readback.builtin_services.each(&:seal!)
          found = issues.dup + context_issues(readback) + order_issues(readback)
          observed = []
          unless declarations(readback) == @approved && environment(readback) == @environment
            found << finding(:nat_readback_mismatch, "回读 NAT 声明与批准候选不同")
          end
          found.concat(prove_targets(readback, observed)) if found.empty?
          found.concat(prove_untranslated(readback, observed)) if found.empty? && require_untranslated
          Readback.new(issues: found.freeze, observations: Value.immutable(observed))
        rescue Error => error
          Readback.new(issues: [ finding(error.code, error.message) ].freeze, observations: [].freeze)
        end

        # 编码服务在协议边界处分开，保留协议和目的端口的关联。
        def self.traffic(sources, destinations, services, source_port = nil)
          return TrafficSet.new if services.empty?
          Nat::ServiceQuery.new(pairs: [ [ services, services ] ]).traffic(sources: sources, destinations: destinations, source_port: source_port)
        end

        private

        def context_issues(actual)
          [ snapshot, actual ].each(&:require_complete!)
          same = snapshot.device_id == actual.device_id && snapshot.vendor == actual.vendor &&
            snapshot.software_version == actual.software_version && snapshot.settings == actual.settings && snapshot.time_zone == actual.time_zone
          same ? [] : [ finding(:stale_plan, "NAT 候选设备或运行上下文与基线不同") ]
        rescue Error => error
          [ finding(error.code, error.message) ]
        end

        def prove_targets(actual, observed)
          failures = []
          policies = actual.behavior.nat_policy_rules unless expectations.empty?
          if policies && policies.size > 1
            positions = policies.map(&:position)
            unless positions.none?(&:nil?) && positions.uniq.size == positions.size && positions == positions.sort
              return [ finding(:unknown_order, "NAT 原生顺序没有完整且一致的证据") ]
            end
          end
          resolver = Nat::Resolver.new(actual)
          segmented = []
          expectations.each do |expected|
            pieces = query_segments(expected, policies || [])
            raise Error.new("NAT 查询分段超出预算", code: :query_too_complex) if segmented.size + pieces.size > TrafficSet::DEFAULT_LIMIT
            segmented.concat(pieces)
          end
          segmented.each do |expected|
            allocation = expected.allocation
            interface_known = !allocation[:interface] || actual.nat_rules.any? { |nat| nat.original_packet.interface == allocation[:interface] }
            unless allocation[:address] && interface_known && !(allocation[:type] == :dynamic && expected.options[:mapped_source_port])
              failures << finding(:unsupported_nat_allocation, "NAT 分配缺少可证明的地址范围，或请求了未知接口或会话端口")
              next
            end
            begin
              mapping = resolver.find(expected.address, **expected.options)
              raise Error.new("候选缺少目标 NAT 关系", code: :nat_missing) unless mapping
              nat = mapping.fetch(:rule)
              unless nat.translation_known? && nat.source_translation.interface.nil?
                raise Error.new("候选 NAT 的规范转换模式未知", code: :conditional_nat)
              end
              prove_source_port!(nat, expected)
              prove_static_pairing!(nat, expected) if allocation[:type] == :static
              # 双向转换必须在同一原始流量上证明两侧，不能只检查被请求的一侧。
              if nat.dual_translation?
                opposite = segmented.find do |other|
                  other.direction != expected.direction && other.traffic.cover?(expected.traffic) && expected.traffic.cover?(other.traffic) && context_covered?(other.context, expected.context)
                end
                unless opposite && resolver.find(opposite.address, **opposite.options)&.fetch(:rule).equal?(nat)
                  raise Error.new("候选双向 NAT 缺少同一原始流量的另一侧关系证明", code: :conditional_nat)
                end
              end
              observed << { expectation: expected.to_h, rule_id: actual.signature(nat), address: mapping.fetch(:address),
                source_mode: nat.source_translation.mode, destination_mode: nat.destination_translation.mode,
                relation: allocation[:type] == :static ? :fixed_relation : :possible_targets }
            rescue Error => error
              failures << finding(error.code, error.message)
            end
          end
          failures
        rescue Error, TrafficSet::LimitExceeded => error
          [ finding(error.is_a?(Error) ? error.code : :query_too_complex, error.message) ]
        end

        # 验证片段保留批准输入和精确原始范围；它不是新的批准条件或可恢复收据。
        Segment = Data.define(:expectation, :traffic, :address, :options) do
          def direction = expectation.direction
          def allocation = expectation.allocation
          def context = expectation.context
          def to_h
            scope = traffic.map { |region| TrafficSet::DIMENSIONS.to_h { |field| [ field, region.public_send(field).map { |range| [ range.begin, range.end ] } ] } }
            expectation.to_h.merge(original_scope: scope)
          end
        end
        private_constant :Segment

        # 沿真实原生条件切分五元组；每段仍交给 Nat::Resolver 的同一首命中和服务项算法。
        def query_segments(expected, policies)
          return [ expected ] if policies.size < 2 || expected.allocation[:type] != :dynamic
          budget = TrafficSet::Budget.new(TrafficSet::DEFAULT_LIMIT)
          cells = expected.traffic.regions
          policies.each do |nat|
            footprint = footprints(nat).first.first
            cells = cells.each_with_object([]) do |cell, pieces|
              current = TrafficSet.new([ cell ])
              (current & footprint).each { |region| budget.append(pieces, region) }
              (current - footprint).each { |region| budget.append(pieces, region) }
            end
          end
          query = Nat::ServiceQuery.coerce(expected.options[:services])
          cells.each_with_object([]) do |region, pieces|
            services = query.restrict(encoded_services(region))
            count = region.source_addresses.size * region.destination_addresses.size * region.source_ports.size
            raise TrafficSet::LimitExceeded, "NAT query exceeds interval budget" if pieces.size + count > TrafficSet::DEFAULT_LIMIT
            region.source_addresses.each do |source|
              region.destination_addresses.each do |destination|
                region.source_ports.each do |source_port|
                  values = TrafficSet::DIMENSIONS.to_h { |field| [ field, region.public_send(field) ] }
                  narrowed = TrafficSet::Region.new(family: region.family, **values.merge(source_addresses: Set.new(source), destination_addresses: Set.new(destination), source_ports: Set.new(source_port)))
                  source_text, destination_text = [ source, destination ].map { |range| IPAddr.format_range(range) }
                  options = expected.options.merge(services: services, source_port: "#{source_port.begin}-#{source_port.end}")
                  if expected.direction == :source
                    address = source_text
                    options[:peers] = { destination_text => {} }
                  else
                    address = expected.address
                    options[:peers] = { source_text => {} }
                    options[:flow] = expected.flow.merge(original_dst: destination_text)
                  end
                  budget.append(pieces, Segment.new(expectation: expected, traffic: TrafficSet.new([ narrowed ]), address: address, options: options.freeze))
                end
              end
            end
          end
        rescue TrafficSet::LimitExceeded => error
          raise Error.new(error.message, code: :query_too_complex)
        end

        def encoded_services(region)
          budget, ranges = TrafficSet::Budget.new(TrafficSet::DEFAULT_LIMIT), []
          region.protocols.each do |protocols|
            if region.destination_ports == Ranges::ANY_PORTS
              budget.append(ranges, (protocols.begin << 16)..(((protocols.end + 1) << 16) - 1))
            else
              protocols.each do |protocol|
                region.destination_ports.each { |ports| budget.append(ranges, ((protocol << 16) + ports.begin)..((protocol << 16) + ports.end)) }
              end
            end
          end
          Set.new(*ranges)
        end

        # 选择规则后再由转换拥有者证明端口关系，不能把原生 nil 匹配条件当成任意重写。
        def prove_source_port!(nat, expected)
          mapped = expected.options[:mapped_source_port]
          return unless mapped
          original = expected.options[:source_port]
          relation = nat.source_translation.fixed_port_relation(original: original && IPAddr.ports(original), translated: IPAddr.ports(mapped))
          unless relation
            raise Error.new("NAT 未声明所要求的固定源端口关系", code: :unsupported_nat_source_port)
          end
        end

        # 集合相同不等于逐地址关系相同；复用 StaticNat 的映射运算比较每个声明分段。
        def prove_static_pairing!(nat, expected)
          source, target = IPAddr.parse(expected.address), IPAddr.parse(expected.allocation.fetch(:address))
          unless nat.is_a?(Elements::StaticNat)
            return if source.cardinality == 1 && target.cardinality == 1
            raise Error.new("策略 NAT 多地址固定配对尚无证明", code: :unsupported_nat_range)
          end
          relation = Elements::StaticNat.new(vendor: :generic, real_ip: expected.address, mapped_ip: expected.allocation.fetch(:address))
          ranges = nat.mappings ? nat.mappings.map(&:first) : nat.real_set.ranges
          cuts = (ranges + source.ranges).flat_map { |range| [ range.begin, range.end + 1 ] }.uniq.sort
          valid = cuts.each_cons(2).all? do |first, last|
            segment = Set.new(first..(last - 1)) & source
            segment.empty? || nat.translate(segment) == relation.translate(segment)
          end
          raise Error.new("固定 NAT 逐地址映射与批准关系不同", code: :conditional_nat) unless valid
        rescue Elements::StaticNat::InvalidMapping => error
          raise Error.new(error.message, code: :conditional_nat)
        end

        # 完整保留既有 NAT 及其依赖、顺序，再证明新增规则在批准流量之外不可能匹配。
        # 这是保守的关系证明：修改/删除旧关系暂不冒充范围外等价。
        def order_issues(actual)
          embedded_chains(actual)
          policies = actual.behavior.nat_policy_rules
          return [] unless policies && policies.size > 1
          positions = policies.map(&:position)
          valid = positions.none?(&:nil?) && positions.uniq.size == positions.size && positions == positions.sort
          valid ? [] : [ finding(:unknown_order, "NAT 原生顺序没有完整且一致的证据") ]
        rescue Error => error
          [ finding(error.code, error.message) ]
        end

        def prove_outside_target
          @issues.concat(order_issues(snapshot) + order_issues(candidate))
          return unless issues.empty?
          candidate.nat_rules.each do |nat|
            dependency = nat.original_packet.match_rule
            next unless dependency && snapshot.rules.any? { |rule| rule.identity == dependency.identity }
            actual = candidate.rules.find { |rule| rule.identity == dependency.identity }
            unless actual && declaration(actual) == declaration(dependency)
              @issues << finding(:nat_dependency_changed, "NAT 关联安全规则已变更，旧谓词引用不能证明新效果")
            end
          end
          unless environment(snapshot) == @environment
            @issues << finding(:nat_outside_target, "NAT 路由、区域或接口依赖发生变化")
            return
          end
          original = declarations(snapshot)
          current = declarations(candidate)
          kept = current.select { |entry| original.include?(entry) }
          if kept != original
            @issues << finding(:nat_outside_target, "既有 NAT 关系、顺序或依赖发生变化")
            return
          end
          unexpanded_embedded_rules(candidate).each do |rule|
            next if original.include?(declaration(rule))
            @issues << finding(:conditional_nat, "新增内嵌 NAT 缺少可证明的原始匹配与转换关系", rule_id: candidate.signature(rule))
          end
          additions = candidate.nat_rules.reject { |nat| original.include?(declaration(nat)) }
          additions.each do |nat|
            footprints(nat).each do |traffic, context|
              permitted = expectations.select { |expected| context_covered?(expected.context, context) }.reduce(TrafficSet.new) { |union, expected| union | expected.traffic }
              unless permitted.cover?(traffic)
                @issues << finding(:nat_outside_target, "新增 NAT 超出批准的原始流量范围", rule_id: candidate.signature(nat))
              end
            end
          rescue Error, TrafficSet::LimitExceeded => error
            @issues << finding(error.is_a?(Error) ? error.code : :query_too_complex, error.message)
          end
        end

        def context_covered?(approved, actual)
          approved.all? { |key, value| value.nil? || (actual[key] && value.to_s.casecmp?(actual[key].to_s)) }
        end

        # 迁移前后声明相同仍可能改变源端无 NAT 的流量；以同一原始范围模型证明完全不相交。
        # 不使用区域差异排除流量，因此未知路由/阶段不会制造虚假的不相交结论。
        def prove_untranslated(actual, observations)
          targets = change_set.targets
          if targets.empty? || targets.any? { |target| target.traffic_set.empty? }
            raise Error.new("无转换证明需要非空的明确目标流量", code: :missing_untranslated_scope)
          end
          if actual.nat_rules.size * targets.size > change_set.proof_limit
            raise Error.new("无转换范围比较超出证明预算", code: :proof_budget_exceeded)
          end
          unexpanded = unexpanded_embedded_rules(actual).first
          if unexpanded
            return [ finding(:conditional_nat, "内嵌 NAT 尚未展开原始匹配与转换关系，无法证明未转换", rule_id: actual.signature(unexpanded)) ]
          end
          actual.nat_rules.each do |nat|
            next if nat.disabled?
            # StaticNat 的既有 footprint 同时覆盖可能的正反方向；动态反向关系未知则不能省略。
            if !nat.is_a?(Elements::StaticNat) && nat.bidirectional.nil?
              raise Error.new("原生 NAT 反向范围未知", code: :conditional_nat)
            end
            footprints(nat).each do |traffic, _context|
              targets.each do |target|
                next if (traffic & target.traffic_set).empty?
                return [ finding(:target_nat_interference, "迁移目标流量与已有 NAT 原始范围相交", rule_id: snapshot.signature(nat)) ]
              end
            end
          end
          observations.concat(targets.map do |target|
            { relation: :untranslated, traffic: ChangeSet.traffic_document(target.traffic_set), context: target.context }
          end)
          []
        rescue Error => error
          [ finding(error.code, error.message) ]
        end

        # 未展开的标记仍是转换证据；停用的独立 NAT 不能解释活动安全规则中的内嵌转换。
        def unexpanded_embedded_rules(actual)
          expanded = actual.nat_rules.reject(&:disabled?).filter_map { |nat| nat.original_packet.match_rule&.identity }
            .to_h { |identity| [ identity, true ] }
          actual.rules.select { |rule| rule.nat? && !rule.disabled? && !expanded.key?(rule.identity) }
        end

        def footprints(nat)
          if nat.disabled? || nat.original_packet.match_rule
            raise Error.new("新增 NAT 的状态或关联规则尚无完整范围证明", code: :conditional_nat)
          end
          packet = nat.original_packet
          context = { from_zone: single_zone(packet.source_zones), to_zone: single_zone(packet.destination_zones), vrf: packet.vrf }
          services = packet.services || ANY_SERVICE
          if packet.protocol && IPAddr.protocol_number(packet.protocol).positive?
            services &= IPAddr.service("#{packet.protocol}/0-65535")
          end
          if packet.destination_port
            mask = Set.new(*(0..255).flat_map { |protocol| IPAddr.ports(packet.destination_port).map { |range| ((protocol << 16) + range.begin)..((protocol << 16) + range.end) } })
            services &= mask
          end
          forward = self.class.traffic(packet.source_addresses || ANY_ADDRESS, packet.destination_addresses || ANY_ADDRESS, services, packet.source_port)
          result = [ [ forward, context ] ]
          if nat.is_a?(Elements::StaticNat) && !nat.source_translation.identity?
            reverse = self.class.traffic(packet.destination_addresses || ANY_ADDRESS, nat.mapped_set, services, packet.source_port)
            result << [ reverse, { from_zone: nat.mapped_zone, to_zone: nat.real_zone, vrf: nil } ]
          elsif nat.bidirectional?
            raise Error.new("新增 NAT 的原生反向规则范围尚无证明", code: :conditional_nat)
          end
          result
        end

        def single_zone(zones)
          return if zones.nil? || zones.empty?
          raise Error.new("NAT 多区域范围尚无证明", code: :conditional_nat) unless zones.one?
          zones.first
        end

        # 共用正式声明比较器；NAT 原生顺序保留在摘要及有序列表中。
        def declarations(value)
          ordered = value.behavior.nat_groups.flatten + Array(value.behavior.nat_policy_rules)
          ((ordered + (value.nat_rules - ordered) + value.rules.select(&:nat?)).map { |element| declaration(element) } +
            embedded_dependencies(value)).freeze
        end

        # 内嵌转换由安全链首命中决定；普通前驱也会抑制 NAT，不能只保留 nat? 子序列。
        # 保护每条转换前的声明前缀，后方规则及其它链不属于该转换的依赖。
        def embedded_dependencies(value)
          comparator = ChangeSet::DeclarationComparison.new(snapshot, candidate)
          embedded_chains(value).flat_map do |ordered, anchors|
            # 声明摘要长度固定；累积摘要保留顺序与边界，避免为每个锚点复制整个前缀。
            prefix = Digest::SHA256.new
            ordered.filter_map do |rule|
              digest = comparator.declaration_digest(rule)
              prefix << digest
              [ digest, prefix.hexdigest ] if anchors.key?(rule.identity)
            end
          end.sort_by(&:first)
        end

        def embedded_chains(value)
          linked = value.nat_rules.filter_map { |nat| nat.original_packet.match_rule&.identity }
            .to_h { |identity| [ identity, true ] }
          value.rules.group_by { |rule| [ value.behavior.rule_chain(rule), rule.scope ] }.values.filter_map do |rules|
            anchors = rules.filter_map { |rule| [ rule.identity, true ] if rule.nat? || linked.key?(rule.identity) }.to_h
            next if anchors.empty?
            [ RuleOrder.new(value.behavior).resolve(rules), anchors ]
          end
        end

        def environment(value)
          [ Elements::Route, Elements::Interface, Elements::Zone ].flat_map do |type|
            value.elements(type).map { |element| declaration(element) }
          end.sort.freeze
        end

        def declaration(object)
          comparator = ChangeSet::DeclarationComparison.new(snapshot, candidate)
          object.is_a?(Elements::NatRule) ? comparator.nat_declaration_digest(object) : comparator.declaration_digest(object)
        end

        def finding(code, message, rule_id: nil)
          Finding.new(check: :nat_effect_proof, rule_id: rule_id, status: :unknown, severity: :critical,
            message: message, evidence: { code: code })
        end
      end
    end
  end
end

require_relative "verification/expectation"
