# frozen_string_literal: true

require "active_support/core_ext/hash/except"
require "active_support/core_ext/hash/slice"
require "json"
require_relative "result"
require_relative "ranges"
require_relative "snapshot"
require_relative "generator/state"
require_relative "generator/syntax"
require_relative "script"
require_relative "generator/rule"
require_relative "nat/generation"
require "digest"

module Algosec
  module Policy
    # 根据查询结果生成厂商命令，并把名称、编号和绑定状态延迟到成功后提交。
    class Generator
      extend Declarations
      extend Syntax
      include Syntax::Runtime
      # 各厂商生成服务对象时共用的完整端口范围。
      ANY_PORTS = Elements::Definition::ANY_PORTS
      attr_reader :result, :commands

      # 校验结果包含配置快照，并为本次设计建立独立命令和状态容器。
      def initialize(result = nil, snapshot: nil, state: nil)
        raise ArgumentError, "命令生成必须使用 Result" unless result.nil? || result.is_a?(Result)
        snapshot ||= result&.snapshot
        raise ArgumentError, "命令生成需要配置快照" unless snapshot.is_a?(Snapshot)
        raise ArgumentError, "命令生成的快照不一致" if result && !result.snapshot.equal?(snapshot)
        unless state.nil? || (state.is_a?(Hash) && !state.frozen?)
          raise ArgumentError, "对象分配状态必须是可修改的 Hash 或 nil"
        end
        @result, @snapshot, @shared_state = result, snapshot, state
        @commands, @registry = [], State.new(snapshot, generator: self.class)
      end

      # 文本调用与结构化预览共用同一次生成流程。
      def perform(results = result) = render(results).text

      # 单条或有序批次共享分配；成功后一起发布文本、逐条命令和实际成员引用。
      def render(results = result, remove_rules: [])
        original = @result
        entries = []
        text = build_script do
          results = [ results ] if results.is_a?(Result)
          unless results.is_a?(Array) && results.all? { |item| item.is_a?(Result) && item.snapshot.equal?(snapshot) }
            raise ArgumentError, "命令生成必须使用同一配置快照的 Result 或 Result 数组"
          end
          if results.map(&:definition).uniq.size > 1
            raise Error.new("同一批次不能混用不同策略定义", code: :mixed_definitions)
          end
          unless remove_rules.is_a?(Array)
            raise ArgumentError, "删除规则必须为数组"
          end
          removal = operation_declaration(:remove_rule, remove_rules) unless remove_rules.empty?
          if results.any? { |item| remove_rules.include?(item.rule) }
            raise Error.new("同一批次不能同时修改和删除同一规则", code: :conflicting_rule_modifications)
          end
          results = results.flat_map(&:generation_results)
          prepare_batch(results)
          results.each do |item|
            @result = item
            @intents, @proof_issues, @nat_evidence = [], [], []
            @generated_schedule = nil
            @references = Result::DIMENSIONS.to_h { |dimension| [ dimension, [] ] }
            offset = commands.size
            case result.type
            when :new then create_rule
            when :modify
              registry.claim_rule_modification(result.rule)
              modify_rule
              record_modified_rule if @intents.empty?
            when :ignore then create_nat_only
            end
            body = commands.drop(offset)
            entries << Script::Entry.new(result: result, text: command_text(frame(body)), references: @references, intents: @intents, issues: @proof_issues, nat_evidence: @nat_evidence)
          end
          remove_rules.uniq.each do |rule|
            offset = commands.size
            send(removal.options.fetch(:handler), rule)
            entries << Script::OperationEntry.new(operation: :remove_rule, rule: rule,
              text: command_text(frame(commands.drop(offset))), intents: [ ChangeSet::Intent.delete(rule_id: rule.rule_id) ])
          end
        end
        Script.new(text: text, entries: entries)
      ensure
        @result = original
        @references = nil
      end

      # 为已选规则生成登记操作的脚本；此入口不向设备执行操作。
      def generate_operation(operation, rules)
        build_script do
          declaration = operation_declaration(operation, rules)
          rules.uniq.each { |rule| send(declaration.options.fetch(:handler), rule) }
        end
      end

      protected

      attr_reader :registry, :snapshot

      def operation_declaration(operation, rules)
        declaration = self.class.declarations[[ :command_operation, operation ]]
        raise Error.new("#{snapshot.vendor} 不支持 #{operation}", code: :unsupported_operation) unless declaration
        current_rules = snapshot.rules
        unless rules.is_a?(Array) && rules.all? { |rule| current_rules.any? { |current| current.equal?(rule) } }
          raise ArgumentError, "策略操作只能引用当前快照的规则"
        end
        declaration
      end

      # 生成器在实际发出规则后登记原生身份和落位；设备分配编号用明确的待分配身份。
      def record_created_rule(name: nil, native_rule_id: nil, rule_set: nil, scope: nil, members: nil, before: nil, rule_number: nil, placement: nil)
        declaration = self.class.declarations.fetch(:command_policy).options
        identity = native_rule_id || name || stable_name("pending", [ rule_key(members), @intents.size ])
        rule = Rule.new(snapshot, result).create(members: members || result.actions.fetch(:new),
          schedule: @generated_schedule,
          name: name, native_rule_id: identity, rule_set: rule_set, rule_number: rule_number,
          scope: scope, action: policy_action, log_enabled: declaration[:logging_default])
        @intents << ChangeSet::Intent.create(rule: rule, placement: placement || declaration.fetch(:placement))
        @intents << ChangeSet::Intent.move(rule_id: rule.rule_id, before: before.rule_id) if before
      rescue Error, ArgumentError => error
        record_proof_issue(error)
      end

      def record_modified_rule
        rule = Rule.new(snapshot, result).modify
        @intents << ChangeSet::Intent.modify(rule_id: result.rule.rule_id, rule: rule)
      rescue Error, ArgumentError => error
        record_proof_issue(error)
      end

      def record_proof_issue(error)
        @proof_issues << Finding.new(check: :generation_evidence, rule_id: result.rule&.rule_id, status: :unknown,
          severity: :critical, message: error.message,
          evidence: { code: error.respond_to?(:code) ? error.code : :unsupported_generation_proof })
      end

      # 厂商可在发射命令前统一规划同批结果的相互作用。
      def prepare_batch(results) end

      # 查询生成和回收共享相同的原子命令与分配状态边界。
      def build_script
        snapshot.require_complete!
        snapshot.catalog.seal!
        snapshot.builtin_services.each(&:seal!)
        @commands, @registry = [], State.new(snapshot, generator: self.class, state: @shared_state || {})
        yield
        @commands = frame(commands)
        registry.commit(@shared_state)
        command_text(commands)
      rescue
        @commands, @registry = [], State.new(snapshot, generator: self.class)
        raise
      end

      # 校验并追加设备命令行，保持生成顺序。
      def emit(*lines)
        lines.each { |line| Value.text(line, label: "设备命令") }
        commands.concat(lines)
      end

      def command_text(lines) = lines.map { |line| "#{line}\n" }.join

      # 保存真正写入策略的成员；厂商也可记录内联地址和服务参数。
      def remember_members(dimension, values)
        @references[dimension] |= values if @references
        values
      end

      # 对对象名称加引号并转义命令中的引号和反斜线。
      def quoted(value)
        text = Value.text(value.to_s, label: "对象名称")
        '"' + text.gsub(/[\\"]/) { |character| "\\#{character}" } + '"'
      end

      # 校验可直接放入命令的对象名称，拒绝命令分隔字符。
      def identifier(value)
        text = Value.text(value.to_s, label: "对象名称")
        raise Error, "对象名称不能用于未加引号的命令：#{text}" if text.match?(/[\s"'`;|\\]/)
        text
      end

      # 删除操作不接受通配符或路径表达式作为规则身份。
      def literal_identifier(value)
        text = identifier(value)
        raise Error, "规则身份必须是单一名称：#{text}" unless /\A[\p{Alnum}_.:\/@+-]+\z/.match?(text)
        text
      end

      def numeric_identifier(value)
        text = identifier(value)
        raise Error, "规则编号必须是非负整数" unless /\A[0-9]+\z/.match?(text)
        text
      end

      # 将地址表达式拆成集合、首尾地址和可选前缀。
      def address_parts(value)
        set = IPAddr.parse(value)
        text = IPAddr.format_range(set.first)
        _, prefix = text.split("/", 2)
        { set: set, text: text, first: IPAddr.from_i(set.min), last: IPAddr.from_i(set.max), prefix: prefix&.to_i }
      end

      # 将服务表达式拆成协议和单一端口范围，供厂商命令生成使用。
      def service_parts(value)
        protocol, ports = value.downcase.split("/", 2)
        number = IPAddr.protocol_number(protocol)
        raise Error, "无法生成服务：#{value}" unless [ IPAddr::TCP, IPAddr::UDP ].include?(number) && ports
        range = IPAddr.ports(ports).first
        raise Error, "服务端口顺序无效：#{value}" unless /\A[0-9]+(?:-[0-9]+)?\z/.match?(ports) && ports.split("-").map(&:to_i).each_cons(2).all? { |first, last| first <= last }
        { protocol: (number == IPAddr::TCP) ? "tcp" : "udp", first: range.begin, last: range.end, text: (range.size == 1) ? range.begin.to_s : "#{range.begin}-#{range.end}" }
      end

      # 校验操作结构，并为每个请求维度选择复用对象或新建对象。
      def prepare(action)
        action ||= {}
        raise Error, "策略对象操作必须是 Hash" unless action.is_a?(Hash) && (action.keys - Result::MEMBERS).empty?
        action.each do |dimension, members|
          raise Error, "#{dimension} 成员必须是 Hash" unless members.is_a?(Hash)
          next unless Result::DIMENSIONS.include?(dimension)
          members.each do |value, candidates|
            next if candidates.nil?
            unless candidates.is_a?(Array) && !candidates.empty? && candidates.all? { |name| name.is_a?(String) && !name.empty? }
              raise Error, "可复用的 #{dimension} 对象名称无效：#{value}"
            end
          end
        end
        names = Result::DIMENSIONS.to_h do |dimension|
          values = select_members(action.fetch(dimension, {}), dimension)
          [ dimension, remember_members(dimension, values.uniq) ]
        end
        %i[nat_sources nat_destinations].each do |direction|
          names[direction] = create_nat(action[direction], direction) if action.key?(direction)
        end
        names
      end

      # 同一维度先完成成员选择，再登记实际引用，便于厂商处理通配成员。
      def select_members(members, dimension)
        members.sort.flat_map { |value, candidates| select_member(value, dimension, candidates) }
      end

      # 选择调用方提供的复用名称，否则生成新的地址或服务对象。
      def select_member(value, dimension, candidates)
        return candidates.first if candidates
        (dimension == :services) ? create_service(value) : create_address(value, dimension: dimension)
      end

      # 确认新策略的三个核心维度都至少包含一个成员。
      def require_members!(members)
        Result::DIMENSIONS.each do |dimension|
          raise Error, "新增策略缺少 #{dimension} 成员" if members.fetch(dimension, []).empty?
        end
      end

      # 处理只有 NAT 操作的结果，不生成普通策略规则。
      def create_nat_only
        action = result.actions&.fetch(:new, {}) || {}
        %i[nat_sources nat_destinations].each { |direction| create_nat(action[direction], direction) if action[direction] }
      end

      # 校验并按静态、动态类型生成 NAT 命令所需的对象。
      def create_nat(records, direction)
        raise Error, "NAT 记录必须是 Hash" unless records.is_a?(Hash)
        values = records.sort.map(&:last)
        values.each do |record|
          nat = record[:nat]
          raise Error, "NAT 类型必须是 static 或 dynamic" unless nat && %i[static dynamic].include?(nat[:type])
          address_parts(record.fetch(:real_ip))
          address_parts(nat.fetch(:address)) if nat[:address] || nat[:type] == :static || direction == :nat_destinations
        end
        values.select { |record| record[:nat][:type] == :static }.each { |record| create_static_nat(record, direction: direction) }
        groups = values.select { |record| record[:nat][:type] == :dynamic }.group_by do |record|
          [ record[:nat].except(:rule), record[:rule_set] ]
        end.values
        create_dynamic_nat(groups, direction: direction) unless groups.empty?
      end

      # 相同业务定义复用；同名但不同定义时分配稳定后缀，避免覆盖设备对象。
      def define_object(kind, key, preferred, type: nil, zone: nil, occupied: [], case_sensitive: true, &block)
        registry.define(kind, key, preferred, type: type, zone: zone, occupied: occupied, case_sensitive: case_sensitive, &block)
      end

      # 只执行一次同一状态键对应的命令生成代码。
      def once(key, &block) = registry.once(key, &block)

      # 校验并生成一次性时间计划名称。
      def schedule_name
        schedule = result.schedule
        return unless schedule
        unless schedule.resolved? && schedule.kind == :once && schedule.start_at && schedule.end_at && schedule.start_at < schedule.end_at
          raise Error, "策略时间必须是完整且递增的一次性时间段"
        end
        raise Error, "设备时间计划只支持分钟精度" unless schedule.start_at.sec.zero? && schedule.end_at.sec.zero? && schedule.start_at.subsec.zero? && schedule.end_at.subsec.zero?
        if result.snapshot&.time_zone
          schedule = Elements::Schedule.new(name: schedule.name, start_at: schedule.start_at, end_at: schedule.end_at, time_zone: result.snapshot.time_zone)
        end
        unless [ schedule.start_at, schedule.end_at ].all? { |time| schedule.time_zone.tzinfo.periods_for_local(time).one? }
          raise Error.new("设备本地时间在夏令时转换处不唯一", code: :ambiguous_schedule_time)
        end
        key = [ schedule.start_at.to_i, schedule.end_at.to_i, schedule.time_zone.name ]
        preferred = "sch_#{schedule.start_at.strftime("%Y%m%d%H%M")}_#{schedule.end_at.strftime("%Y%m%d%H%M")}"
        name = define_object(:schedule, key, preferred, type: Elements::Schedule) { |selected| yield selected, schedule }
        @generated_schedule = Elements::Schedule.new(name: name, vendor: snapshot.vendor, device_id: snapshot.device_id,
          start_at: schedule.start_at, end_at: schedule.end_at, time_zone: schedule.time_zone).seal!
        name
      end

      # 校验静态 NAT 两端集合基数一致，并返回两端地址信息。
      def equal_nat_ranges!(record)
        real = address_parts(record.fetch(:real_ip))
        mapped = address_parts(record.fetch(:nat).fetch(:address))
        raise Error, "静态 NAT 的公网与私网地址数量不一致" unless real[:set].cardinality == mapped[:set].cardinality
        [ real, mapped ]
      end

      # 根据地址形态生成稳定的默认对象名称。
      def address_name(parts)
        case parts[:prefix]
        when 0 then "any"
        when 32 then "Host_#{parts[:first]}"
        when nil then "range_#{parts[:first]}-#{parts[:last]}"
        else "Net_#{parts[:text]}"
        end
      end

      # 区间精确拆成 CIDR，不能用单一掩码扩大请求范围。
      def cidrs(set) = IPAddr.cidrs(set)

      # 用规范化键生成稳定哈希后缀，避免同一对象跨请求改名。
      def stable_name(prefix, key)
        "#{prefix}_#{Digest::SHA256.hexdigest(JSON.generate(naming_key(key)))[0, 20]}"
      end

      # 分配规则身份时包含来源和 NAT 分组，迁移的独立源规则不会合并。
      def rule_key(action = nil)
        key = [ result.from_zone, result.to_zone,
               *Result::DIMENSIONS.map { |dimension| (action ? action.fetch(dimension, {}) : result.public_send(dimension)).keys.sort },
               result.schedule&.window ]
        key << result.decision unless result.decision == :permit
        key << [ :source_rule, result.source_rule_id ] if result.source_rule_id
        key << action.slice(:nat_sources, :nat_destinations) if action && (action.keys & %i[nat_sources nat_destinations]).any?
        key
      end

      # 按规则区域、成员和时间计划生成并登记策略名称。
      def rule_name(prefix = "p")
        key = rule_key
        define_object(:policy, key, stable_name(prefix, key), type: Elements::SecurityRule,
                      occupied: snapshot.rules.map(&:native_rule_id).compact) { |_| }
      end

      # 从共享状态中取得设备范围内第一个可用编号。
      def available_id(kind, key, range, used)
        registry.available_id(kind, key, range, used)
      end

      # 只复用完整且固定的同区域地址；当前 DNS 答案相同不代表对象等价。
      def reusable_address(value, dimension:)
        set = IPAddr.parse(value)
        zone = (dimension == :sources) ? result.from_zone : result.to_zone
        snapshot.addresses.sort_by(&:name).find do |address|
          reusable_address_in_zone?(address, zone) && address.resolved? && !address.conditional? && address.resolved_set == set
        end&.name || create_address(value, dimension: dimension)
      end

      # 在设备未验证时间计划命令时拒绝带计划的设计。
      def unsupported_schedule!
        raise Error.new("#{result.vendor} 暂无经过验证的时间计划命令", code: :unsupported_schedule) if result.schedule
      end

      # 在设备未验证端口 NAT 命令时拒绝端口转换设计。
      def unsupported_port_nat!
        if result.services.values.any? { |record| record[:translated_port] }
          raise Error.new("#{result.vendor} 暂无经过验证的端口转换命令", code: :unsupported_port_nat)
        end
      end

      # 将请求服务和转换端口规范化为唯一端口映射。
      def port_mappings
        result.services.sort.map do |value, record|
          before = service_parts(record.fetch(:origin, value))
          after = service_parts("#{before[:protocol]}/#{record[:translated_port] || value.split("/", 2).last}")
          unless before[:first] == before[:last] && after[:first] == after[:last]
            raise Error.new("端口转换需要单个源端口和目标端口", code: :unsupported_port_nat)
          end
          { protocol: before[:protocol], before: before[:first], after: after[:first] }
        end.uniq
      end

      # 策略内嵌 NAT 只能作用于该策略的全部成员；不同分配与无 NAT 成员必须分开。
      def split_policy_actions(action)
        slices = %i[sources destinations].map do |dimension|
          direction = (dimension == :sources) ? :nat_sources : :nat_destinations
          action.fetch(dimension, {}).group_by do |value, _|
            record = action.dig(direction, value)
            next unless record
            next unless split_nat_record?(record)
            key = record[:nat].except(:rule, :group)
            (dimension == :destinations) ? [ key, record[:real_ip] ] : key
          end.values.map(&:to_h)
        end
        slices.first.product(slices.last).map do |sources, destinations|
          slice = action.merge(sources: sources, destinations: destinations)
          %i[nat_sources nat_destinations].zip([ sources, destinations ]).each do |direction, members|
            slice[direction] = action[direction].slice(*members.keys) if action[direction]
          end
          slice
        end
      end

      # 把集合、哈希、数组和区间转换成稳定命名键。
      def naming_key(value)
        case value
        when Set then value.map { |range| [ range.begin, range.end ] }
        when Hash then value.sort_by { |key, _| key.to_s }.map { |key, entry| [ key.to_s, naming_key(entry) ] }
        when Array then value.map { |entry| naming_key(entry) }
        when Range then [ naming_key(value.begin), naming_key(value.end) ]
        else value
        end
      end

      # 确认给已有策略补充 NAT 时，规则范围恰好覆盖当前请求。
      def validate_policy_nat_scope!
        unless result.rule && result.rule.sources.resolved_set == Ranges.addresses(result.sources.keys) &&
               result.rule.destinations.resolved_set == Ranges.addresses(result.destinations.keys) &&
               Ranges.rule_services(result.rule) == Ranges.services(result.services.keys)
          raise Error.new("给已有策略补充 NAT 会影响请求之外的流量，需要拆分策略", code: :nat_scope_conflict)
        end
      end

      # 判断现有地址对象能否在指定区域复用。
      def reusable_address_in_zone?(address, zone) = true

      # 判断 NAT 记录是否需要按动态规则拆分策略。
      def split_nat_record?(record) = record.dig(:nat, :type) == :dynamic
    end
  end
end
