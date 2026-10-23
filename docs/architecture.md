# 架构与宿主接入

模块来源为 Algosec 应用的 `backend/lib/algosec.rb` 及 `backend/lib/algosec/`。新工程的 `lib/` 是唯一领域源码；原应用通过 gem 依赖消费代码，不再维护第二份实现。

## 分层

`Elements` 保存对象和引用，`Config` 将设备文本解析为带诊断的结果，`Policy` 消费结果快照进行查询、分析与规划，`Deployment` 协调已有计划的执行与读回。厂商实现归 `Vendors`；共享层调用声明的能力，不按厂商散布重复分支。

领域命名以 Palo Alto 的常用术语为基准：`AddressObject`、`ServiceObject`、`SecurityRule`、`NatRule`、`Rulebase`。这统一对象和属性，不把其他厂商的执行顺序、默认动作或 NAT 阶段改写成 PAN-OS 语义。`Scope`、原生身份、规则绑定和厂商元数据保留实际配置上下文。调用方直接使用规范类型；不提供 `Address`、`Service`、`Rule` 类别名或旧路径转发。

对象通过构造器和明确的 `with` 方法保护不变量。解析结果发布后封存同一对象图；新候选共享未变的对象引用，只替换实际修改的声明。未知动作、缺失配置、未解析条件和不完整证据分别表达，不能用空值或默认成功掩盖。

`ctx_parser` 保留配置来源与游标；`net-connector` 管理传输、认证、交互、结果与会话清理；`ctx_driver` 支持具名证据采集。ActiveSupport 负责成熟的缓存、时区与扩展能力，Nokogiri 负责 XML。独立化的目标是明确宿主边界，不是清除依赖或重写这些机制。

公开入口为 `require "algosec"`。独立子入口包括 `algosec/config`、`algosec/config/document`、`algosec/policy`、`algosec/elements`、`algosec/connector`、`algosec/device_session`、`algosec/deployment`、`algosec/builtin_services`、`algosec/dns_resolver`、`algosec/offline_check`。审批文档另显式加载 `algosec/policy/plan_document`。内部实现保留显式依赖顺序与厂商按需加载，不引入另一套自动加载器。

## 模块组织与 NAT 边界

独立领域对象保留清楚的专业名称；专属辅助实现放进拥有者的子目录，文件路径与命名空间对应。目录不按下划线机械拆分：`SecurityRule`、`NatPool`、`RoutingTable` 本身就是完整概念。

```text
elements/
  address/expansion.rb             # Address::Expansion
  service/expansion.rb             # Service::Expansion
  catalog/reference_resolver.rb    # Catalog::ReferenceResolver，私有
  nat.rb                          # NAT 值对象入口
  nat/original_packet.rb
  nat/translation.rb
  nat/source_translation.rb
  nat/destination_translation.rb
  static_nat.rb                    # 固定地址映射
  dynamic_nat.rb                   # 规则型 NAT
  security_rule.rb                 # 安全策略领域对象
policy/
  nat.rb                          # NAT 查询、转换、验证和生成入口
  nat/translator.rb
  nat/resolver.rb
  nat/verification.rb
  nat/service_query.rb
  nat/embedded_selection.rb
  nat/generation.rb
  nat/generation/{huawei,palo_alto}.rb
  generator/{syntax,state,rule}.rb
  request/traffic.rb
  rule_matcher/comparison.rb
  analysis/rule_view.rb
  change_set/{declaration_comparison,proof_contexts}.rb
config/
  cache/entry.rb
  parser/syntax.rb
  result/rule_projection.rb
```

`Elements::Address`、`Elements::Service` 是共享能力的命名空间；具体领域对象仍是 `AddressObject`、`AddressGroup`、`ServiceObject`、`ServiceGroup`。`Catalog` 拥有引用装配过程，`Config::Result` 拥有报告投影，`Config::Cache` 拥有内部序列化条目。

`AddressGroup::Negated` 属于地址匹配领域，位于 `elements/address_group/negated.rb`。厂商解析器将原生命令转换为这个对象；配置文档不再依赖 PAN-OS 专属的领域子类。地址组的成员类型由地址／服务族确定，子类仍能引用同族普通组。`Address::Expansion::Projection` 位于 `address/expansion/projection.rb`，递归遍历后调用对象的集合语义，因此嵌套取反、独立查询和共享规则报告保持一致，DNS 条件及缺失引用继续保留为未知证据。

`StaticNat` 与 `DynamicNat` 保留当前工程的分类：前者保存固定映射及精确配对，后者保存基于原始报文条件的 NAT 规则。**`DynamicNat` 不承诺每一侧采用动态分配**；规则可以声明纯静态转换或混合转换。分配性质读取 `source_translation.mode`、`destination_translation.mode` 和 `allocation_mode`，不从 Ruby 类名推断。源／目的表示转换角色，静态／动态表示映射或分配方式，二者独立；PAN-OS 的源转换也分别提供 static IP、dynamic IP 和 dynamic IP and port 模式。参见 [Source NAT](https://docs.paloaltonetworks.com/ngfw/networking/nat/source-nat)。

两种 NAT 对象共用 `NatRule` 协议，组合 `Nat::OriginalPacket`、`Nat::SourceTranslation` 和 `Nat::DestinationTranslation`。两种方向的转换继承共同的 `Nat::Translation` 值约束；目的转换不继承源转换，也不暴露源端口转换专属算法。原始范围、转换目标和引用图各有唯一的状态拥有者。

`DestinationTranslation` 另持有目的端口的原生关系模式，证明保持端口、固定目标或明确的一对一偏移。两个端口集合分别包含请求值，不能替代对应关系证明。厂商解析器声明已知模式，`ServiceQuery` 在按协议和规则分段时保留请求的偏移、常量及孔洞；请求集合等长不会使未知的设备模式变成已知。选择首条原生规则后才验证转换结果，未证明的关系在反向发现中继续保留为未知。

`Policy::Nat::Translator` 将查询地址换算为厂商策略使用的匹配地址，`Nat::Resolver` 选择已有转换关系，`Nat::Verification` 验证转换效果，`Nat::Generation` 装配实际生成的声明证据。`Nat::Translator.build(snapshot)` 通过厂商的 `nat_translator` 选择子类，共同逻辑直接由基类实现。ASA 与 PAN-OS 的扩展均位于各自的 `nat/translator.rb`。`nat.rb` 负责装配这些职责，不集中实现所有算法。

配置对象缓存当前为 `algosec-config-ruby-v82`，需要从原文重建旧缓存。配置文档仍使用显式类型码，不保存内部 Ruby 类路径，schema 版本保持不变。目录迁移本身不改变领域行为版本；取反地址组的引用装配、嵌套计算和共享报告修正对应 `firewall-domain-v5`，目的端口关系与解析修正对应 `firewall-domain-v6`；生成候选保留地址组取反及服务组属性的修正对应 `firewall-domain-v7`。部署基线纳入快照时区后进一步升为 `firewall-domain-v8`、策略修订 v27。旧语义文档及计划须重新生成。

## 证据与算法

`Config::Document` 使用固定类型编解码器保存声明、引用、来源摘要、解析上下文和诊断；载入时调用领域构造器，校验版本与摘要，不恢复任意 Ruby 类。默认导出省略原始配置和未解析命令正文，但保留其存在、数量和摘要。需要完整生成片段的宿主显式使用 `raw: true`，并负责加密和访问控制。

`Config::Comparison` 使用同一份声明类型定义，比较根匹配组及其引用图的类型、作用域和成员，区分普通组与取反组。根匹配组的临时名称和配置正文不作为规则变化；具名依赖仍保留完整声明。`Config::Diagnostic` 自行校验并拥有不可变字段，解析器按诊断值去重，结果只复制诊断列表，不重复复制每个诊断；正文不存在与正文已脱敏保持不同状态。

`Analysis` 返回 `Assessment` 和独立的 `Finding` 值；无法确定的检查抛出 `Analysis::Unknown`，不再用空子类重复命名同一分析协议。查询的 `Result` 与批次 `Report` 分别拥有文件和发布边界。

`Packet` 与 `TrafficSet` 表达地址族、源地址、目的地址、协议、源端口和目的端口。集合运算保留各维度之间的配对，不把分别合并的源、目的集合当作原有流量并集。`Evaluation` 按原生顺序分割剩余流量，复用同一首条匹配算法处理查询、候选验证和独立读回；未知条件会产生未知结果，不能跳过后假定命中下一条。

`TrafficSet::Region` 与 `TrafficSet::Budget`、`Evaluation::Predicate` 与 `Evaluation::Result`、`ChangeSet::Intent` 与 `ChangeSet::Target` 分别放在所属对象目录。具体的算法、值和结果仍有明确职责，短小的记录类型保留在使用处。

`ChangeSet` 保存明确的创建、修改、移动和删除意图。意图完整校验后才封存规则，失败不会改变调用方的对象图。修改规则时通过组的复制协议保留子类、作用域与协议属性，并独立复制成员容器。`Generator` 在实际发出原生命令时记录分配的名称、成员、位置和时间计划，由这些生成证据构造候选。`Plan` 同时要求命令生成、目标行为、目标之外行为保持以及必需的效果证明通过。`Plan#to_h` 是审阅数据，不能把其中的 `verified` 字段载入为执行授权。

`Generator` 的可选 `state:` 是同一快照内连续生成的临时分配记录，只接受可修改的 Hash 或 nil。生成前封存配置目录和内建服务，成功后才发布名称、编号和绑定；失败保留先前分配状态。已使用的记录绑定原始 `Snapshot` 实例和生成器类，不能跨设备、跨厂商、跨实现或在重新加载的快照上复用。新上下文使用新的空状态；旧的无来源记录不被推定有效。它不属于配置文档或审批持久化格式。

名称分配由厂商声明占用同一名称空间的对象类型，共享分配器同时检查配置目录、外置内建服务和本次已分配名称。地址对象与地址组、服务对象与服务组不会因 Ruby 类型不同而重复使用名字；ASA 还合并网络与服务对象族，Fortinet 合并地址与 VIP 对象族。SRX、Netscreen 复用元素定义的地址引用区域，包含本地区域和全局回退，避免新建局部对象遮蔽旧规则引用的全局对象；其他区域独有的对象仍可同名。原生命名约束参见 [PAN-OS 对象名称](https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000ClhICAS&lang=en_US)、[ASA 对象名称空间](https://www.cisco.com/c/en/us/td/docs/security/asa/asa912/configuration/firewall/asa-912-firewall-config/access-objects.html)和 [FortiOS 重名限制修复](https://docs.fortinet.com/document/fortigate/6.4.0/fortios-release-notes/289806/resolved-issues)。

Fortinet 的 `VipBinding` 保存不可变的外部地址范围、接口、协议/端口和内部转换。重叠范围内的地址或端口偏移不同即拒绝生成；`any` 接口和不限制协议的完整地址映射参与重叠判断。它复用生成事务保存同批及跨批声明，不解析原生命令，也不承担 NAT 效果证明。已有配置中的 NAT 关系仍由查询和效果证明单独处理。

安全策略证明以明确的区域、规则链和应用上下文为条件，不独自证明路由或 NAT。NAT 效果由 `Nat::Verification` 复用原始流首条匹配及转换关系，结合实际生成声明验证；时间效果由 `TimeVerification` 从计划时刻起检查完整一次性窗口的边界、区间和未来尾段。周期计划、动态会话分配或原生语法缺乏证明时，计划显式保留阻断原因。所有效果证明绑定同一个 `ChangeSet`，读回重新计算证据。

`Convergence.new(snapshot).perform(rule_ids: ids)` 对明确选中的同一规则链执行整批合并或去冗余。`Reclaimer.new(snapshot).perform` 返回分类证据，`#plan(rule_ids: ids)` 对选中的删除重新证明。两者共用精确集合、首条匹配及变更集，不分别实现端口、区域或时间匹配。

`Migration.new(source:, target:, zones: mapping).perform` 将源端有效的普通策略分区映射到目标快照；`zones` 为源区域名到目标区域名的映射。入口 ACL 没有原生出口约束时，调用方必须提供 `source_zone_pairs: [["inside", "outside"]]`，输出保留这个请求范围。迁移证明限于声明范围，不代表完整设备、路由或默认行为迁移。无法保持动作、日志状态、时间或 NAT 关系时返回不可执行计划及原因。

## Rails 应用

应用 Gemfile 声明 `gem "algosec"`；初始化器加载入口并调用 `Algosec::Vendors.validate!`。应用自己的 `Algosec::Application`、services 和 jobs 继续由 Zeitwerk 管理，gem 的命名空间可以共存。

ConfigurationPipeline 负责选择宿主缓存：未配置 `ALGOSEC_CACHE_DIR` 时传入 `Config::Cache.new(store: Rails.cache)`；配置目录时交由 `Config::Cache.new` 选择 FileStore。显式传入的 `cache:` 保持优先。

数据库记录、锁、快照版本核验、任务恢复、鉴权和设备凭据配置都保留在应用。离线模块不持久化应用模型，也不自动重试可能已执行的设备操作。宿主将解析、DNS 与计划计算放在事务之外，再以短事务校验配置修订和业务状态；持久化的计划必须重建类型对象并重新验证。

`Snapshot#baseline` 统一提供设备、厂商、配置修订、软件版本、设置、时区和语义版本。`Plan`、`ChangeSet` 与 NAT/时间效果证明共用这份不可变上下文；源、目标各自与批准基线比较，时区漂移在第一条写命令前拒绝。宿主通过 `Plan.validate_context!` 比较数据库上下文时，也必须包含 `time_zone`，不能从当前环境补填旧审批。候选图的恢复独立核对时区。

`Plan#target_snapshot` 和 `#source_snapshot` 保留本次实际参与证明的封存对象图。审批记录同时绑定原配置版本与这两份实际图，因而能够恢复规划时已经刷新的 DNS 观察，不会退回到最初导入时的旧答案。恢复不触发解析或 DNS。宿主 `DeploymentReadback` 预检还比较完整图，核对地址、解析来源和观察时间；基础 `Deployment::Verification` 的上下文检查尚不提供这项 DNS 观察一致性保证，使用该适配器时需由自定义 verifier 补齐。

`Deployment` 依赖明确的会话工厂、日志适配器和读回验证器。它区分配置效果确认、设备保存确认、日志提交确认和原执行会话关闭。会话工厂创建的连接由协调器关闭；借入连接的关闭责任留给调用者。写入后失去结果时保留 `uncertain`，不得自动重放命令。

终态收尾放在 `ensure` 中，覆盖普通异常、取消、线程终止和非局部退出。写入前中止为 `failed`，开始写入后为 `uncertain`。未收到日志确认时不标记日志已提交；会话工厂没有正常返回时，不补造执行通道关闭证明。批量返回的全部完成步骤先进入 `Attempt`，再逐条持久化；日志失败不会删除已知步骤，也不自动重试失败的日志或设备命令。

`DeviceSession#execute_script` 的进度块保持只在成功进度时触发。部署显式传入 `on_receipt:`，对声明此参数的连接器使用独立完成回执，在响应完成后的日志、后处理或取消失败时仍固定已交付的步骤；旧连接器沿用进度块与返回 `Result` 补录。部署不同时注册进度块和完成回执，步骤仍按阶段和位置去重。此能力属于连接器，领域层不复制执行引擎或从异常猜测设备响应。

保存确认只接受本厂商全部保存命令的明确完成行，并排除失败和重绘历史。保存回执先核验原生证据，再写日志；之后的取消或回执日志失败不撤销已确认的保存事实。返回结果仅因连接器自身 `LogError` 失败时也保留已有原生保存确认。下发仍传播失败并保持不确定，效果读回与日志提交分别判断。未回传的完成证据无法从缺失回执推断，当前依赖交付边界见[能力说明](capabilities.md)。

宿主的原执行令牌和可轮换的核验令牌各有职责。租约过期不等于原会话已退出，也不立即释放设备预留。只有原写入方确认关闭、后续只读核验取得足够新证据，并成功持久化结论，才允许结束不确定状态。

## 工作区提取

最初的 0.2.0 提取包含当时工作区的 158 个 Ruby 文件，含未跟踪 Huawei NatPlan 和 4 个未提交修改文件。该提取除缓存宿主边界和版本号外保持原内容；后续领域重构以此为基线。原文件 SHA256、提取前补丁及快照保存在本地 `tmp/extraction/`，该目录被 Git 和 gemspec 排除。

原测试中存在 10 条与当前领域实现不一致的预期，已用相同测试分别加载原源码和新源码复现。迁移按既有契约调整测试：源策略路由参与匹配、等价不同出口保持歧义、H3C 服务组按 ServiceGroup 取值、原生规则编号为数字、Fortinet 池复用需要模式和 ARP 属性、华为 NAT 需要顺序及原生匹配证据，未支持语法保留不完整诊断。这些调整没有改变领域规则。

## 验证边界

领域测试可独立运行，设备传输使用可观察的替身；真实设备不在离线验收范围内。应用集成测试另外使用隔离数据库。发布包还需从临时 GEM_HOME 安装并在工程外加载，防止测试误用相邻源码或系统已安装的同名模块。
