# 防火墙自动化模块重构审计

审计基线：2026-10-22，`algosec-rb` 0.2.0。本文汇总核心模型、厂商适配、策略算法、执行与 Rails 接入四项源码审计，供高阶设计、任务拆分和验收追踪使用。它描述重构前的状态；问题进入实现后应以关联回归测试和验收结果更新状态，不能把本审计当作已修复证明。

本次联合审计完整阅读 `lib/**/*.rb` 的 **158 个文件、18,785 行**，包括根入口 `lib/algosec.rb`；仅统计 `lib/algosec/` 会得到 157 个。汇总时逐文件 SHA-256 与 `tmp/modernization/baseline-sha256.json` 相同。原提取工作和 Huawei NAT 改动均保留。另检查了原应用的采集、导入、查询、规划、执行、模型与任务边界，以及当前安装的 net-connector/ctx_driver 相关实现。

## 证据与现有能力

本轮主流程运行 `bundle exec rake`（原始输出保存在 `tmp/modernization/baseline-gates.log`）：**550 runs / 4902 assertions / 0 failures / 0 errors / 0 skips**；RuboCop 241 个文件通过。厂商审计独立运行 71 runs / 1489 assertions，生命周期审计独立运行 34 runs / 302 assertions，均通过。核心区间集另外通过种子 1022 的 5,000 次枚举集合对照。测试存在重叠，这些数字不能相加当成独立覆盖数。运行环境为 Homebrew Ruby 4.0.7 / Bundler 4.0.20；系统 Ruby 2.6 不适用。

现有测试通过仍有下文的可复现反例。所有这些证据来自源码、离线 fixture 或会话替身；不证明设备固件接受生成语法、真实登录、生产策略效果或保存持久化。本轮只读审计没有运行宿主数据库验收。结构化入库必须另有实际 PostgreSQL 往返测试；文件缓存往返不能替代。

当前登记表实际为 **14 个登记项、10 个防火墙实现、13 个 connector、1 个专用 collector**。下表直接核对 `Algosec::Vendors.definitions`，不沿用旧测试名称中的 nine/九家。

| 登记项 | 实际登记组件 | 能力边界 |
| --- | --- | --- |
| `asa`, `fortinet`, `h3c`, `huawei`, `neteye`, `netscreen`, `palo_alto`, `srx`, `topsec` | elements、parser、policy、generator、connector | 类存在不代表所有语法、版本、NAT 模式和删除操作均支持 |
| `hillstone` | 上述五项及 collector | collector 在同一会话采集固件内置服务 |
| `cisco_ios`, `cisco_n9k`, `radware` | connector | 不具备本模块的防火墙配置解析与策略生成能力 |
| `generic` | elements | 通用领域默认定义，不是设备语法适配器 |

`PolicyFactory::VENDORS` 从登记表动态取值，因此当前通用规则 roundtrip 为 10 厂商，通用迁移全配对为 100 对。它们主要覆盖简单网络规则；不能据此宣称完整策略或 NAT 的任意厂商迁移。保存配置 fixture 有 7 份：ASA、Fortinet、Hillstone、Huawei、Neteye、Palo Alto、Topsec；Huawei 样例明确为 partial。H3C、Netscreen、SRX 缺少同目录的保存配置 fixture，已有生成式测试须与原生配置证据区分。

## 值得保留的对象与业务边界

- `Catalog`、`ReferenceResolver` 已能区分缺失、歧义与循环引用，并按依赖顺序组装对象。地址定义与 DNS 观测分开，条件未知没有被统一改成 any。
- `Rule` 已区分原生身份、作用域身份、显示名称和执行顺序；`RuleBinding` 保留应用了空规则链的语义。继续演进这一套对象，不另建只供展示的平行规范化模型。
- `Set` 是可复用的不可变区间代数；Service 的完整 terms 和 NAT 映射对包含区间索引无法表达的信息。算法应复用数学基础并保留领域条件，不重写区间库。
- 路由保留 VRF、多个路径、策略路由未知与等价出口歧义。NAT 适配器保留不同厂商的阶段、作用域、豁免、顺序及配对，不按字段名强行统一执行顺序。
- `GenerationState` 的事务式分配、原子失败、确定命名及 Plan 的基线校验仍有价值；需要在其上增加语义证明，不以新框架替换这些成熟行为。
- net-connector 管理登录、传输、分页、提示符、命令结果和会话关闭；ctx_driver 管理独立查询采集。ActiveSupport 管理缓存与时区，Nokogiri 管理 XML。遵循用户要求，复用这些依赖。
- Rails 宿主管理加密、鉴权、审批、数据库约束、队列和持久认领；gem 管理领域语义与可复用流程。外部 I/O 留在短数据库锁之外；未知写入结果只能回读，不能自动重放。

## 已复现的领域缺陷

下表中的“已复现”仅指当前 checkout 的离线最小反例。行号属于上述基线，后续重构可能变化。优先级表示业务影响；不把尚未支持的能力误报成已有行为缺陷。

| 编号 | 影响及最小反例 | 当前位置 | 必须证明的回归契约 |
| --- | --- | --- | --- |
| D01 / P1 | PAN-OS 两条原始谓词相同的 DNAT，先译到 `.8`、后译到 `.9`；按期望 `.9` 查询会跳过真正首条，返回后条 | `policy/nat_resolver.rb:22`、`:519` | 先按原始包选择首条，再计算翻译；逆向候选必须通过正向验证；地址、端口、豁免及部分重叠均覆盖 |
| D02 / P1 | generic NAT 接受 `from_zone=inside`，仍命中仅 `dmz` 的前置 SNAT | `policy/nat_resolver.rb:520`；`policy/behavior.rb:91` | OriginalPacket 检查两端区域及声明的作用域；缺少必要上下文返回 unknown，不忽略调用方传入条件 |
| D03 / P1 | 前置 deny TCP/443、后置 permit any；精确查询 `protocol=any` 错报 permit，而 TCP 查询 deny | `policy/traffic_matcher.rb:28`；`policy/traffic_ranges.rb:35` | Packet 只接收具体协议；TrafficSet 单独表达协议集合，保留 deny/allow/unknown 分区及命中依据 |
| D04 / P1 | Fortinet 省略 action，完整解析后得到 permit；FortiOS 文档定义缺省为 deny | `vendors/fortinet/parser.rb:345`；`elements/definition.rb:106` | 厂商边界解析真实默认值；统一 Action 不能把缺失/未知默认为允许 |
| D05 / P1 | Topsec / ScreenOS 规则尾部附加未知匹配字段，parser 吞掉整行，仍 `complete?=true` 且无对象诊断 | `vendors/topsec/parser.rb:137`；`vendors/netscreen/parser.rb:364` | 完整 token 消费；未识别条件附着对应规则并产生诊断；手工 Snapshot 也不能绕过条件未知 |
| D06 / P2 | SRX 生成地址 `range-address A to B`，自身 parser 只接受单值地址，回读 partial | `vendors/srx/generator.rb:43`；`vendors/srx/parser.rb:133` | 所有已声明可生成地址形态可完整解析，保持端点与身份；另需原生语法证据 |
| D07 / P2 | PAN Source Translation 的 `arbitrary-mode` 被接受为完整 NAT | `vendors/palo_alto/parser.rb:515` | 受限翻译模式构造器；未知原生模式保留诊断，不能仅搬运字符串 |
| D08 / P2 | 显式 static NAT 配两个原始地址时，Request 静默改成 dynamic | `policy/request.rb:72` | 保持显式模式及一一配对，或明确拒绝不支持/不等长请求；不能靠集合数量改变业务意图 |
| D09 / P2 | 限定源端口和 UUID 的 TCP/443 Service，其 `matches?` 拒绝；公开 `Rule#covers?` 却用有损索引报告覆盖 | `elements/rule.rb:151`；`elements/service.rb:38` | 完整条件参与覆盖；无条件命中不能由协议/目的端口索引单独证明；不要外推为所有上层 matcher 都有同样漏洞 |
| D10 / P2 | 完整 Result 绑定来源后修改规则成员为缺失引用，`complete?` 和来源绑定不变，引用计数过期 | `config/result.rb:14`、`:81`；`elements/group.rb` | 构建态与发布态分离；同一 revision 的发布对象不可改变语义；DNS 刷新产生新观测/快照 |
| D11 / P2 | `Rule(status: 'vendor-future-status').active?` 为 true | `elements/rule.rb:58`；`elements/definition.rb:131` | 已识别原生状态才能映射布尔 disabled；未知状态不等同启用 |
| D12 / P2 | `Service(protocol: 'any', destination_port: '443')` 能匹配 UDP/53 | `elements/service.rb:104`；`ipaddr.rb:176` | any 与受限端口组合须有精确定义或明确拒绝；IP 协议 0 不能与内部 any 标记混淆 |
| D13 / P2 | 普通领域对象及 Diagnostic 的 inspect / ActiveSupport 默认 as_json 包含原始配置哨兵 | `elements/base.rb`；`config/result.rb:8` | 常规日志/inspect/JSON 只含安全元数据；原文和完整诊断通过明确导出接口取得 |
| D14 / P3 | 单独 `require 'algosec/policy'` 后构造默认时间 matcher，触发 `ActiveSupport::IsolatedExecutionState` NameError | `policy/request.rb:3` | 每个文档承诺的公开 require 入口在全新进程独立加载，显式依赖成熟库 |

D04 的外部语义依据为 [FortiOS 7.4.3 firewall policy CLI reference](https://docs.fortinet.com/document/fortigate/7.4.3/cli-reference/333889629/config-firewall-policy)。D05 的未知 token 反例不声称是厂商合法命令；它证明 parser 把自己不理解的输入错误标为完整。D11 同样是公开模型边界反例，不直接证明已知固件会输出该状态。

## 已确认的能力缺口

| 编号 | 当前边界 | 设计与验收要求 |
| --- | --- | --- |
| G01 | 覆盖与回收只寻找单条覆盖规则；两个 `/25` 的 allow 已覆盖 `/24`，仍建议修改，后续冗余 `/24` 不能被认出 | 共用精确多维并集/差集和 first-match 剩余区域；对角源/目的集合不得产生交叉放宽；输出未覆盖/差异见证，超预算明确 unknown |
| G02 | Searcher 无条件跳过同区域流量 | 显式 intrazone/interzone/universal 规则及厂商默认决策参与评估；不能把同区等同绕过安全策略 |
| G03 | Plan.ready? 仅表示无生成问题及可校验基线 | 分开生成准备、语义验证、执行回读、保存证据；ChangeSet 的预期变化及范围外不变性必须可验证 |
| G04 | Migration 仅处理空目标、网络条件规则；NAT、复杂时间/日志/应用等多项拒绝 | 扩展能力必须有精确映射和行为比较；不能将原先拒绝改成丢字段后成功；非空目标要证明放置顺序与既有行为 |
| G05 | 无统一 PAN-OS Application / source user / log settings 领域条件；原生语法 `acl/object` 与 PAN rule type 混在同一概念 | 单一 SecurityRule 模型直接用于解析、查询、规划、生成和持久化；原生绑定与语义 rule type 分开 |
| G06 | 当前 CacheEntry 是 Ruby 对象内部布局，不是公开持久化格式；类名进入身份和比较 | 明确 schema/semantic version 的 JSON 文档、稳定类型 ID、引用与作用域；构造器校验重建；升级使旧计划失效，宿主显式迁移/重解析 |
| G07 | 解析保留 IPv6，不等于所有查询/路由/NAT 支持 IPv6 | 地址族必须贯穿 TrafficSet 和 NAT；按已证明的厂商/操作能力发布，不能让相同低位整数跨族匹配 |
| G08 | 回收支持禁用、过期或单条覆盖，不具备使用率证据驱动的生命周期 | disabled、expired、redundant、unused 分开；零命中只有在观察窗口完整、计数器未重置且采集可靠时才成立；回收批次仍需前后等价与引用检查 |
| G09 | 安全的 deploy/preflight/save/readback/recovery 在 Rails 服务中，独立 gem 调用方需自行复制 | 以普通 Ruby 协作对象承接 Workflow、Attempt、Journal、Verifier；持久认领留宿主；未知执行只能回读 |

G01 是保守漏判，不能称为已证明的放行漏洞；现有局部合并算法有防止笛卡尔积放宽的约束，应保留。周时间窗逆序/空窗在当前测试中约定为 inactive，这属于需要明确的时间语义选择，不应直接列作 bug。

## 宿主接入的具体风险与补充验收

以下路径相对原应用 `algosec/backend`。这些是当前源码确认的边界缺失/交错风险；本审计未用真实数据库或进程终止测试重现所有交错，不声称已发生生产事故。

| 编号 | 当前证据 | 必须新增的验收 |
| --- | --- | --- |
| H01 | `collection.rb:35` 只持久化 content / builtins，丢失 Capture 的命令哈希、字节数、时间及辅助采集完整性 | 多命令采集到 PostgreSQL 后，新进程恢复同一证据和上下文；原文仍走加密存储，常规 JSON 无凭据 |
| H02 | Collection / Deployment 只 claim queued，verify 只接 uncertain；进程被杀可能永久停留 running 并占用唯一设备约束 | 明确认领身份和失效/恢复协议；旧工作者不能继续写；只读采集可重新采集，可能写过的部署先转 uncertain 并回读，不能自动重发 |
| H03 | `policy_execution.rb:119` configure 回读只比较安全覆盖，没有验证计划中的 NAT 效果 | 原安全策略已允许、计划只增 NAT；回读映射缺失/错误/歧义时不能成功；同时验证成功路径的方向、地址、端口和先后顺序 |
| H04 | 审批/计划核验发生在实时读取之前；直接 import 可在两者间变更解析上下文，执行前仅比较配置文本 checksum | 确定性交错测试：同文本、不同解析上下文在首条命令前必须 stale_plan；最后短事务核验 revision 与认领，不把设备 I/O 放锁内 |
| H05 | RequestPlanning 与 RiskAnalysis 在行锁内取 Snapshot，可能触发 DNS/缓存重建 | 锁外准备不可变证据，锁内只验证 revision 并持久发布；覆盖并发上下文变化 |
| H06 | `execute_script(...).value!` / save 在持久化失败结果的步骤证据前抛错，上游已有完成步骤被丢弃 | 先记录安全回执元数据再传播失败；部分成功、save 失败、checkpoint 存储失败都保持 uncertain 且不重放 |
| H07 | importer、Rule 与查询调用方直接使用旧字段；类名还参与身份/缓存布局 | 一份宿主投影适配器映射规范对象到现有列；重建 gem 后从打包安装加载跑消费方契约，不能靠常量别名假装历史数据已迁移 |

运行配置效果与持久化确认保持两个独立维度。当前正向保存回执不是独立读取 startup/saved configuration 的证据；报告必须标明实际采用哪种确认方式。

## 厂商差异不能在命名统一时丢失

| 厂商 | 必须保留的关键语义 / 当前限制 |
| --- | --- |
| ASA | before/auto/after NAT 阶段、版本相关真实/映射地址、ACL 作用域和序号、源端口配对；当前无 remove_rule |
| Fortinet | VDOM、策略 ID 与顺序、VIP 与 policy-embedded SNAT、pool overload/interface/ARP 属性；central NAT 未实现 |
| H3C | ACL/object-policy 绑定、对象重名和大小写规则、规则移动顺序、接口 NAT 开关；remove 仅 object-policy |
| Hillstone | 聚合对象依赖、固件内置服务、一次/周/月/混合时间窗；未知应用/profile 条件不能当纯网络规则 |
| Huawei | NatServer / nat-policy 身份空间、类型优先级与原生顺序、Easy-IP 路由、源/目的同规则翻译、版本门禁；保留已有 NatPlan WIP |
| Neteye | protocol object 与 service group 可引用类型差异、static NAT 绑定规则、原生 ID 与 priority；时间生成与 remove 当前未支持 |
| Netscreen | 区域地址簿与 Global fallback、MIP/VIP/DIP、policy-embedded NAT、虚拟路由器、reject/tunnel 原生动作 |
| Palo Alto | 原始地址与 NAT 后安全区域、rule type、默认规则、vsys/shared 作用域；当前主要支持本地 vsys1，Panorama pre/post 等明确 partial |
| SRX | 区域对规则身份、NAT rule-set 与分阶段行为、地址簿作用域；原生 application 多为 L4 Service，不能直接改名 App-ID |
| Topsec | 原始/翻译源目的与服务、多区域 NAT、VLAN 未知、原生 ID；生成命令与保存配置语法不同，当前无 remove_rule |

统一领域命名以 PAN-OS 为基准：AddressObject、AddressGroup、ServiceObject、ServiceGroup、SecurityRule、NatRule、OriginalPacket、SourceTranslation、DestinationTranslation、Rulebase。属性使用 source/destination zones、addresses、applications、services 等明确含义；RuleIdentity、RulePosition 和 NativeBinding 分开。PAN-OS 的规则顺序和原始包语义见 [NAT policy rules](https://docs.paloaltonetworks.com/ngfw/networking/nat/nat-policy-rules)。统一术语不意味着其他厂商强行采用 PAN-OS 的执行阶段。

仍需定向核实的结构风险包括：PAN parser 的 destination-interface 与 SNAT interface 共用字段、多行 non-recurring 时间窗覆盖、`option` 被识别但没有完整解释；Neteye 部分 service_refs 源端口路径；缺少保存配置 fixture 的厂商。它们尚无本审计证明的合法固件反例，应保持“待验证”，不要混入已复现缺陷数量。

## 用户业务链验收矩阵

| 用户流程 | 核心对象 / 责任边界 | 最小验收证据 | 关联项 |
| --- | --- | --- | --- |
| 设备登录 | DeviceSession 借用 net-connector；宿主注入凭据和设备身份 | 正常/失败/异常均关闭；同会话采集；实际设备验收另列 | G09、H02 |
| 配置抓取 | Capture 保留源、辅助数据、时间与完整性 | 截断/辅助失败不伪装完整，备份先于解析失败；持久证据可恢复 | H01 |
| 解析与结构化入库 | Parser 构建同一规范对象，Configuration 发布；Document 与宿主 Repository 适配 | 10 厂商契约；完整 token 消费；JSONB/加密原文新进程往返；稳定身份、引用、上下文和诊断 | D04–D07、D10–D14、G05–G07、H07 |
| 策略查询 | Packet / TrafficSet、Rulebase、路由与 NAT 阶段 | 首条命中、组合覆盖、deny hole、协议/源端口、跨区域、unknown、完整 NAT 正反向证据 | D01–D03、D09、G01–G02 |
| 策略设计 | Request 与 typed ChangeSet；对象复用与冲突校验 | 保持显式意图；候选配置预期变化成立且范围外不放宽；批次最终状态全部满足 | D08、G01、G03 |
| 策略下发 | Workflow / Attempt / Journal / Verifier；宿主认领、审批和短事务 | stale baseline/同文本异上下文拒绝；部分完成/保存失败/worker 中断/回执存储失败可恢复；NAT 与安全效果独立验收 | G09、H02–H06 |
| 策略收敛 | Rulebase 差异与候选操作 | 多条覆盖、合并对角反例、交错 deny、时间与引用依赖；前后行为等价见证 | G01、G03 |
| 策略翻译 | 单一规范模型、厂商能力和 renderer | 当前 100 对简单规则基线保留；更复杂条件、NAT、非空目标按能力扩展；不支持必须明确拒绝 | G03–G07 |
| 无效策略回收 | Reclaim 候选、UsageObservation、批次依赖与等价校验 | 禁用/过期/冗余/无使用证据分类；计数重置/窗口缺失不得判 unused；删除后引用及行为保持 | G01、G08 |

## 完整源码清单

下列分组互斥，共 158 文件。完整阅读归属来自四份本轮审计，汇总补读 version；生命周期审计还完整阅读了被其他组计入的 planner、plan、snapshot 和 Hillstone collector，未重复计数。机器清单 `tmp/modernization/inventory.json` 另含逐文件 SHA-256、行数和全部审阅归属；该临时目录不进入 gem。

### 核心元素、配置与区间：36 文件 / 4,064 行

```text
lib/algosec/address_expressions.rb (39)
lib/algosec/config/cache.rb (100)
lib/algosec/config/cache_entry.rb (55)
lib/algosec/config/comparison.rb (96)
lib/algosec/config/parser.rb (523)
lib/algosec/config/reader.rb (145)
lib/algosec/config/result.rb (97)
lib/algosec/config/rule_projection.rb (32)
lib/algosec/config/syntax.rb (111)
lib/algosec/config.rb (12)
lib/algosec/elements/address.rb (112)
lib/algosec/elements/address_expansion.rb (137)
lib/algosec/elements/address_group.rb (24)
lib/algosec/elements/base.rb (178)
lib/algosec/elements/catalog.rb (80)
lib/algosec/elements/definition.rb (186)
lib/algosec/elements/dynamic_nat.rb (102)
lib/algosec/elements/group.rb (132)
lib/algosec/elements/interface.rb (135)
lib/algosec/elements/nat_pool.rb (45)
lib/algosec/elements/reference_resolver.rb (103)
lib/algosec/elements/route.rb (131)
lib/algosec/elements/routing_table.rb (131)
lib/algosec/elements/rule.rb (190)
lib/algosec/elements/rule_binding.rb (28)
lib/algosec/elements/schedule.rb (154)
lib/algosec/elements/service.rb (125)
lib/algosec/elements/service_expansion.rb (53)
lib/algosec/elements/service_group.rb (36)
lib/algosec/elements/static_nat.rb (162)
lib/algosec/elements/zone.rb (75)
lib/algosec/elements.rb (12)
lib/algosec/ipaddr.rb (205)
lib/algosec/ipv6.rb (58)
lib/algosec/service_expressions.rb (77)
lib/algosec/set.rb (183)
```

### 厂商实现与登记声明：82 文件 / 9,605 行

```text
lib/algosec/declarations.rb (36)
lib/algosec/vendors/asa/connector.rb (70)
lib/algosec/vendors/asa/elements.rb (48)
lib/algosec/vendors/asa/generator.rb (176)
lib/algosec/vendors/asa/nat_acl.rb (58)
lib/algosec/vendors/asa/parser.rb (453)
lib/algosec/vendors/asa/policy.rb (116)
lib/algosec/vendors/asa.rb (5)
lib/algosec/vendors/cisco_ios/connector.rb (14)
lib/algosec/vendors/cisco_ios.rb (6)
lib/algosec/vendors/cisco_n9k/connector.rb (14)
lib/algosec/vendors/cisco_n9k.rb (6)
lib/algosec/vendors/fortinet/connector.rb (15)
lib/algosec/vendors/fortinet/elements.rb (28)
lib/algosec/vendors/fortinet/generator.rb (201)
lib/algosec/vendors/fortinet/parser.rb (429)
lib/algosec/vendors/fortinet/policy.rb (45)
lib/algosec/vendors/fortinet.rb (5)
lib/algosec/vendors/generic/elements.rb (13)
lib/algosec/vendors/generic.rb (5)
lib/algosec/vendors/h3c/connector.rb (15)
lib/algosec/vendors/h3c/elements.rb (24)
lib/algosec/vendors/h3c/generator.rb (239)
lib/algosec/vendors/h3c/parser.rb (893)
lib/algosec/vendors/h3c/policy.rb (109)
lib/algosec/vendors/h3c.rb (5)
lib/algosec/vendors/hillstone/collector.rb (23)
lib/algosec/vendors/hillstone/connector.rb (26)
lib/algosec/vendors/hillstone/elements.rb (35)
lib/algosec/vendors/hillstone/generator.rb (111)
lib/algosec/vendors/hillstone/parser.rb (731)
lib/algosec/vendors/hillstone/policy.rb (29)
lib/algosec/vendors/hillstone/predefined_services.rb (76)
lib/algosec/vendors/hillstone.rb (5)
lib/algosec/vendors/huawei/connector.rb (14)
lib/algosec/vendors/huawei/elements.rb (24)
lib/algosec/vendors/huawei/generator.rb (228)
lib/algosec/vendors/huawei/nat_action.rb (45)
lib/algosec/vendors/huawei/nat_plan.rb (216)
lib/algosec/vendors/huawei/nat_server.rb (129)
lib/algosec/vendors/huawei/network_syntax.rb (120)
lib/algosec/vendors/huawei/parser.rb (746)
lib/algosec/vendors/huawei/policy.rb (114)
lib/algosec/vendors/huawei/service_terms.rb (66)
lib/algosec/vendors/huawei.rb (5)
lib/algosec/vendors/neteye/connector.rb (52)
lib/algosec/vendors/neteye/elements.rb (25)
lib/algosec/vendors/neteye/generator.rb (115)
lib/algosec/vendors/neteye/parser.rb (373)
lib/algosec/vendors/neteye/policy.rb (19)
lib/algosec/vendors/neteye.rb (5)
lib/algosec/vendors/netscreen/connector.rb (58)
lib/algosec/vendors/netscreen/elements.rb (56)
lib/algosec/vendors/netscreen/generator.rb (167)
lib/algosec/vendors/netscreen/parser.rb (529)
lib/algosec/vendors/netscreen/policy.rb (53)
lib/algosec/vendors/netscreen.rb (5)
lib/algosec/vendors/palo_alto/address_translator.rb (23)
lib/algosec/vendors/palo_alto/connector.rb (14)
lib/algosec/vendors/palo_alto/elements.rb (39)
lib/algosec/vendors/palo_alto/generator.rb (276)
lib/algosec/vendors/palo_alto/parser.rb (583)
lib/algosec/vendors/palo_alto/policy.rb (36)
lib/algosec/vendors/palo_alto/set_configuration.rb (47)
lib/algosec/vendors/palo_alto.rb (6)
lib/algosec/vendors/radware/connector.rb (14)
lib/algosec/vendors/radware.rb (6)
lib/algosec/vendors/registry.rb (111)
lib/algosec/vendors/srx/connector.rb (49)
lib/algosec/vendors/srx/elements.rb (66)
lib/algosec/vendors/srx/generator.rb (166)
lib/algosec/vendors/srx/parser.rb (324)
lib/algosec/vendors/srx/policy.rb (25)
lib/algosec/vendors/srx.rb (5)
lib/algosec/vendors/topsec/connector.rb (14)
lib/algosec/vendors/topsec/elements.rb (21)
lib/algosec/vendors/topsec/fields.rb (20)
lib/algosec/vendors/topsec/generator.rb (147)
lib/algosec/vendors/topsec/parser.rb (291)
lib/algosec/vendors/topsec/policy.rb (48)
lib/algosec/vendors/topsec.rb (5)
lib/algosec/vendors.rb (41)
```

### 策略领域与算法：29 文件 / 3,976 行

```text
lib/algosec/policy/address_translator.rb (175)
lib/algosec/policy/analysis.rb (102)
lib/algosec/policy/behavior.rb (150)
lib/algosec/policy/command_syntax.rb (95)
lib/algosec/policy/definition.rb (60)
lib/algosec/policy/domain_query.rb (79)
lib/algosec/policy/generation_state.rb (95)
lib/algosec/policy/generator.rb (382)
lib/algosec/policy/independent_results.rb (45)
lib/algosec/policy/migration.rb (151)
lib/algosec/policy/nat_resolver.rb (638)
lib/algosec/policy/network_locator.rb (173)
lib/algosec/policy/plan.rb (70)
lib/algosec/policy/planner.rb (86)
lib/algosec/policy/ranges.rb (86)
lib/algosec/policy/reclaimer.rb (97)
lib/algosec/policy/request.rb (135)
lib/algosec/policy/result.rb (143)
lib/algosec/policy/rule_comparison.rb (73)
lib/algosec/policy/rule_matcher.rb (212)
lib/algosec/policy/rule_order.rb (35)
lib/algosec/policy/rule_view.rb (160)
lib/algosec/policy/script.rb (23)
lib/algosec/policy/searcher.rb (330)
lib/algosec/policy/snapshot.rb (144)
lib/algosec/policy/traffic_matcher.rb (74)
lib/algosec/policy/traffic_ranges.rb (65)
lib/algosec/policy/value.rb (73)
lib/algosec/policy.rb (25)
```

### 根入口、采集与外围生命周期：10 文件 / 1,135 行

```text
lib/algosec/builtin_services.rb (134)
lib/algosec/collector.rb (8)
lib/algosec/connector.rb (52)
lib/algosec/device_session.rb (109)
lib/algosec/dns_resolver.rb (97)
lib/algosec/domain_name.rb (31)
lib/algosec/offline_check/output.rb (85)
lib/algosec/offline_check/readback.rb (234)
lib/algosec/offline_check.rb (366)
lib/algosec.rb (19)
```

### 版本入口：1 文件 / 5 行

```text
lib/algosec/version.rb (5)
```

Huawei `vendors/huawei/nat_plan.rb` 在审计开始及汇总时的 SHA-256 均为 `f8d499eb226acb8e4b75bd1916acd6ea1b1a4bd50e7f9505138353f039f7b809`。这用于核对在制改动保留，不是其设备验收证据。
