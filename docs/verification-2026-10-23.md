# 0.3.0 本地交付验收

日期：2026-10-23。工程：`algosec-rb`；模块名：`algosec`。原应用通过普通 gem 依赖和缓存包接入，运行时不引用相邻源码目录。

## 实现与设计

依据[领域设计](superpowers/specs/2026-10-22-firewall-domain-design.md)和[17 项任务计划](superpowers/plans/2026-10-22-firewall-domain.md)，完成统一对象、采集解析、结构文档、查询、策略设计、部署协调、收敛、迁移和回收的实现与宿主接入。

以 Palo Alto / PAN-OS 常用术语命名领域对象，厂商适配器保留各自语法、原生身份、执行顺序和作用域。对象拥有身份、条件、集合运算或生命周期；跨业务复用 `Evaluation`、`ChangeSet`、`Plan` 及效果证明。使用 Ruby 组合、委托、不可变值、块式资源管理，以及 ActiveSupport、ctx_parser、ctx_driver、net-connector 等成熟依赖。数据库、任务与审批持久化留在宿主。

最后审查修复了离线联合覆盖、精确缺口与命令切片对应关系，以及内嵌 NAT 查询和效果证明跳过普通前序安全规则的问题。NAT 选择复用完整 `Evaluation`，并保留 `RuleOrder` / `DeclarationComparison` 的顺序依赖证明。选择正确和依赖未变分别验证。

厂商补充修复覆盖 PAN-OS 多个非周期窗口、ASA/H3C 多周期声明、Fortinet 跨午夜及 24 小时周期、Neteye 源端口、SRX NAT 接口上下文。可表达的条件完整保留；暂不能准确表达的条件保留原始证据和 unknown/partial。所有修复都有失败复现与回归，结构文档恢复后仍保留相同语义。

| 业务场景 | 当前共同实现与宿主衔接 |
| --- | --- |
| 设备登录 | `Connector` / `DeviceSession` 管理所有权、会话释放与执行收据 |
| 配置抓取与解析 | `Collector` / `Config::Parser` 与厂商适配器保留来源、诊断和原生身份 |
| 结构化入库 | `Config::Document`；宿主加密保存文档并原子发布业务投影 |
| 策略查询 | `Packet` / `TrafficSet` / `Evaluation` / `Searcher` / `NatResolver` 共用精确范围与首条匹配 |
| 策略设计 | `Planner` / `ChangeSet` / `Plan` 绑定基线、目标及时间/NAT 效果证明 |
| 策略下发 | `Deployment` 与宿主 journal/claim 协作，分开执行、关闭、保存和独立读回证据 |
| 策略收敛 | `Convergence` 保留流量配对、动作和附加条件，验证整批行为 |
| 策略翻译 | `Migration` 验证源/目标作用域、动作、日志与范围外行为 |
| 无效策略回收 | `UsageObservation` / `Reclaimer` 保留统计证据、审批和原生删除读回 |

## 最终包

- 文件：`pkg/algosec-0.3.0.gem`，211 个白名单文件。
- SHA256：`64a88e9e5339101fbc32c4d6d037839d6d06b60d452cd31a81c40c8b73020c7a`。
- 构建包、宿主 `vendor/cache` 和 `Gemfile.lock` 校验值一致；Bundler 校验保持开启。
- 实际宿主加载 `/opt/homebrew/lib/ruby/gems/4.0.0/gems/algosec-0.3.0`，net-connector 为 0.16.1；独立源码全量检查使用 0.16.0。隔离安装按当前本地缓存解析为 0.17.0，该环境验证独立入口与示例，未据此声称所有版本均完成设备验收。
- 领域语义 `firewall-domain-v2`，配置缓存 v78，策略修订 v22；Config 文档 schema 1，Plan 文档 schema 2。旧语义文档和审批明确拒绝恢复，需重新采集或显式导入及重新审批。

## 验证结果

| 范围 | 结果 |
| --- | --- |
| Gem 全量 `bundle exec rake` | 1,018 tests / 29,871 assertions，零失败、错误、跳过 |
| Gem lint / 离线示例 | 320 个 Ruby 文件通过，两个示例通过 |
| 发布包 | 源内容及权限核对、隔离 GEM_HOME 安装、12 个独立入口、两个安装后示例通过 |
| 本地发布检查 | `script/release.rb --check` 通过；未执行上传分支 |
| 原应用完整 Rails 测试 | 实际安装包运行，906 tests / 27,895 assertions，零失败、错误、跳过 |
| 原应用加载与跨进程恢复 | Zeitwerk 通过；独立进程从数据库恢复文档、查询和规划通过 |
| 安装包新增回归 | 宿主实际安装包执行离线、厂商和内嵌 NAT 回归：39 tests / 409 assertions，通过 |
| 厂商修复专项 | 169 tests / 1,478 assertions，通过；另核对十家时间计划语义 |
| 内嵌 NAT 独立复核 | 85 tests / 350 assertions，通过，原错误查询与效果证明已关闭 |
| 五项数据库迁移 | 本任务前序在专用空库升级、回退五项、再升级；前后 schema SHA256 相同，本轮未改迁移 |

本轮最终日志位于 `tmp/modernization/continuation-20261023/`：`gem-gate.log`、`package.log`、`release-check.log`、`install.log`、`host-results.json` 及各 `host-*.log`。333 个源码、测试与构建文件在检查前后摘要一致；宿主仅同步最终包和对应锁文件校验值。厂商、策略、生命周期与离线专项审查分别记录于该目录的 `vendor-audit.md`、`policy-audit.md`、`lifecycle-audit.md` 和 `offline-audit.md`。

五迁移往返证据仍为 `tmp/modernization/migration-roundtrip/evidence.json`。宿主 Ruby 源码本轮没有变化；前序 93 个修改 Ruby 文件的 lint 结果、各任务基线与独立审查保留在原日志和 `.superpowers/sdd/2026-10-22-firewall-domain/`。所有修复前副本、失败回归和中间包检查点均保留，未用后续成功覆盖失败证据。

## 验收边界

网络会话使用模拟传输；数据库测试使用专用 PostgreSQL `127.0.0.1:61628`，验收后已停止该实例并保留数据和日志。没有操作真实防火墙或生产数据库，没有提交、推送或发布，也没有将本地验证表述为远程 CI 结果。

十家厂商能力按[能力矩阵](capabilities.md)逐项声明。普通迁移矩阵检查 100 个组合：80 个在测试条件下通过，目标 ASA 出口范围和目标 Hillstone 未指定日志状态的各 10 个组合明确阻断。内嵌 NAT 前缀中的变更目前保守要求重新证明，不能把动作相同或当前未生效当作转换等价。上线前须按[升级说明](release.md)处理五项迁移、缓存与旧审批；空库迁移往返不证明生产数据可无损回退。
