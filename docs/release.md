# 发布步骤

模块名为 `algosec`，本地源码目录名为 `algosec-rb`，正式仓库为 https://github.com/gatework/algosec 。0.1.0 是初始骨架；0.2.0 是未发布的提取检查点；0.3.0 发布独立防火墙领域。历史本地验收记录不能替代本次 CI 和包校验。

1. 更新版本、CHANGELOG 与兼容性说明；使用 Ruby 4.0.7 或更新版本。
2. 运行 `bundle exec rake`、`bundle exec rake build`、`ruby script/verify_package.rb pkg/algosec-VERSION.gem` 和 `ruby script/release.rb --check`。检查源码、历史与包中的敏感信息。
3. 提交并推送正式仓库，等待 Linux/macOS CI 全部通过；保留成功 CI 的 gem 和 SHA256SUMS，禁止用重新构建的不同字节替代。
4. 为同一提交创建 vVERSION 标签与 GitHub Release。release.yml 验证版本、CHANGELOG 和完整 CI 后，通过 `release` 环境的 RubyGems Trusted Publisher 发布其 CI 产物。
5. 回读 main/tag、GitHub 附件、RubyGems `yanked=false` 与下载 SHA256；安装验证和最终工作区状态全部通过才视为交付完成。遇到认证或索引延迟，保留同一产物，先核对远程状态再重试失败任务。

`ALGOSEC_GEM_CACHE` 可为隔离安装提供已备齐的依赖缓存。宿主升级仍须完成独立迁移、锁文件和实际验收，发布本 gem 不自动部署宿主。

## 原应用的过渡接入

原应用已有 `backend/vendor/cache/` 模式。将通过门禁的 `algosec-VERSION.gem` 放入该目录，首次接入运行 `bundle install --local --no-cache`，升级时运行 `bundle update algosec net-connector --local`，由 Gemfile.lock 固定版本与 SHA256。这样 Docker 与部署无需访问相邻源码。

发布后仍消费同一个 gem 名称。开发时可临时用 `path:` 联调，但不把个人机器路径带进部署锁文件。依赖模块在各自工程维护，禁止通过修改缓存中的解包源码修复模块。

## 0.3.0 的语义升级

2026-10-23 后续查询审查将源码升级为 `firewall-domain-v3`、`algosec-config-ruby-v79` 和 `algosec-policy-ruby-v23`。ICMP 任意类型索引现包含类型 0，避免策略路由或 NAT 跳过前置匹配；请求入口不再丢弃 `any/443` 等限制。旧对象缓存中的服务和 NAT 索引必须重建，v2 配置文档和审批拒绝直接恢复。

同日生成算法审查进一步升级为 `firewall-domain-v4` 和 `algosec-policy-ruby-v24`。生成名称现避开同一原生名称空间中的对象组和内建对象，Fortinet VIP 分配检查重叠地址及端口转换。v3 审批可能保存旧生成脚本，不能通过重新证明候选图直接执行，必须重新生成并审批。统一语义版本也使 v3 配置文档拒绝直接恢复；文档 schema 不变。领域类和内部类按职责重命名、移动后，Ruby 对象缓存升级为 `algosec-config-ruby-v80`；旧缓存必须从配置原文重建。

Elements 逐模块审查进一步将语义版本升为 `firewall-domain-v5`、配置缓存升为 `algosec-config-ruby-v81`。地址取反移入通用 `AddressGroup::Negated`，修复普通地址组引用、嵌套取反及规则报告绕过取反的问题；文档 schema 保持不变。配置替换或 DNS 刷新失败会保留原有状态与错误存在性证据，Route 在构造时校验地址组／服务组角色。旧语义的文档与审批需要重新生成，旧 Ruby 缓存从原文重建。

目的 NAT 端口关系审查在保留以上改动的基础上升为 `firewall-domain-v6`、`algosec-policy-ruby-v25` 和 `algosec-config-ruby-v82`。查询和效果证明现在核对逐端口对应关系，分段保留请求偏移，反向发现保留未知别名；Fortinet 的端口模式进入配置声明与读回比较，单个映射起点按一对一范围扩展，未建模的负载均衡配置明确保留不完整。v5 及更旧的配置文档和审批不能直接恢复，文档 schema 版本保持不变。

Policy 模块审查将源码语义升为 `firewall-domain-v7`、策略修订 v26：候选规则修改保留地址组补集和服务组属性，变更意图在封存输入前完成校验。内部类型按所属目录拆分，NAT 转换器统一使用 `.build` 选择厂商子类，不保留旧类名与转发入口。配置缓存仍为 v82；v6 及更旧审批需重新设计。

部署预检进一步升为 `firewall-domain-v8`、`algosec-policy-ruby-v27`。`Snapshot#baseline` 统一包含源、目标各自的时区，计划、效果证明和审批恢复共同使用；时区漂移在写入前拒绝。宿主构造数据库基线上下文时必须提供 `time_zone`，不能沿用缺少该字段的旧审批或改版本号补造证据。本轮没有增加对象存储状态，缓存仍为 v82，文档 schema 版本不变。宿主适配、安装包同步与宿主回归需另行完成；完整 DNS 观察图预检仍由宿主 verifier 承担。

升级时从原文重新采集或显式导入配置，并从原始需求重新校验、规划和审批。旧的规范化请求可能已经丢失端口或类型限制，不能仅用旧计划中的 `any` 重新证明。历史记录及原 0.3.0 包验收仍保留；宿主同步新包、锁文件与验收另行执行，源码测试通过不表示当前宿主已升级。

## 0.3.0 的宿主升级

本版本提高 `net-connector` 下限到 0.16.0，配置对象缓存版本为 `algosec-config-ruby-v78`，策略修订为 `algosec-policy-ruby-v22`，领域语义版本为 `firewall-domain-v2`。应用与后台任务应使用同一构建包；旧对象缓存不可继续作为新版本证据。

宿主新增五项迁移：配置文档及采集证据、自动化认领、采集认领历史、审批输入文档，以及收敛操作约束。正式升级须在目标环境执行应用迁移；本工程的本地验收只在隔离 PostgreSQL 执行。回滚前若已有收敛记录或新审批数据，应先制定数据保留方案，不能把空测试库的可逆迁移当成生产无损回滚保证。

`Config::Document` 使用 schema 1；`PlanDocument` 使用 schema 2，包含明确的目标元数据和 NAT 校验输入。未知版本拒绝恢复。`firewall-domain-v1` 文档可能包含旧解析器丢失的时间窗、源端口或接口限定，不能直接恢复成当前语义；保留原历史记录，通过重新采集或显式导入建立新配置，再重新规划和审批。不能只清缓存、改文档版本字段或回填历史成功标记来获得执行权限。没有结构文档的旧配置记录仍保留原文解析入口；新导入记录写入加密文档。

任务超时或租约失效不证明旧连接已经关闭。未确认的执行继续保留设备写入预留，原会话关闭证据及新的只读核验完成后才可终结；不能通过重试写命令来消除未知状态。
