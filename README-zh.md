# algosec

[English](README.md)

从 Algosec Rails 应用抽取的独立 Ruby gem，提供防火墙配置解析、策略查询与规划、厂商命令生成和设备会话。无需启动 Rails 或数据库服务。

## 安装与验证

要求 **Ruby 4.0.7 或更新版本**。0.3.0 提供独立防火墙领域模块。运行时使用 ActiveSupport 8.1、net-connector 0.16 或更新版本，具体范围由 gemspec 声明。

```sh
bundle install
bundle exec rake
bundle exec rake build
ruby script/verify_package.rb pkg/algosec-0.3.0.gem
```

应用可声明 `gem "algosec", "~> 0.3.0"`。也可使用已验证的本地包，联调时可显式使用 `gem "algosec", path: "../../algosec-rb"`（从原应用 backend 目录计算）。部署时使用已构建包并锁定校验值，不依赖相邻源码目录。

```ruby
require "algosec"

result = Algosec::Config::Parser.perform(
  "set security address-book global address web 192.0.2.10/32\n",
  vendor: :srx, device_id: 1
)
puts result.complete?
snapshot = Algosec::Policy::Snapshot.from_config(result)
```

运行 `bundle exec ruby examples/offline.rb` 可验证合成配置解析、策略快照与缓存往返，无需设备连接。

运行 `bundle exec ruby examples/policy_lifecycle.rb` 可验证原生配置解析、JSON 文档恢复、精确报文查询、冗余规则回收、审批输入重新证明及独立读回。示例还检查规则未实际删除时不能报告回收成功。

## 职责与依赖

| 模块 | 职责 |
| --- | --- |
| Elements、IPAddr、Set、表达式 | 地址、服务、区域、路由、NAT 和规则对象 |
| Config | 来源、厂商解析、完整性、缓存和配置比较 |
| Policy | 查询、匹配、分析、规划、回收、迁移和命令生成 |
| Vendors | 厂商声明、方言、能力与差异 |
| Connector、Collector、DeviceSession | 复用 net-connector / ctx_driver 的设备会话和采集 |
| Deployment | 协调计划、会话、执行收据、保存确认和独立读回，持久化适配器由宿主注入 |
| OfflineCheck | 显式调用的离线流程与报告 |

独立模块可以依赖 ActiveSupport 等成熟外部组件，避免不必要的自行实现。缓存与时区继续使用 ActiveSupport，配置来源使用 ctx_parser，XML 使用 Nokogiri。gemspec 声明实际依赖；数据库驱动可能由 net-connector 传递引入，但离线使用不需要数据库服务。

应用负责持久化、授权、凭据来源、任务状态、HTTP 和业务编排。领域库不探测 `Rails.cache` 或 `Rails.root`。

```ruby
Algosec::Vendors.names(:parser)     # 10 个配置解析平台
Algosec::Vendors.names(:connector)  # 13 个设备连接平台
Algosec::Vendors.validate!          # 校验已注册能力

Algosec::Config::Cache.new                         # 每个实例独立的内存缓存
Algosec::Config::Cache.new(directory: "/tmp/fw")  # 显式文件缓存
Algosec::Config::Cache.new(store: Rails.cache)     # 由宿主注入缓存
```

`ALGOSEC_CACHE_DIR` 也可指定文件目录。`store:` 不能与目录同时设置。默认缓存不写 gem 安装目录；文件缓存含原始配置，只能放在受控的可信位置。

`require "algosec"` 只加载代码，不连接设备或写出报告。部分配置保留诊断，`Policy::Snapshot.from_config` 默认拒绝不完整证据。生成命令不等于执行，设备下发须由调用方显式发起。

## 工程约定

结构与交付门禁参考 ctx_parser，保留已有 Minitest 测试，避免重写断言。`bundle exec rake` 依次运行领域测试、RuboCop 和离线示例。应用模型和应用 Rake 任务的回归仍在原应用执行。

打包白名单只包含运行时 Ruby、示例、使用文档和许可证。测试、现场配置、迁移快照、日志、凭据和构建产物不进入 gem。CI 配置覆盖 Linux/macOS；本地通过不代表远程矩阵或真实设备已经验收。

领域对象以 Palo Alto 常用术语统一命名，厂商执行差异保留在适配器中。详见[架构与接入](docs/architecture.md)、[厂商能力与证据边界](docs/capabilities.md)、[发布步骤](docs/release.md)、[变更记录](CHANGELOG.md)。源码和版本维护于 [gatework/algosec](https://github.com/gatework/algosec)。

MIT 许可证，见 [LICENSE](LICENSE)。
