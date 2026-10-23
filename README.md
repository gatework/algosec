# algosec

[中文](README-zh.md)

A Ruby library for firewall configuration parsing, policy analysis and planning, multi-vendor command generation, and device sessions. Extracted from the Algosec Rails application; the gem runs without starting Rails or a database service.

## Installation

Requires **Ruby 4.0.7 or newer**. Version 0.3.0 provides the standalone firewall domain. Runtime dependencies include ActiveSupport 8.1 and net-connector 0.16 or newer within the declared major-version bounds.

```sh
bundle install
bundle exec rake
bundle exec rake build
gem install --local pkg/algosec-0.3.0.gem
```

Applications can declare `gem "algosec", "~> 0.3.0"`. Use an explicit development `path:` only for local integration. Application lockfiles should record the resolved dependencies.

```ruby
require "algosec"

result = Algosec::Config::Parser.perform(
  "set security address-book global address web 192.0.2.10/32\n",
  vendor: :srx, device_id: 1
)
puts result.complete?
snapshot = Algosec::Policy::Snapshot.from_config(result)
```

The self-checking [offline example](examples/offline.rb) parses a synthetic policy and verifies a cache round trip. Run `bundle exec ruby examples/offline.rb`.

The [policy lifecycle example](examples/policy_lifecycle.rb) exercises configuration JSON restoration, exact packet evaluation, redundant-rule reclamation, approved-input reconstruction and independent native readback. It also rejects readback where the selected rule was never removed. Run `bundle exec ruby examples/policy_lifecycle.rb` without device or database access.

## Boundaries

- `Elements`, address/service expressions, `Config`, and `Policy` represent firewall facts and policy decisions.
- `Vendors` owns platform declarations and semantics. Discover actual capabilities with `Algosec::Vendors.names(:parser)`, `names(:policy)`, and `names(:connector)`.
- `Connector` and `DeviceSession` use `net-connector` and `ctx_driver`; configuration source tracking uses `ctx_parser`.
- `Deployment` coordinates plans, sessions, execution receipts, persistence confirmation and independent readback through host-supplied adapters.
- ActiveSupport provides time zones, cache stores, and Ruby extensions; Nokogiri handles Palo Alto XML. Independence from the Rails application does not mean avoiding mature external dependencies.
- Persistence, authorization, credentials, job recovery, HTTP, and application workflows remain the host application's responsibility.

Incomplete configuration remains incomplete. `Policy::Snapshot.from_config` rejects it by default. Command generation produces reviewable text; executing it requires an explicit device-session operation. Offline tests do not validate firmware behavior.

## Cache integration

```ruby
cache = Algosec::Config::Cache.new                         # Per-instance memory cache
cache = Algosec::Config::Cache.new(directory: "/tmp/fw")  # Explicit FileStore
cache = Algosec::Config::Cache.new(store: Rails.cache)     # Host-supplied store
```

`ALGOSEC_CACHE_DIR` also selects FileStore. A store and a directory cannot be combined. The gem neither probes Rails nor writes into its installation directory. Persisted cache contains source configuration and must remain in a trusted, access-controlled location.

## Development and release

`bundle exec rake` runs the existing Minitest domain suite, RuboCop, and offline examples. Tests use synthetic or sanitized fixtures and require no application database. Rails-specific integration tests remain in the application.

`bundle exec rake build` creates `pkg/algosec-0.3.0.gem` and `pkg/SHA256SUMS`. `ruby script/verify_package.rb pkg/algosec-0.3.0.gem` checks packaged source and performs an isolated install outside the checkout. Test data, local backups, credentials, logs, and build outputs are excluded from the package.

Canonical objects use Palo Alto terminology while vendor adapters retain native execution semantics. See [architecture and integration](docs/architecture.md), [vendor capabilities and evidence boundaries](docs/capabilities.md), [release procedure](docs/release.md), and [changes](CHANGELOG.md). Source and releases are maintained at [gatework/algosec](https://github.com/gatework/algosec).

MIT, see [LICENSE](LICENSE).
