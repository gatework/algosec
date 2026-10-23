# frozen_string_literal: true

# CiscoN9k 的组件能力入口；业务差异保留在各组件中。
Algosec::Vendors.register :cisco_n9k, namespace: "CiscoN9k",
                          components: %i[connector], directory: File.expand_path("cisco_n9k", __dir__),
                          aliases: %w[n9k nexus nxos cisconxos]
