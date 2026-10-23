# frozen_string_literal: true

# CiscoIos 的组件能力入口；业务差异保留在各组件中。
Algosec::Vendors.register :cisco_ios, namespace: "CiscoIos",
                          components: %i[connector], directory: File.expand_path("cisco_ios", __dir__),
                          aliases: %w[cisco ios iosxe ciscoiosxe]
