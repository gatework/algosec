# frozen_string_literal: true

# Netscreen 的组件能力入口；业务差异保留在各组件中。
Algosec::Vendors.register :netscreen, namespace: "Netscreen",
                          components: %i[elements parser policy generator connector], directory: File.expand_path("netscreen", __dir__)
