# frozen_string_literal: true

# Srx 的组件能力入口；业务差异保留在各组件中。
Algosec::Vendors.register :srx, namespace: "Srx",
                          components: %i[elements parser policy generator connector], directory: File.expand_path("srx", __dir__)
