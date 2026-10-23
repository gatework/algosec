# frozen_string_literal: true

# Topsec 的组件能力入口；业务差异保留在各组件中。
Algosec::Vendors.register :topsec, namespace: "Topsec",
                          components: %i[elements parser policy generator connector], directory: File.expand_path("topsec", __dir__)
