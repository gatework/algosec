# frozen_string_literal: true

# Radware 的组件能力入口；业务差异保留在各组件中。
Algosec::Vendors.register :radware, namespace: "Radware",
                          components: %i[connector], directory: File.expand_path("radware", __dir__),
                          aliases: %w[alteon]
