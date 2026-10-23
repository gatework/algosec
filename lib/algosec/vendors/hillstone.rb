# frozen_string_literal: true

# Hillstone 的组件能力入口；业务差异保留在各组件中。
Algosec::Vendors.register :hillstone, namespace: "Hillstone",
                          components: %i[elements parser policy generator connector collector], directory: File.expand_path("hillstone", __dir__)
