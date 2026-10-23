# frozen_string_literal: true

# H3c 的组件能力入口；业务差异保留在各组件中。
Algosec::Vendors.register :h3c, namespace: "H3c",
                          components: %i[elements parser policy generator connector], directory: File.expand_path("h3c", __dir__)
