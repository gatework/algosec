# frozen_string_literal: true

# Asa 的组件能力入口；业务差异保留在各组件中。
Algosec::Vendors.register :asa, namespace: "Asa",
                          components: %i[elements parser policy generator connector], directory: File.expand_path("asa", __dir__)
