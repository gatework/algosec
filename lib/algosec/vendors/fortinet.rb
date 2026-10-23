# frozen_string_literal: true

# Fortinet 的组件能力入口；业务差异保留在各组件中。
Algosec::Vendors.register :fortinet, namespace: "Fortinet",
                          components: %i[elements parser policy generator connector], directory: File.expand_path("fortinet", __dir__)
