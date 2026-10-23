# frozen_string_literal: true

# Huawei 的组件能力入口；业务差异保留在各组件中。
Algosec::Vendors.register :huawei, namespace: "Huawei",
                          components: %i[elements parser policy generator connector], directory: File.expand_path("huawei", __dir__)
