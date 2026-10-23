# frozen_string_literal: true

# Generic 的组件能力入口；业务差异保留在各组件中。
Algosec::Vendors.register :generic, namespace: "Generic",
                          components: %i[elements], directory: File.expand_path("generic", __dir__)
