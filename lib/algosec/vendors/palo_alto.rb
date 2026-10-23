# frozen_string_literal: true

# PaloAlto 的组件能力入口；业务差异保留在各组件中。
Algosec::Vendors.register :palo_alto, namespace: "PaloAlto",
                          components: %i[elements parser policy generator connector], directory: File.expand_path("palo_alto", __dir__),
                          aliases: %w[panos]
