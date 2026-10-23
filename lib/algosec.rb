# frozen_string_literal: true

require_relative "algosec/version"
require_relative "algosec/set"
require_relative "algosec/ipaddr"
require_relative "algosec/elements"
require_relative "algosec/vendors"
require_relative "algosec/config"
require_relative "algosec/policy"

module Algosec
  autoload :BuiltinServices, File.expand_path("algosec/builtin_services", __dir__)
  autoload :Connector, File.expand_path("algosec/connector", __dir__)
  autoload :Collector, File.expand_path("algosec/collector", __dir__)
  autoload :Deployment, File.expand_path("algosec/deployment", __dir__)
  autoload :DeviceSession, File.expand_path("algosec/device_session", __dir__)
  autoload :OfflineCheck, File.expand_path("algosec/offline_check", __dir__)
end
