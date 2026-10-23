# frozen_string_literal: true

require_relative "elements/definition"
require_relative "policy/definition"
require_relative "vendors/registry"

module Algosec
  # 厂商入口清单负责加载，能力与别名由每个厂商自己声明。
  module Vendors
    class UnsupportedCapability < ArgumentError; end

    @registry = Registry.new(self)

    class << self
      # 记录声明位置，便于查找厂商能力来源。
      def register(key, **options)
        location = caller_locations(1, 1).first
        @registry.register(key, **options, source_location: [ location.path, location.lineno ])
      end

      def normalize(vendor) = @registry.normalize(vendor)

      def definition(vendor) = @registry.definition(vendor)

      def definitions = @registry.definitions

      def supports?(vendor, component) = @registry.supports?(vendor, component)

      def names(component) = @registry.names(component)

      def fetch(vendor, component) = definition(vendor).fetch(component.to_sym)

      def validate! = @registry.validate!
    end

    %w[generic asa srx netscreen fortinet h3c huawei hillstone topsec neteye
       cisco_ios cisco_n9k palo_alto radware].each do |entry|
      require_relative "vendors/#{entry}"
    end
  end
end
