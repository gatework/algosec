# frozen_string_literal: true

require "json"
require "nokogiri"

module Algosec
  module Vendors
    module PaloAlto
      # 运行配置 XML 转为与离线 set 导出一致的路径；不进入配置模式读取候选配置。
      module SetConfiguration
        module_function

        def from_xml(text)
          raise ArgumentError, "PAN-OS XML DTD is not supported" if text.match?(/<!DOCTYPE|<!ENTITY/i)
          document = Nokogiri::XML(text) { |options| options.strict.nonet }
          root = document.at_xpath("/config") || document.at_xpath("/response/result/config")
          raise ArgumentError, "PAN-OS running XML has no config root" unless root
          rows = []
          walk = lambda do |node, path|
            key = if node.name == "entry"
              node["name"] || raise(ArgumentError, "PAN-OS XML entry has no name")
            elsif node.name == "member"
              nil
            else
              node.name
            end
            path = [ *path, key ].compact
            children = node.element_children
            if children.empty?
              parts = [ *path, (node.text unless node.text.empty?) ].compact
              if parts[0] == "devices"
                parts = parts.drop(2)
              end
              rows << "set #{parts.map { |part| (part.match?(/\A[a-zA-Z0-9_.\/:-]+\z/) ? part : JSON.generate(part)) }.join(' ')}"
            else
              children.each { |child| walk.call(child, path) }
            end
          end
          root.element_children.each { |node| walk.call(node, []) }
          rows.join("\n") + "\n"
        rescue Nokogiri::XML::SyntaxError => error
          raise ArgumentError, "Invalid PAN-OS running XML: #{error.class}"
        end
      end
    end
  end
end
