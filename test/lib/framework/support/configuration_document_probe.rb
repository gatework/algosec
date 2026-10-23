# frozen_string_literal: true

# 独立进程直接查询恢复后的领域对象，不使用文档编码器生成期望值。
module ConfigurationDocumentProbe
  def self.call(result, at:)
    ip = Algosec::IPAddr.to_i("192.0.2.1")
    {
      "complete" => result.complete?,
      "addresses" => result.address_objects.map do |address|
        projection = address.address_projection(at: at)
        [ address.identity_fields, projection.fetch(:set).include?(ip), projection.fetch(:resolution) ]
      end,
      "rules" => result.rules.map do |rule|
        active = begin
          rule.active?(at: at)
        rescue Algosec::Elements::Group::UnresolvedReference
          "unresolved"
        end
        [ rule.locator, rule.action, rule.status_known?, rule.disabled?, active,
          rule.services.resolved? ? rule.services.matches?(protocol: "tcp", source_port: "1234", destination_port: "443") : "unresolved" ]
      end,
      "nat" => result.elements(Algosec::Elements::NatRule).map do |nat|
        [ nat.identity_fields, nat.disabled?, nat.stage, nat.source_translation.mode, nat.destination_translation.mode,
          nat.source_translation.targets&.include?(ip), nat.destination_translation.targets&.include?(ip) ]
      end,
      "networks" => result.elements.select { |object| object.is_a?(Algosec::Elements::Zone) || object.is_a?(Algosec::Elements::Interface) }
        .map { |object| [ object.identity_fields, object.set.include?(ip) ] }
    }
  end
end
