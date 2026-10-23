# frozen_string_literal: true

class Algosec::Vendors::Example::Parser < Algosec::Config::Parser
  VENDOR = :example
  stage :addresses
  line_rule :addresses, :host, prefix: %w[host], using: :host
  stage :emit_objects, using: :emit_objects
  field :address, "ip", to: :member, convert: :host_member

  private

  # 测试语法只有 host <name> <ip>，用来证明新增厂商无需改核心。
  def host_member(values) = [ address_leaf(values.fetch(0)) ]

  def host(line, words)
    map_field(:address, draft(:address, words.fetch(1), name: words.fetch(1)), "ip", words.drop(2), line)
  end
end
