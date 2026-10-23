# frozen_string_literal: true

class Algosec::Vendors::Example::Generator < Algosec::Policy::Generator
  command_fields sources: "source", destinations: "destination", services: "service"
  command_frame before: [ "configure" ], after: [ "commit" ]

  # 示例只声明新建策略能力，不模拟尚未实现的 NAT 或修改命令。
  def create_rule
    members = Algosec::Policy::Result::DIMENSIONS.to_h { |dimension| [ dimension, result.public_send(dimension).keys ] }
    command_block("rule allow", close: "end") { emit(*member_commands(members)) }
  end
end
