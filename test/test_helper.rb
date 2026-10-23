# frozen_string_literal: true

require "bundler/setup"
require "minitest/autorun"
require "pathname"
require "algosec"
require "active_support/test_case"

# 测试只定位当前源码和合成 fixture，不创建 Rails 常量或数据库连接。
module TestPaths
  def self.root = Pathname.new(File.expand_path("..", __dir__))
end

Algosec::Vendors.validate!
