# frozen_string_literal: true

require "rake/testtask"

Rake::TestTask.new do |test|
  test.libs << "lib"
  test.pattern = "test/**/*_test.rb"
end

desc "Build and verify an isolated gem installation"
task :package do
  ruby "script/package.rb"
end

task default: :test
