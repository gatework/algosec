# frozen_string_literal: true

require "bundler/gem_tasks"
require "rake/testtask"
require "rubocop/rake_task"
require "digest"

Rake::TestTask.new(:test) do |task|
  task.libs << "test"
  task.pattern = "test/**/*_test.rb"
  task.ruby_opts = [ "-r./test/test_helper" ]
  task.warning = false
end
RuboCop::RakeTask.new(:lint)

desc "Run synthetic examples without devices or databases"
task :examples do
  Dir["examples/**/*.rb"].sort.each { |path| ruby "-Ilib", path }
end

task default: [ :test, :lint, :examples ]

# 校验值对应本次构建的确切字节，应用缓存和发布步骤复用同一产物。
task :build do
  spec = Gem::Specification.load("algosec.gemspec")
  artifact = "pkg/#{spec.full_name}.gem"
  File.write("pkg/SHA256SUMS", "#{Digest::SHA256.file(artifact).hexdigest}  #{File.basename(artifact)}\n")
end

# 显式发布命令执行前先通过本地门禁；普通构建不会上传。
release = Rake::Task[:release]
prerequisites = release.prerequisites.dup
release.clear_prerequisites.enhance([ :default, *prerequisites ])
