# frozen_string_literal: true

require "fileutils"
require "json"
require "tmpdir"
require_relative "error"

module Algosec
  module OfflineCheck
    # 一次离线验证独占输出目录；只有整批完成后才发布报告及其引用文件。
    class Output
      def initialize(directory, inputs:)
        @directory, @inputs = File.expand_path(directory), inputs
      end

      # 锁随文件句柄释放，失败只清理本次临时目录，不改写历史运行内容。
      def open
        FileUtils.mkdir_p(@directory, mode: 0o700)
        @directory = File.realpath(@directory)
        @latest = File.join(@directory, "report.json")
        lock_path = File.join(@directory, ".offline-check.lock")
        validate_paths!(@latest, lock_path)
        File.open(lock_path, File::RDWR | File::CREAT | File::NOFOLLOW, 0o600) do |lock|
          stage = nil
          raise Error, "离线验证锁路径不是普通文件" unless lock.stat.file?
          raise Error, "离线验证输出目录已被占用" unless lock.flock(File::LOCK_EX | File::LOCK_NB)
          retire_report
          @stage = stage = Dir.mktmpdir(".run-", @directory)
          @run = File.join(@directory, File.basename(@stage).delete_prefix("."))
          yield self
        ensure
          FileUtils.remove_entry(stage) if stage && File.exist?(stage)
        end
      end

      def cache_path = File.join(@stage, "cache")

      # 文件留在私有临时目录，报告引用的是发布后不会被下一次覆盖的路径。
      def write(name, content)
        File.open(File.join(@stage, name), File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
          file.write(content)
          file.flush
          file.fsync
        end
        File.join(@run, name)
      end

      # 先发布完整目录，再以报告链接作为本次运行的完成标志。
      def publish(summary)
        report_path = write("report.json", JSON.pretty_generate(summary) + "\n")
        raise Error, "离线验证运行目录已存在" if File.exist?(@run) || File.symlink?(@run)
        File.rename(@stage, @run)
        temporary = File.join(@run, ".report-link")
        File.symlink(File.join(File.basename(@run), "report.json"), temporary)
        File.rename(temporary, @latest)
        report_path
      ensure
        File.unlink(temporary) if temporary && File.symlink?(temporary)
      end

      private

      # 输入可以位于输出目录，但不能占用会被替换的报告或锁路径。
      def validate_paths!(*paths)
        @inputs.each do |input|
          if paths.any? { |path| File.expand_path(input) == path || File.identical?(input, path) }
            raise Error, "验证输入不能与报告或锁文件使用同一路径"
          end
        end
      end

      # 新尝试不沿用旧成功标志；旧格式报告移入历史目录，已有运行文件保留。
      def retire_report
        if File.symlink?(@latest)
          File.unlink(@latest)
        elsif File.exist?(@latest)
          raise Error, "离线验证报告路径不是普通文件" unless File.file?(@latest)
          archive = Dir.mktmpdir("previous-", @directory)
          File.rename(@latest, File.join(archive, "report.json"))
        end
      end
    end

    private_constant :Output
  end
end
