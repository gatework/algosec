# frozen_string_literal: true

module Algosec
  # 配置和辅助数据的采集顺序；连接和会话生命周期由借用的会话负责。
  class Collector
    def collect(session) = session.read_config
  end
end
