# frozen_string_literal: true

require "active_support"
require_relative "vendors"
require_relative "policy/definition"
require_relative "policy/request"
require_relative "policy/result"
require_relative "policy/report"
require_relative "policy/snapshot"
require_relative "policy/rule_order"
require_relative "policy/rule_matcher"
require_relative "policy/traffic_matcher"
require_relative "policy/nat"
require_relative "policy/behavior"
require_relative "policy/searcher"
require_relative "policy/change_set"
require_relative "policy/planner"
require_relative "policy/independent_results"
require_relative "policy/analysis"
require_relative "policy/reclaimer"
require_relative "policy/convergence"
require_relative "policy/migration"

module Algosec
  module Policy
    # 策略行为变化独立使已准备的计划失效，不要求同时清空解析对象缓存。
    REVISION = "algosec-policy-ruby-v27"
  end
end
