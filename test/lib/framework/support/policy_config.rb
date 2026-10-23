# frozen_string_literal: true

module PolicyConfig
  # 模拟设备保存配置时的编号、顶部插入和配置模式退出，不改匹配条件。
  def saved_config(vendor, content)
    rows = content.lines.map(&:chomp)
    rows.reject! { |line| [ "configure", "configure terminal", "configure mode", "system-view", "return", "sys", "save", "save config", "commit check", "commit" ].include?(line) }
    case vendor
    when :h3c
      rows.map! { |line| line.sub(/^exit$/, "#") }
      rows.unshift("zone-pair security source inside destination outside", "object-policy apply ip objects", "#")
    when :netscreen
      objects, policies = [], []
      until rows.empty?
        line = rows.shift
        if (match = line.match(/\A(set policy id \d+) top from /))
          policy = [ line.sub(" top from ", " from ") ]
          if rows.first == match[1]
            policy << rows.shift until policy.last == "exit" || rows.empty?
          end
          policies.unshift(policy)
        else
          objects << line
        end
      end
      rows = objects + policies.flatten
    when :hillstone
      objects, policies = [], []
      until rows.empty?
        line = rows.shift
        if line == "rule top"
          policy = [ "rule id #{100 + policies.size}" ]
          policy << rows.shift until policy.last == "exit" || rows.empty?
          policies.unshift(policy)
        else
          objects << line
        end
      end
      rows = objects + policies.flatten
    when :fortinet
      id = 99
      rows.map! { |line| (line == "edit 0") ? "edit #{id += 1}" : line }
      # PolicyFactory 的目标快照已有这两个区域；保存配置必须带上引用上下文。
      rows.unshift("config system zone", " edit inside", " next", " edit outside", " next", "end")
    when :topsec
      rows.map!.with_index { |line, index| "ID #{index + 1} #{line}" }
    when :asa, :neteye
      rows.reject! { |line| %w[exit end].include?(line) }
    when :srx
      rows.reject! { |line| line == "exit" }
    when :huawei
      rows.map! { |line| line.sub(/^quit$/, "#") }
    end
    rows.join("\n") + "\n"
  end
end
