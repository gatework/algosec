# frozen_string_literal: true

class Algosec::Vendors::Example::Collector < Algosec::Collector
  def collect(session)
    config = session.read_config
    auxiliary = session.read("show auxiliary")
    raise Algosec::DeviceSession::ReadError, auxiliary.failure unless auxiliary.success?

    Algosec::DeviceSession::Capture.new(content: config.content + auxiliary.body, evidence: config.evidence + auxiliary.evidence)
  end
end
