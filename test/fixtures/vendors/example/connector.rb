# frozen_string_literal: true

class Algosec::Vendors::Example::Connector < Net::Connector::Base
  profile do
    commands { running_config "show configuration" }
    prompts { login(/example#\z/); command(/example#\z/) }
  end
end
