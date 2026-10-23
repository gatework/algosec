# frozen_string_literal: true

class Algosec::Vendors::Example::Elements < Algosec::Elements::Definition
  defaults default_vrf: "default"
  identity :address, :name
end
