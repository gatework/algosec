# frozen_string_literal: true

require "minitest/autorun"
require "algosec"

class ParserSettingsTest < Minitest::Test
  def test_fortinet_selects_vdom_from_symbol_settings
    assert_selected "tenant", settings: { vdom: "tenant" }
  end

  def test_fortinet_selects_vdom_from_string_settings
    assert_selected "tenant", settings: { "vdom" => "tenant" }
  end

  def test_fortinet_defaults_to_root
    assert_selected "root", settings: {}
  end

  def test_explicit_vdom_overrides_settings
    assert_selected "root", settings: { vdom: "tenant" }, vdom: "root"
  end

  def test_reader_vendor_dispatch_applies_settings
    reader = Algosec::Config::Reader.new(document, vendor: :fortinet)
    result = Algosec::Config::Parser.perform(reader, settings: { vdom: "tenant" })

    refute_same reader, result.reader
    assert_equal reader.content, result.reader.content
    assert_equal [ "tenant-address" ], result.elements(Algosec::Elements::AddressObject).map(&:name)
  end

  def test_settings_for_another_vendor_do_not_become_constructor_arguments
    result = Algosec::Config::Parser.perform("set security address-book global address web 192.0.2.1/32\n",
      vendor: :srx, settings: { vdom: "tenant", unrelated: true })

    assert result.complete?, result.diagnostics.inspect
    assert_equal [ "web" ], result.elements(Algosec::Elements::AddressObject).map(&:name)
  end

  def test_settings_must_be_a_hash
    [ nil, [], "tenant" ].each do |settings|
      error = assert_raises(ArgumentError) do
        Algosec::Config::Parser.perform(document, vendor: :fortinet, settings: settings)
      end
      assert_match(/settings.*hash/i, error.message)
    end
  end

  private

  def assert_selected(vdom, **options)
    result = Algosec::Config::Parser.perform(document, vendor: :fortinet, **options)

    assert result.complete?, result.diagnostics.inspect
    assert_equal [ "#{vdom}-address" ], result.elements(Algosec::Elements::AddressObject).map(&:name)
  end

  def document
    <<~CONFIG
      config vdom
        edit root
          config firewall address
            edit root-address
              set subnet 192.0.2.1 255.255.255.255
            next
          end
        next
        edit tenant
          config firewall address
            edit tenant-address
              set subnet 198.51.100.1 255.255.255.255
            next
          end
        next
      end
    CONFIG
  end
end
