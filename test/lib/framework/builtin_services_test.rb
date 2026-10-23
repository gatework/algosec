# frozen_string_literal: true

require_relative "../../test_helper"
require "open3"
require "rake"
require "tmpdir"

class BuiltinServicesTest < Minitest::Test
  def test_unknown_term_fields_cannot_expand_a_service_to_any_port
    [ { protocol: "tcp", destination_prt: "443" },
      { protocol: "tcp", destination_port: "443", source_prt: "1024" },
      { protocol: "tcp", destination_port: "443", 1 => "ignored" } ].each do |term|
      error = assert_raises(Algosec::BuiltinServices::Error) { load_services("services" => { "WEB" => [ term ] }) }
      assert_includes error.message, "WEB"
    end
  end

  def test_duplicate_service_names_cannot_overwrite_an_earlier_definition
    document = [
      { "name" => "WEB", "terms" => [ { "protocol" => "tcp", "destination_port" => "443" } ] },
      { "name" => "WEB", "terms" => [ { "protocol" => "udp", "destination_port" => "53" } ] }
    ]
    error = assert_raises(Algosec::BuiltinServices::Error) { load_services(document) }
    assert_includes error.message, "WEB"

    assert_raises(Algosec::BuiltinServices::Error) do
      load_services("services" => { "WEB" => { protocol: "tcp" }, WEB: { protocol: "udp" } })
    end
  end

  def test_conflicting_aliases_cannot_discard_a_restriction
    [ { protocol: "tcp", destination: "443", destination_port: "80" },
      { protocol: "tcp", source: "1024", source_port: "Any" },
      { "protocol" => "tcp", protocol: "udp" },
      { protocol: "tcp", "uuid" => "first", uuid: "second" } ].each do |term|
      error = assert_raises(Algosec::BuiltinServices::Error) { load_services("services" => { "WEB" => term }) }
      assert_includes error.message, "WEB"
    end
  end

  def test_terms_wrappers_cannot_hide_sibling_service_fields
    [ { source_port: "1024" }, { protocol: "udp" }, { destination_prt: "80" } ].each do |sibling|
      definition = { "terms" => [ { protocol: "tcp", destination_port: "443" } ], **sibling }
      error = assert_raises(Algosec::BuiltinServices::Error) { load_services("services" => { "WEB" => definition }) }

      assert_includes error.message, "WEB"
      assert_includes error.message, sibling.keys.sole.to_s
    end
  end

  def test_documents_cannot_choose_between_multiple_service_containers
    [ %w[records services], %w[services builtin_services], %w[records builtin_services] ].each do |containers|
      document = containers.to_h { |key| [ key, { "WEB" => { protocol: "tcp", destination_port: "443" } } ] }
      assert_raises(Algosec::BuiltinServices::Error) { load_services(document) }
    end
  end

  def test_equivalent_aliases_keep_the_same_definition
    term = { "protocol" => "TCP", protocol: "tcp", destination: 443, "destination_port" => "443-443",
             source: "Any", source_port: "0-65535", "timeout" => "-", timeout: nil }
    service = load_services("services" => { "WEB" => term }).services.fetch("WEB")

    assert service.matches?(protocol: "tcp", source_port: "1024", destination_port: "443")
    refute service.matches?(protocol: "tcp", source_port: "1024", destination_port: "80")
    assert_nil service.timeout
  end

  def test_supported_document_and_service_shapes_keep_defaults_and_explicit_any
    term = { "protocol" => "tcp", "destination" => "Any" }
    [ { "records" => { "WEB" => [ term ] } },
      { "services" => { "WEB" => term } },
      { "builtin_services" => { "WEB" => { "terms" => [ term ] } } },
      { "records" => [ { "name" => "WEB", "terms" => [ term ] } ] },
      [ { "name" => "WEB", **term } ] ].each do |document|
      service = load_services(document).services.fetch("WEB")
      assert service.matches?(protocol: "tcp", source_port: "1234", destination_port: "65535")
    end
    service = load_services("services" => { "WEB" => { protocol: "tcp" } }).services.fetch("WEB")
    assert service.matches?(protocol: "tcp", source_port: "1234", destination_port: "443")
  end

  def test_source_metadata_and_truncated_records_remain_supported
    document = { "source" => { "command" => "show service predefined" }, "truncated_names" => [ "cut~" ],
                 "records" => { "cut~" => { "unknown" => true }, "WEB" => { "protocol" => "tcp" } } }
    assert_equal [ "WEB" ], load_services(document).services.keys
  end

  def test_truncated_name_evidence_owns_its_text
    name = +"cut~"
    loaded = load_services("truncated_names" => [ name ], "records" => {})
    name.replace("changed")

    assert_equal [ "cut~" ], loaded.truncated_names
    assert_raises(FrozenError) { loaded.truncated_names.first.clear }
    refute name.frozen?
  end

  def test_icmp_type_and_code_and_rpc_metadata_remain_restricted
    loaded = load_services("services" => {
      "PING" => { "protocol" => "icmp", "destination" => "type:8", "source" => "code:0" },
      "RPC" => { "terms" => [ { protocol: "tcp", destination_port: "135", uuid: "app", timeout: "60", term: "rpc" } ] }
    })
    ping = loaded.services.fetch("PING")
    assert ping.matches?(protocol: "icmp", source_port: "0", destination_port: "8")
    refute ping.matches?(protocol: "icmp", source_port: "1", destination_port: "8")
    assert_equal "app", loaded.services.fetch("RPC").terms.sole.fetch(:uuid)
    assert_equal "60", loaded.services.fetch("RPC").timeout
    assert_equal "rpc", loaded.services.fetch("RPC").terms.sole.fetch(:term)
  end

  def test_direct_loading_does_not_depend_on_rails_or_the_offline_workflow
    script = <<~RUBY
      require "algosec/builtin_services"
      loaded = Algosec::BuiltinServices.new({ "services" => { "WEB" => { protocol: "tcp" } } }, vendor: :hillstone, device_id: 1)
      abort "service missing" unless loaded.services.key?("WEB")
      abort "offline workflow loaded" if defined?(Algosec::OfflineCheck)
      abort "Rails loaded" if defined?(Rails)
    RUBY
    output, errors, status = Open3.capture3(RbConfig.ruby, "-I", TestPaths.root.join("lib").to_s, "-e", script)

    assert status.success?, errors
    assert_empty output
    assert_empty errors
    refute Algosec::OfflineCheck.const_defined?(:BuiltinServices, false)
  end

  private

  def load_services(document)
    Algosec::BuiltinServices.new(document, vendor: :hillstone, device_id: 1)
  end
end
