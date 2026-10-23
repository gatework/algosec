# frozen_string_literal: true

require_relative "../../test_helper"
require_relative "support/policy_factory"
require "open3"

class DeclarationsTest < Minitest::Test
  include PolicyFactory
  Vendors = Algosec::Vendors

  def test_vendor_capabilities_aliases_and_load_validation
    assert_equal %i[asa srx netscreen fortinet h3c huawei hillstone topsec neteye palo_alto], Vendors.names(:parser)
    assert_equal 13, Vendors.names(:connector).size
    assert_equal :cisco_ios, Vendors.normalize("Cisco IOS-XE")
    assert_equal :cisco_n9k, Vendors.normalize("Cisco-N9K")
    assert_equal :palo_alto, Vendors.normalize("PAN-OS")
    assert_equal :radware, Vendors.normalize("alteon")
    assert_equal Algosec::Vendors::PaloAlto::Parser, Vendors.fetch(:palo_alto, :parser)
    assert_raises(ArgumentError) { Vendors.fetch(:unknown, :connector) }
    assert_raises(ArgumentError) { Vendors.names(:parsr) }
    Vendors.validate!
    entry = Vendors.definition(:fortinet)
    assert entry.frozen?
    assert entry.components.frozen?
    assert_match %r{/vendors/fortinet.rb\z}, entry.source_location.first
  end

  def test_registry_rejects_conflicts_before_publishing_and_checks_implementations
    registry = Vendors::Registry.new(Module.new)
    directory = TestPaths.root.join("lib/algosec/vendors/generic")
    entry = registry.register(:demo, namespace: "Demo", components: [ :elements ], aliases: [ "device-os" ], directory: directory)
    assert_raises(ArgumentError) { registry.register(:other, namespace: "Other", components: [ :elements ], aliases: [ "deviceos" ], directory: directory) }
    assert_raises(ArgumentError) { registry.register(:other, namespace: "Other", components: [ :parser ], directory: directory) }
    assert_raises(ArgumentError) { registry.register(:other, namespace: "Other", components: [ :wrong ], directory: directory) }
    assert_equal [ :demo ], registry.definitions.keys
    entry.namespace.send(:remove_const, :Elements)
    entry.namespace.const_set(:Elements, String)
    assert_raises(ArgumentError) { registry.validate! }
  end

  def test_domain_declarations_are_inherited_isolated_and_inspectable
    parent = Class.new(E::Definition) do
      defaults default_vrf: "parent"
      identity :address, :zone, :name
    end
    child = Class.new(parent) { defaults default_vrf: "child" }
    assert_equal "parent", parent.default_vrf
    assert_equal "child", child.default_vrf
    object = E::AddressObject.new(name: "a", zone: "inside", member: [ { type: "host", value: "192.0.2.1" } ], definition: child)
    assert_equal [ "inside", "a" ], child.address_identity(object)
    assert parent.declarations[:default_vrf].options.frozen?
    assert_match(/declarations_test.rb\z/, child.declarations[:default_vrf].source_location.first)
    assert_raises(ArgumentError) { child.defaults(default_vrf: "twice") }
    assert_raises(ArgumentError) { child.defaults(scoped_addresses?: "yes") }
    assert_raises(ArgumentError) { child.defaults(default_vfr: "typo") }
    assert_raises(ArgumentError) { child.identity(:typo, :name) }
  end

  def test_field_merge_modes_sources_and_unknown_commands
    parser = syntax_parser.new
    result = parser.perform("host a 192.0.2.1\ntag one\ntag one\ntag two\nunknown value\n")
    assert_equal Algosec::IPAddr.parse("192.0.2.1"), result.find(E::AddressObject, name: "a").set
    assert_equal [ "one", "one", "two" ], parser.observed[:append]
    assert_equal [ "one", "two" ], parser.observed[:union]
    assert_equal "two", parser.observed[:replace]
    assert_equal [ 5 ], result.diagnostics.map(&:line_number)
    assert_equal [ "unknown value\n" ], result.unparsed_lines
    assert_raises(Algosec::Config::IncompleteConfiguration) { syntax_parser.new(strict: true).perform("unknown value\n") }
  end

  def test_conversion_failure_preserves_unconsumed_line_and_parser_can_be_reused
    parser = syntax_parser.new
    reader = Algosec::Config::Reader.new("host a\n", vendor: :fortinet)
    error = assert_raises(Algosec::Config::ParseError) { parser.perform(reader) }
    assert_equal 1, error.line_number
    refute reader.parsed?(0)
    assert parser.perform("host a 192.0.2.1\n").complete?
    assert_empty parser.perform("").catalog.to_a
  end

  def test_rule_order_duplicates_and_missing_handlers
    parser = syntax_parser
    assert_raises(ArgumentError) { parser.line_rule(:objects, :duplicate, prefix: %w[host], using: :host) }
    assert_raises(ArgumentError) { parser.field(:address, "ip", to: :ip) }
    assert_raises(ArgumentError) { parser.stage(:objects) }
    bad = Class.new(Algosec::Config::Parser) { stage :objects, using: :missing }
    assert_raises(ArgumentError) { bad.validate_declarations! }
    child = Class.new(parser) { field :address, "mask", to: :mask }
    refute parser.declarations.key?([ :field, :address, "mask" ])
    assert child.declarations.key?([ :field, :address, "mask" ])
    result = parser.new.perform("host special 192.0.2.9\n")
    assert_equal "specialized", result.find(E::AddressObject, name: "special").description
    shadowed = Class.new(parser) { line_rule :objects, :unreachable, prefix: %w[host another], using: :host }
    assert_raises(ArgumentError) { shadowed.validate_declarations! }
    empty = Class.new(Algosec::Config::Parser) { stage :empty }
    assert_raises(ArgumentError) { empty.validate_declarations! }
    overridden = Class.new(parser) { line_rule :objects, :host, prefix: %w[host], using: :host }
    overridden.validate_declarations!
    parser.validate_declarations!
  end

  def test_command_frame_is_immutable_and_failure_does_not_publish_allocations
    opening, closing = [ "configure" ], [ "commit" ]
    klass = Class.new(P::Generator) do
      command_fields sources: "source"
      define_method(:create_rule) do
        define_object(:address, "a", "a") { emit("host a") }
        command_block("rule a", close: "end") { emit("bad\ncommand") }
      end
    end
    klass.command_frame(before: opening, after: closing)
    assert_equal [ "configure" ], opening
    opening << "external mutation"
    state = {}
    result = P::RuleMatcher.new(snapshot(:hillstone)).match(group(:hillstone))
    generator = klass.new(result, state: state)
    assert_raises(ArgumentError) { generator.perform }
    assert_empty generator.commands
    assert_empty state
    assert_equal [ "configure" ], klass.declarations[:command_frame].options[:before]
  end

  def test_new_vendor_can_parse_query_generate_and_build_connector_without_core_changes
    script = <<~'SCRIPT'
      require "algosec"
      Algosec::Vendors.register :example, namespace: "Example", aliases: [ "example-os" ],
        components: %i[elements parser policy generator connector], directory: "test/fixtures/vendors/example"
      Algosec::Vendors.validate!
      require_relative "test/lib/framework/support/policy_factory"
      include PolicyFactory
      parsed = Algosec::Config::Parser.perform("host web 192.0.2.1\n", vendor: "example-os", device_id: 1)
      raise "parse failed" unless parsed.complete? && parsed.catalog.size == 1
      cache = snapshot(:example, parsed.catalog.to_a)
      report = P::Searcher.new(networks: networks(:example), snapshots: { 1 => cache }).perform!(
        sources: [ "10.0.0.1" ], destinations: [ "192.0.2.1" ], services: [ "tcp/443" ])
      commands = P::Planner.new(report).perform.first[:policy_contents].first[:new][:content]
      raise "wrong command frame" unless commands.start_with?("configure\nrule allow\n") && commands.end_with?("end\ncommit\n")
      raise "wrong fields" unless commands.include?('source "10.0.0.1/32"')
      connector = Algosec::Connector.build(:example, host: "192.0.2.1")
      raise "wrong profile" unless connector.config_commands == [ "show configuration" ]
      puts "extension verified"
    SCRIPT
    output, error, status = Open3.capture3(RbConfig.ruby, "-Ilib", "-e", script, chdir: TestPaths.root.to_s)
    assert status.success?, error
    assert_equal "extension verified\n", output
    refute Vendors.definitions.key?(:example)
  end

  def test_public_entrypoint_loads_policy_without_rails_or_registry_validation
    script = <<~'SCRIPT'
      require "algosec"
      snapshot = Algosec::Policy::Snapshot.new(device_id: 1, vendor: :hillstone, catalog: Algosec::Elements::Catalog.new)
      raise "wrong snapshot" unless snapshot.vendor == :hillstone
      puts Algosec::Policy::Planner.name
    SCRIPT
    output, error, status = Open3.capture3(RbConfig.ruby, "-Ilib", "-e", script, chdir: TestPaths.root.to_s)
    assert status.success?, error
    assert_equal "Algosec::Policy::Planner\n", output
  end

  private

  def syntax_parser
    Class.new(Algosec::Config::Parser) do
      const_set(:VENDOR, :fortinet)
      attr_reader :observed
      stage :objects
      line_rule :objects, :special, prefix: %w[host special], using: :special
      line_rule :objects, :host, prefix: %w[host], using: :host
      line_rule :objects, :tag, prefix: %w[tag], using: :tag
      stage :emit_objects, using: :emit_objects
      field :address, "ip", to: :member, convert: :host_member
      field :tag, "append", to: :append, merge: :append
      field :tag, "union", to: :union, merge: :union
      field :tag, "replace", to: :replace

      private

      def host_member(values) = [ address_leaf(values.fetch(0)) ]

      def host(line, words)
        map_field(:address, draft(:address, words.fetch(1), name: words.fetch(1)), "ip", words.drop(2), line)
      end

      def special(line, words)
        host(line, words)
        draft(:address, "special", description: "specialized")
      end

      def tag(line, words)
        object = draft(:tags, "tags")
        %w[append union replace].each { |keyword| map_field(:tag, object, keyword, words.drop(1), line) }
        @observed = object.attributes
      end
    end
  end
end
