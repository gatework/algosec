# frozen_string_literal: true

module Algosec
  module Config
    class Document
      class Decoder
        ROOT = %w[schema_version semantic_version context source diagnostics nodes catalog builtin_services raw_details].freeze
        SOURCE = %w[sha256 md5 source_complete created_at line_count parsed_flags position].freeze

        def initialize(data, expected_source_sha256:, expected_context:, source_content:, source_details:)
          @data, @expected_sha, @expected_context = data, expected_source_sha256, expected_context
          @source_content, @source_details = source_content, source_details
          @nodes, @objects, @codecs = {}, {}, {}
          @commands = {}
          @configs, @messages, @errors = {}, {}, Hash.new { |hash, key| hash[key] = {} }
        end

        def call
          validate_envelope
          index_nodes
          validate_roots
          validate_graph
          validate_details
          reader = restore_reader
          diagnostics = restore_diagnostics(reader.size)
          @nodes.each_key { |id| build(id) }
          roots = @data.fetch("catalog").map { |id| @objects.fetch(id) }
          Value.fail! unless roots.map(&:identity).uniq.size == roots.size
          catalog = Elements::Catalog.new(roots, vendor: @context.fetch("vendor"), device_id: @context.fetch("device_id"))
          builtins = @data.fetch("builtin_services").to_h { |entry| [ entry.fetch("name"), @objects.fetch(entry.fetch("node")) ] }
          Result.new(reader: reader, catalog: catalog, diagnostics: diagnostics, at: Value.instant(@context.fetch("reference_time")),
            time_zone: @context.fetch("time_zone"), parsing_settings: @context.fetch("settings"), definition_id: @context.fetch("definition"),
            builtin_services: builtins, dns_context: @context.fetch("dns_context"))
        end

        private

        def validate_envelope
          Value.json(@data)
          Value.object(@data, ROOT)
          Value.fail! unless @data["schema_version"].instance_of?(Integer) && @data["schema_version"] == SCHEMA_VERSION && @data["semantic_version"] == SEMANTIC_VERSION
          Value.fail! unless @data["raw_details"].nil? || @data["raw_details"].is_a?(Hash)
          Value.fail! unless @source_details.nil? || @source_details.is_a?(Hash)
          Value.fail! unless @expected_context.nil? || @expected_context.is_a?(Hash)
          Value.fail! unless @expected_sha.nil? || (@expected_sha.is_a?(String) && /\A[0-9a-f]{64}\z/.match?(@expected_sha))
          %w[nodes catalog builtin_services diagnostics].each { |key| Value.fail! unless @data[key].is_a?(Array) }
          @data.fetch("diagnostics").each { |entry| Value.object(entry, %w[code line_number message_present]) }
          @context = @data.fetch("context")
          Context.validate(@context)
          Value.object(@data.fetch("source"), SOURCE)
          Value.fail! if @expected_sha && @expected_sha != @data.fetch("source").fetch("sha256")
          if @expected_context
            Value.json(@expected_context)
            Value.fail! unless @expected_context.is_a?(Hash) && (@expected_context.keys - Context::KEYS).empty?
            Value.fail! unless @expected_context.all? { |key, value| @context.fetch(key) == value }
          end
        end

        def index_nodes
          nodes = @data.fetch("nodes")
          Value.fail! unless nodes.is_a?(Array) && nodes.size <= MAX_NODES
          nodes.each do |node|
            Value.object(node, %w[id kind identity_fields attributes edges])
            id = node.fetch("id")
            Value.fail! unless id.is_a?(String) && /\An[0-9]{6,}\z/.match?(id) && !@nodes.key?(id)
            codec = Document.codec_named(node.fetch("kind"))
            codec.validate(node)
            identity = node.fetch("identity_fields")
            Value.fail! unless identity.is_a?(Array) && identity.all? { |part| part.is_a?(String) }
            @nodes[id], @codecs[id] = node, codec
          end
        end

        def validate_roots
          roots = @data.fetch("catalog")
          builtins = @data.fetch("builtin_services")
          Value.fail! unless roots.is_a?(Array) && roots.uniq.size == roots.size && builtins.is_a?(Array)
          roots.each { |id| reference(id) }
          names = []
          builtins.each do |entry|
            Value.object(entry, %w[name node])
            name = entry.fetch("name")
            Value.fail! unless name.is_a?(String) && !names.include?(name)
            names << name
            reference(entry.fetch("node"), kinds: %w[service_object])
          end
        end

        def reference(id, kinds: nil, optional: false)
          return if id.nil? && optional
          Value.fail! unless id.is_a?(String) && @nodes.key?(id)
          Value.fail! if kinds && !kinds.include?(@nodes.fetch(id).fetch("kind"))
          id
        end

        def edge_ids(id)
          node, codec = @nodes.fetch(id), @codecs.fetch(id)
          codec.edge_types.flat_map do |name, (shape, kinds)|
            value = node.fetch("edges").fetch(name)
            case shape
            when :named
              Value.fail! unless value.is_a?(Array)
              names = []
              value.filter_map do |entry|
                Value.object(entry, %w[name node])
                key = entry.fetch("name")
                Value.fail! unless key.is_a?(String) && !names.include?(key)
                names << key
                reference(entry.fetch("node"), kinds: kinds, optional: true)
              end
            when :array
              Value.fail! unless value.is_a?(Array) && value.uniq.size == value.size
              value.map { |target| reference(target, kinds: kinds) }
            else
              reference(value, kinds: kinds, optional: shape == :optional)
            end
          end.compact
        end

        def validate_graph
          @edges = @nodes.to_h { |id, _| [ id, edge_ids(id) ] }
          visiting, visited = {}, {}
          walk = lambda do |id, depth|
            Value.fail! if depth > 256 || visiting[id]
            return if visited[id]
            visiting[id] = true
            @edges.fetch(id).each { |target| walk.call(target, depth + 1) }
            visiting.delete(id)
            visited[id] = true
          end
          roots = @data.fetch("catalog") + @data.fetch("builtin_services").map { |entry| entry.fetch("node") }
          roots.each { |id| walk.call(id, 0) }
          Value.fail! unless visited.size == @nodes.size
        end

        def validate_details
          embedded = @data.fetch("raw_details")
          Value.fail! if embedded && @source_details && embedded != @source_details
          details = embedded || @source_details
          return unless details
          Value.json(details)
          Value.object(details, %w[schema_version source_sha256 document_sha256 element_configs diagnostic_messages dns_errors unparsed_commands])
          Value.fail! unless details["schema_version"].instance_of?(Integer) && details["schema_version"] == 1 && details["source_sha256"] == @data.fetch("source").fetch("sha256") &&
            details["document_sha256"] == Value.digest(@data.merge("raw_details" => nil))
          configs = details.fetch("element_configs")
          Value.fail! unless configs.is_a?(Array)
          configs.each do |entry|
            Value.object(entry, %w[node value])
            id, value = entry.values_at("node", "value")
            reference(id)
            Value.fail! if @configs.key?(id)
            protected_value(value, @nodes.fetch(id).fetch("attributes").fetch("config_present"))
            @configs[id] = value
          end
          Value.fail! unless @configs.size == @nodes.size
          messages = details.fetch("diagnostic_messages")
          Value.fail! unless messages.is_a?(Array)
          messages.each do |entry|
            Value.object(entry, %w[index value])
            index, value = entry.values_at("index", "value")
            Value.fail! unless index.is_a?(Integer) && index >= 0 && index < @data.fetch("diagnostics").size && !@messages.key?(index)
            protected_value(value, @data.fetch("diagnostics").fetch(index).fetch("message_present"))
            @messages[index] = value
          end
          Value.fail! unless @messages.size == @data.fetch("diagnostics").size
          restore_errors(details.fetch("dns_errors"))
          restore_commands(details.fetch("unparsed_commands"))
        end

        def protected_value(value, present)
          Value.fail! unless present == true || present == false
          Value.fail! unless present ? value.is_a?(String) : value.nil?
        end

        def restore_errors(entries)
          Value.fail! unless entries.is_a?(Array)
          expected = @nodes.flat_map do |id, node|
            next [] unless node["kind"] == "address_object"
            node.fetch("attributes").fetch("dns_answers").filter_map { |domain, answer| [ id, domain ] if answer.fetch("error_key") }
          end
          seen = []
          entries.each do |entry|
            Value.object(entry, %w[node domain value])
            key = entry.values_at("node", "domain")
            Value.fail! unless expected.include?(key) && !seen.include?(key)
            answer = @nodes.fetch(key[0]).fetch("attributes").fetch("dns_answers").fetch(key[1])
            protected_value(entry["value"], answer.fetch("error_present"))
            @errors[key[0]][key[1]] = entry["value"]
            seen << key
          end
          Value.fail! unless seen.sort == expected.sort
        end

        def restore_commands(entries)
          Value.fail! unless entries.is_a?(Array)
          expected = @nodes.select { |_id, node| %w[security_rule schedule].include?(node.fetch("kind")) }.keys
          entries.each do |entry|
            Value.object(entry, %w[node value])
            id, commands = entry.values_at("node", "value")
            Value.fail! unless expected.include?(id) && !@commands.key?(id) && commands.is_a?(Array) && commands.all? { |command| command.is_a?(String) }
            metadata = @nodes.fetch(id).fetch("attributes").fetch("unparsed_commands_metadata")
            Value.fail! unless metadata.fetch("count") == commands.size && metadata.fetch("sha256") == Digest::SHA256.hexdigest(JSON.generate(commands))
            @commands[id] = commands
          end
          Value.fail! unless @commands.keys.sort == expected.sort
        end

        def restore_reader
          source = @data.fetch("source")
          reader = Reader.from_metadata(vendor: @context.fetch("vendor"), device_id: @context.fetch("device_id"), device_name: @context.fetch("device_name"),
            created_at: Value.instant(source.fetch("created_at")), source_complete: source.fetch("source_complete"),
            source_sha256: source.fetch("sha256"), md5: source.fetch("md5"), line_count: source.fetch("line_count"),
            parsed_flags: source.fetch("parsed_flags"), position: source.fetch("position"))
          @source_content.nil? ? reader : reader.with_source(@source_content)
        end

        def restore_diagnostics(line_count)
          entries = @data.fetch("diagnostics")
          Value.fail! unless entries.is_a?(Array)
          entries.each_with_index.map do |entry, index|
            Value.object(entry, %w[code line_number message_present])
            code = DIAGNOSTIC_CODES.fetch(entry.fetch("code")) { Value.fail! }
            number, present = entry.values_at("line_number", "message_present")
            Value.fail! unless number.nil? || (number.is_a?(Integer) && number.between?(1, line_count))
            Value.fail! unless present == true || present == false
            Diagnostic.new(code, @messages[index], number, message_present: present)
          end
        end

        def build(id)
          return @objects.fetch(id) if @objects.key?(id)
          node, codec = @nodes.fetch(id), @codecs.fetch(id)
          edges = node.fetch("edges").to_h do |name, value|
            shape = codec.edge_types.fetch(name).first
            resolved = case shape
            when :named then value.map { |entry| entry.merge("node" => entry["node"] && build(entry["node"])) }
            when :array then value.map { |target| build(target) }
            else value && build(value)
            end
            [ name, resolved ]
          end
          attrs = node.fetch("attributes")
          object = codec.build(attrs, edges, codec.common(attrs, @context, @configs[id]), @context, { dns_errors: @errors[id], unparsed_commands: @commands[id] })
          Value.fail! unless object.identity_fields == node.fetch("identity_fields") && codec.attributes(object) == attrs && codec.edges(object) == edges
          if object.is_a?(Elements::AddressObject)
            object.dns_answers.each_value do |answer|
              Context.dns(answer["source"], @context["device_id"])
              Value.fail! if answer.key?("source") && answer["source"] != @context["dns_context"]
            end
          end
          @objects[id] = object
        end
      end
    end
  end
end
