# frozen_string_literal: true

module Algosec
  module Config
    class Document
      class Encoder
        def initialize(result)
          @result, @nodes, @objects = result, [], []
          @ids = {}.compare_by_identity
        end

        def call(raw:)
          Value.fail! unless raw == true || raw == false
          context = Context.dump(@result)
          Context.validate(context)
          catalog = @result.catalog.map { |object| visit(object) }
          builtins = @result.builtin_services.map { |name, object| { "name" => name, "node" => visit(object) } }
          source = @result.reader.source_metadata
          data = { "schema_version" => SCHEMA_VERSION, "semantic_version" => SEMANTIC_VERSION, "context" => context,
            "source" => { "sha256" => source.fetch(:source_sha256), "md5" => source.fetch(:md5),
              "source_complete" => source.fetch(:source_complete), "created_at" => Value.time(source.fetch(:created_at)),
              "line_count" => source.fetch(:line_count), "parsed_flags" => source.fetch(:parsed_flags), "position" => source.fetch(:position) },
            "diagnostics" => @result.diagnostics.map { |item| { "code" => item.code.to_s, "line_number" => item.line_number, "message_present" => item.message_present? } },
            "nodes" => @nodes, "catalog" => catalog, "builtin_services" => builtins, "raw_details" => nil }
          Value.json(data)
          data["raw_details"] = details(data) if raw
          data
        end

        private

        def visit(object)
          return @ids.fetch(object) if @ids.key?(object)
          Value.fail! if @nodes.size >= MAX_NODES
          kind, codec = Document.codec_for(object)
          validate_owner(object)
          id = format("n%06d", @nodes.size + 1)
          @ids[object] = id
          node = { "id" => id, "kind" => kind, "identity_fields" => object.identity_fields, "attributes" => codec.attributes(object), "edges" => {} }
          @nodes << node
          @objects << object
          node["edges"] = codec.edges(object).to_h do |name, edge|
            shape = codec.edge_types.fetch(name).first
            value = case shape
            when :named then edge.map { |entry| { "name" => entry.fetch("name"), "node" => entry["node"] && visit(entry["node"]) } }
            when :array then edge.map { |child| visit(child) }
            else edge && visit(edge)
            end
            [ name, value ]
          end
          id
        end

        def validate_owner(object)
          Value.fail! unless object.vendor == @result.reader.vendor && object.device_id == @result.reader.device_id && object.definition_id == @result.definition_id
        end

        def details(data)
          { "schema_version" => 1, "source_sha256" => @result.reader.source_sha256, "document_sha256" => Value.digest(data),
            "element_configs" => @objects.map { |object| { "node" => @ids.fetch(object), "value" => object.config } },
            "diagnostic_messages" => @result.diagnostics.each_with_index.map { |item, index| { "index" => index, "value" => item.message } },
            "unparsed_commands" => @objects.select { |object| object.is_a?(Elements::SecurityRule) || object.is_a?(Elements::Schedule) }
              .map { |object| { "node" => @ids.fetch(object), "value" => object.unparsed_commands } },
            "dns_errors" => @objects.grep(Elements::AddressObject).flat_map do |object|
              object.dns_answers.keys.filter_map do |domain|
                { "node" => @ids.fetch(object), "domain" => domain, "value" => object.dns_error(domain) } if object.dns_error_key?(domain)
              end
            end }
        end
      end
    end
  end
end
