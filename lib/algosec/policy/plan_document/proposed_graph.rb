# frozen_string_literal: true

module Algosec
  module Policy
    class PlanDocument
      # 候选没有设备采集来源；复用 Document 的固定类型编码器和图验证器，绝不伪造 source。
      module ProposedGraph
        KEYS = %w[kind schema_version semantic_version context nodes catalog builtin_services].freeze
        module_function

        def dump(elements, snapshot:, at:)
          Encoder.new(elements, snapshot, at).call
        end

        def load(document, snapshot:)
          Decoder.new(document, snapshot).call
        end

        class Encoder < Config::Document::Encoder
          def initialize(elements, snapshot, at)
            @elements, @snapshot, @at = elements, snapshot, at
            @nodes, @objects, @ids = [], [], {}.compare_by_identity
          end

          def call
            roots = @elements.map { |element| visit(element) }
            builtins = @snapshot.builtin_services.map { |element| { "name" => element.name, "node" => visit(element) } }
            dns = @nodes.select { |node| node["kind"] == "address_object" }.flat_map do |node|
              node.fetch("attributes").fetch("dns_answers").values.filter_map { |answer| answer.fetch("evidence")["source"] }
            end.uniq
            V.fail! if dns.size > 1
            context = { "vendor" => @snapshot.vendor.to_s, "device_id" => @snapshot.device_id, "definition" => @snapshot.vendor.to_s,
              "device_name" => nil, "settings" => PlanDocument.review(Vendors.fetch(@snapshot.vendor, :parser).options(@snapshot.settings)), "reference_time" => @at.getutc.iso8601(9),
              "time_zone" => @snapshot.time_zone, "dns_context" => dns.first }
            Config::Document::Context.validate(context)
            { "kind" => "proposed_graph", "schema_version" => 1, "semantic_version" => Algosec::SEMANTIC_VERSION,
              "context" => context, "nodes" => @nodes, "catalog" => roots, "builtin_services" => builtins }
          end

          private

          def validate_owner(object)
            V.fail! unless object.vendor == @snapshot.vendor && object.device_id == @snapshot.device_id && object.definition_id == @snapshot.vendor.to_s
          end
        end

        class Decoder < Config::Document::Decoder
          def initialize(document, snapshot)
            super(document, expected_source_sha256: nil, expected_context: nil, source_content: nil, source_details: nil)
            @snapshot = snapshot
          end

          def call
            V.json(@data)
            V.object(@data, KEYS)
            V.fail! unless @data["kind"] == "proposed_graph" && @data["schema_version"] == 1 && @data["semantic_version"] == Algosec::SEMANTIC_VERSION
            @context = @data.fetch("context")
            Config::Document::Context.validate(@context)
            V.fail! unless @context["vendor"] == @snapshot.vendor.to_s && @context["device_id"] == @snapshot.device_id &&
              @context["time_zone"] == @snapshot.time_zone && @context["settings"] == PlanDocument.review(Vendors.fetch(@snapshot.vendor, :parser).options(@snapshot.settings))
            index_nodes
            validate_roots
            validate_graph
            restore_builtin_references
            @nodes.each_key { |id| build(id) }
            roots = @data.fetch("catalog").map { |id| @objects.fetch(id) }
            V.fail! unless roots.map(&:identity).uniq.size == roots.size
            roots.each(&:seal!)
            roots.freeze
          end

          private

          def restore_builtin_references
            builtins = @snapshot.builtin_services.to_h { |service| [ service.name, service ] }
            V.fail! unless @data.fetch("builtin_services").map { |entry| entry.fetch("name") }.sort == builtins.keys.sort
            @data.fetch("builtin_services").each do |entry|
              id = entry.fetch("node")
              restored = build(id)
              original = builtins.fetch(entry.fetch("name"))
              _kind, codec = Config::Document.codec_for(original)
              V.fail! unless original.identity == restored.identity && codec.attributes(original) == codec.attributes(restored)
              @objects[id] = original
            end
          end
        end
      end
    end
  end
end
