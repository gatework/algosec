# frozen_string_literal: true

module Algosec
  class Deployment
    # 实时正文基线由宿主核验，解析与领域证明分别使用明确协作者。
    class Verification
      Context = Data.define(:target, :source)
      Evidence = Data.define(:confirmed, :revision, :semantic_version) do
        def confirmed? = confirmed == true && semantic_version == Algosec::SEMANTIC_VERSION
        def to_h = { confirmed: confirmed?, revision: revision, semantic_version: semantic_version }
      end

      def initialize(snapshot_loader:, baseline_validator:, source_loader: nil)
        @snapshot_loader, @baseline_validator, @source_loader = snapshot_loader, baseline_validator, source_loader
      end

      def preflight(plan:, capture:)
        unless @baseline_validator.call(plan: plan, capture: capture) == true
          raise Policy::Error.new("实时配置与审批基线不一致", code: :stale_plan)
        end
        target = @snapshot_loader.call(capture: capture, plan: plan)
        source = if plan.source_baseline == plan.target_baseline
          target
        else
          raise Policy::Error.new("缺少实时源设备基线", code: :missing_baseline) unless @source_loader
          @source_loader.call(plan: plan)
        end
        Context.new(target: target, source: source)
      end

      def verify(plan:, capture:)
        snapshot = @snapshot_loader.call(capture: capture, plan: plan)
        snapshot.require_complete!
        proof = plan.verify_readback(snapshot)
        Evidence.new(confirmed: proof.verified?, revision: snapshot.revision, semantic_version: Algosec::SEMANTIC_VERSION)
      end
    end
  end
end
