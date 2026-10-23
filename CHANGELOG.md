# Changelog

## Unreleased

## 0.3.0 (2026-10-23)

- Bind target and source snapshot time zones before deployment writes and when restoring approved plans or proposed graphs. Snapshot owns the shared immutable baseline used by Plan, ChangeSet and effect proofs; clock-context drift can no longer be deferred until readback.
- Advance semantic documents and approvals to `firewall-domain-v8` and policy revisions to v27, preserving v7 group semantics. Host baseline contexts must include `time_zone`; old approvals require replanning. Configuration caches remain v82 because this change adds no stored object state.
- Prove destination port relations after native rule selection instead of accepting independent coverage of the two port sets, including Huawei server-map lookups and consumed-mapping validation. Preserve per-protocol offsets, constants and holes when segmenting requests, and retain unknown aliases during reverse discovery.
- Preserve Fortinet VIP `1-to-1` and `m-to-n` semantics through configuration documents and readback. Expand an implicit mapped start for one-to-one ranges; multi-target allocation and unmodeled server load balancing cannot prove a fixed port result. Invalid or unhandled modes retain incomplete evidence.
- Advance semantic documents and approvals to `firewall-domain-v6`, policy revisions to v25 and configuration caches to v82, preserving v5 address-negation semantics. Reparse configurations and replan requests under the new port relation semantics.
- Allocate generated names across each vendor's shared object/group namespaces, including external built-in services, ASA network/service objects and Fortinet addresses/VIPs. Respect local and global address-book lookup to prevent shadowing existing references while retaining separate zone namespaces and stable batch reuse.
- Reject Fortinet VIP allocations with conflicting address or port translations on overlapping external matches, including wildcard interfaces, within one render or successive renders sharing state. Failed batches publish neither commands nor allocations; compatible overlaps remain available for preview without granting NAT effect proof.
- Advance semantic documents and approvals to `firewall-domain-v4` and policy revisions to v24 so older generated scripts require replanning. Configuration caches advance to v80 for the renamed domain and internal classes.
- Consume the connector's optional `on_receipt:` completion callback when explicitly supported, retaining apply/save receipts and native save confirmation before cancellation or journal failure. Older connectors keep the result/progress fallback and its documented cancellation limitation; net-connector 0.18.0 supplies this callback.
- Bind shared generation allocations to their original snapshot and generator; seal the consumed graph and reject cross-context or unbound legacy state before emitting commands, while preserving successful reuse and batch rollback.
- Finalize deployment attempts on thread termination and nonlocal exits; an unacknowledged terminal journal cannot leave a successful status.
- Retain every completed step from a returned connector result before persisting receipts, so an early journal failure cannot erase later completion evidence or trigger replay.
- Preserve explicit native save confirmation after a connector logging failure, while retaining the original error and uncertain deployment status. When inferring confirmation from a failed returned result, other execution errors and incomplete or contradictory save evidence remain unconfirmed.
- Reject service requests whose port or ICMP type restrictions cannot be represented, instead of silently widening `any/443` to `any` or `icmp/8` to the entire protocol. Apply the same validation to direct result maps, traffic conversion and legacy NAT queries.
- Unify unrestricted ICMP/ICMPv6 type markers across service indexes, matching, coverage, projections and equality; retain original terms and include type zero in policy routing and NAT first-match selection.
- Aggregate multi-address domain query outcomes by canonical action, preserving differences between deny, drop, reset and reject.
- Advance semantic documents and approvals to `firewall-domain-v3`, configuration caches to v79 and policy revisions to v23. Reparse configuration and replan from original requests before approval; do not relabel older evidence.

- Unify vendor output around canonical security rules, NAT rules, address and service objects, scopes and rulebases while retaining native identity and unknown evidence.
- Add exact packet/traffic evaluation, whole-change-set proofs, future time-window checks and typed NAT verification.
- Implement verified convergence, scoped cross-vendor migration and evidence-based reclamation with independent native readback.
- Add versioned configuration and approved-plan documents; reconstruct inputs and rerun proofs after restoration.
- Coordinate deployment receipts, save confirmation and readback through injected session and journal protocols.
- Provide configuration, approval and deployment protocols for host adapters; encryption, durable claims and persistence remain in the host application.
- Require net-connector 0.16 or newer; invalidate the previous object-cache and policy revision.
- Extend offline examples, package verification and capability documentation. Offline checks do not establish live-device behavior.
- Preserve multiple PAN-OS schedule declarations, Neteye source-port limits and unsupported SRX NAT interface context; retain those conditions through configuration documents.
- Align offline verification with joint coverage and generated traffic slices; invalidate earlier semantic documents and approvals with firewall-domain-v2.
- Select embedded NAT through the complete ordered security rulebase so earlier ordinary rules cannot produce false translation queries or proofs.
- Accumulate ASA and H3C periodic windows without losing day/time pairings; keep unmodeled combined and Fortinet overnight/full-day schedules explicitly unknown.

## 0.2.0 (2026-10-22)

- Extract the firewall domain from the Algosec Rails application into a standalone gem.
- Preserve configuration, policy, vendor, connector, collection, and offline-check APIs, including the working-tree Huawei NAT changes.
- Declare runtime dependencies explicitly and retain ActiveSupport cache/time-zone support.
- Default configuration caches to per-instance MemoryStore; hosts inject shared stores or file directories.
- Add independent domain tests, synthetic examples, package verification, and Linux/macOS CI.
- Prepare local release artifacts; no registry publication is implied.
- Use a new version because RubyGems already contains the initial 0.1.0 scaffold.

## 0.1.0 (2026-10-16)

- Publish the initial namespace scaffold.
