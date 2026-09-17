# Phase 8 Runbook

**Mục đích:** materialize nguồn đã pin và xây Security Knowledge Graph toàn cục,
provenance-complete cho bốn CWE development mà không đọc advisory, evaluator-only
hoặc `test_locked`.

## Contract

- Nguồn: MITRE CWE 4.20, OWASP Top 10:2021 tại commit pin, và CodeQL Java API
  models `codeql/java-all@9.2.2`; URL/version/hash/license nằm trong
  `configs/knowledge/phase8_sources.yaml`.
- Scope: `CWE-22/78/79/94` cộng related-CWE closure một hop ở MITRE view 1000.
- Graph là global; Phase 9 mới tạo project view và cross-layer mapping.
- Phase 6 `p6_static_v2_dev_full_001` và Phase 7 `p7_pg_dev_full_004` là dependency
  bắt buộc, được kiểm bằng checksum mà không ingest project graph/label.
- Source download/copy chỉ diễn ra ở preparation boundary. Builder chính offline,
  zero LLM call và không có provider/API dependency.
- `deterministic/` và `llm_inferred/` tách vật lý. Canonical Phase 8 yêu cầu inferred
  layer rỗng; CodeQL generated-only/experimental models không được nhập.

## 1. Materialize nguồn pin

```bash
cd ~/Documents/MaxVera
bash scripts/tools/setup_codeql.sh
bash scripts/tools/fetch_phase8_knowledge.sh
```

Lệnh idempotent nếu source bundle hiện có vẫn đúng checksum. Nếu upstream trả byte
khác pin hoặc local `java-all@9.2.2` không đúng model-tree hash, lệnh fail closed;
không cập nhật hash tự động. `data/raw/` chỉ được tạo bởi bước preparation này và
không được sửa tay.

## 2. Dry-run và pilot

Mỗi run ID immutable:

```bash
bash scripts/tools/build_security_kg.sh \
  --mode pilot --dry-run --run-id p8_skg_global_dry_002

bash scripts/tools/build_security_kg.sh \
  --mode pilot --run-id p8_skg_global_pilot_003

bash scripts/tools/validate_phase8.sh \
  --run-root results/graphs/knowledge/p8_skg_global_pilot_003
```

Pilot vẫn build toàn bộ global KG vì đây là artifact nhỏ và deterministic; nhãn
`pilot` chỉ ngăn promote nhầm thành canonical full result.

## 3. Full build

Sau khi quality gate và pilot pass, dùng một run ID full mới:

```bash
bash scripts/tools/build_security_kg.sh \
  --mode full --run-id p8_skg_global_full_002

bash scripts/tools/validate_phase8.sh \
  --run-root results/graphs/knowledge/p8_skg_global_full_002

jq . results/graphs/knowledge/p8_skg_global_full_002/kg_summary.json
jq '.root_cwes[] | {cwe_id,status,relation_counts}' \
  results/graphs/knowledge/p8_skg_global_full_002/audit_sample.json
```

Không chạy lại cùng ID hoặc chỉnh artifact sau atomic finalization. Nếu code/config
đổi, tạo run ID mới. Chỉ khóa một full run khi implementation/config/docs đã đồng
bộ và provenance manifest đủ để tái lập. Canonical development artifact là
`p8_skg_global_full_002`, được tạo tại clean commit `50ed53e`; validator và mọi
gate bên dưới đều pass. `full_001` là dirty-tree diagnostic candidate. Không sửa
hoặc chạy lại hai ID này; reproduction mới phải dùng run ID mới.

## Output chính

```text
results/graphs/knowledge/<run-id>/
├── deterministic/{nodes,edges}.jsonl
├── llm_inferred/{nodes,edges}.jsonl
├── audit_sample.json
├── kg_summary.json
├── dependency_status.json
├── source_manifest.json
├── manifest.json
└── checksums.sha256
```

## Gate Phase 8

- exact checksum của ba source bundle và hai dependency lock đều đúng;
- mọi node/edge có provenance đầy đủ và confidence trong `[0,1]`;
- ID, ordering, graph digest và checksum tái tạo deterministic;
- mọi root CWE pass audit cho related-CWE, OWASP, source, sink, propagator,
  precondition và mitigation;
- có sanitizer fact thật; không tạo placeholder cho family chưa có model;
- inferred layer rỗng, zero network/LLM call trong build;
- không có project ID, CVE/advisory/patch/fix hoặc `test_locked` trong fact output.
