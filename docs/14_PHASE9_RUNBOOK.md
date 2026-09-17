# Phase 9 Runbook

**Mục đích:** xây Evidence Graph/USEG iteration 0 từ các canonical development
artifacts Phase 6/7/8, không đọc evaluator-only, advisory, patch hoặc
`test_locked`.

## Contract

- Input khóa: `p6_static_v2_dev_full_001`, `p7_pg_dev_full_004`,
  `p8_skg_global_full_002`; runner kiểm exact checksums trước build.
- Full run có đủ 96 final statuses. 15 Phase 7 failures tiếp tục là
  `ANALYSIS_FAILED`; không tạo partial hoặc placeholder graph.
- Hypothesis/location/precondition trở thành Evidence nodes; Program/Security
  facts được tham chiếu bằng upstream stable ID.
- `TAINT_CANDIDATE` chỉ là `unverified_candidate`, không phải verified finding.
- Confidence components và provenance được lưu riêng; không có aggregate scalar.
- Iteration 0 không gọi mạng hoặc LLM. Verification/contradiction thật thuộc
  Phase 11; node kind đã được khai báo nhưng không materialize giả ở Phase 9.

## 1. Quality gate

```bash
cd ~/Documents/MaxVera
uv run --frozen ruff check .
uv run --frozen mypy src
uv run --frozen pytest -q
```

## 2. Dry-run và pilot

Mỗi run ID là immutable:

```bash
bash scripts/tools/build_phase9_useg.sh \
  --mode pilot --dry-run --run-id p9_useg_dev_dry_002

bash scripts/tools/build_phase9_useg.sh \
  --mode pilot --limit 4 --run-id p9_useg_dev_pilot_003

bash scripts/tools/validate_phase9.sh \
  --run-root results/graphs/useg/p9_useg_dev_pilot_003
```

Pilot mặc định chọn project đầu tiên có Phase 7 graph thành công. Có thể dùng
`--project-id <opaque-id>` để kiểm một project development cụ thể.

## 3. Full build

Sau khi commit implementation/config/docs và xác nhận worktree sạch, dùng ID mới:

```bash
bash scripts/tools/build_phase9_useg.sh \
  --mode full --run-id p9_useg_dev_full_002

bash scripts/tools/validate_phase9.sh \
  --run-root results/graphs/useg/p9_useg_dev_full_002

jq . results/graphs/useg/p9_useg_dev_full_002/useg_summary.json
jq . results/graphs/useg/p9_useg_dev_full_002/trace_audit.json
```

Workspace hiện có validated dirty-tree candidate `p9_useg_dev_full_001`; không
dùng lại hoặc chỉnh artifact này. `full_002` trên clean commit là candidate phù
hợp để khóa canonical.

## 4. Truy vết một candidate path

Lấy một `TAINT_PATH` ID rồi query provenance subgraph:

```bash
path_id="$(jq -r 'select(.kind == "TAINT_PATH") | .node_id' \
  results/graphs/useg/p9_useg_dev_full_002/useg/nodes.jsonl | head -n 1)"

bash scripts/tools/trace_phase9_useg.sh \
  --run-root results/graphs/useg/p9_useg_dev_full_002 \
  --node-id "$path_id" --max-depth 4
```

Kết quả phải có `layers_reached` gồm `evidence`, `program`, `security`.

## Output chính

```text
results/graphs/useg/<run-id>/
├── useg/{nodes,edges}.jsonl
├── project_status.jsonl
├── project_summary.jsonl
├── useg_summary.json
├── trace_audit.json
├── dependency_status.json
├── manifest.json
└── checksums.sha256
```

Full run có `STATUS=FAILED` khi tồn tại 15 recorded misses. Đây là đúng theo
intention-to-analyze; authoritative gate là validator
`PASS_WITH_ANALYSIS_FAILURES`, đủ 96 final statuses và exact checksums.

## Gate Phase 9

- exact lock/checksum Phase 6/7/8 và 96 final statuses;
- mọi node/edge có provenance; confidence giữ thành component độc lập;
- canonical ID/order, resolved endpoints và rebuild deterministic;
- graph dependency không có cycle gây double-count confidence;
- serialization JSONL round-trip không mất dữ liệu;
- mọi candidate path truy được tới Program location và Security fact;
- mọi future final finding phải thêm trace tới tool/model call;
- không có evaluator/test knowledge, placeholder verification hoặc LLM/network
  call trong iteration 0.
