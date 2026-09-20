# Phase 11 — Static verification và iterative USEG update

Phase 11 nhận đúng canonical B9 `p10_b9_dev_full_001`, không gọi LLM và không
đọc evaluator labels trong analyzer. Mỗi frozen specification được chạy bằng
CodeQL Java global taint tracking trên vulnerable database. Chỉ differential
run có path ở vulnerable version và không còn path với cùng specification ở
fixed version mới mang trạng thái `VERIFIED_DIFFERENTIAL`.

## 1. Contract đã khóa

- protocol `1.8.0`, verifier `phase11-static-verification-v1`;
- dependencies: Phase 9 `p9_useg_dev_full_003` và Phase 10 B9
  `p10_b9_dev_full_001`, kiểm exact checksum;
- CodeQL CLI `2.26.2`, `codeql/java-all@9.2.2`;
- tối đa 10 specifications/project, 4 path/specification và 40 CodeQL query
  invocations/project trong differential mode;
- đúng một analysis iteration; thứ tự dừng là evidence threshold, budget, rồi
  no-new-evidence;
- zero LLM calls/tokens; verdict của LLM không có vai trò verifier;
- raw Phase 9/10 artifacts và mọi Phase 11 run là immutable.

Mỗi spec sinh hai query: endpoint inventory phân biệt descriptor không resolve
với resolved-but-no-path, và `path-problem` dùng `TaintTracking::Global` để lưu
full SARIF code flow. Sanitizer là barrier; propagator được thêm như explicit
flow step. Kết quả được materialize thành USEG iteration 1 mà không tạo cycle.

## 2. Trạng thái finding

| Trạng thái | Ý nghĩa |
|---|---|
| `VERIFIED_DIFFERENTIAL` | có vulnerable path và không có path với cùng spec ở fixed DB |
| `UNVERIFIED_FIXED_NOT_RUN` | có vulnerable path nhưng chưa chạy fixed DB |
| `UNVERIFIED_NO_VULNERABLE_PATH` | source/sink resolve nhưng CodeQL không tìm thấy path |
| `UNVERIFIED_UNRESOLVED_SOURCE` | source descriptor không resolve |
| `UNVERIFIED_UNRESOLVED_SINK` | sink descriptor không resolve |
| `UNVERIFIED_PERSISTS_FIXED` | path vẫn tồn tại ở fixed DB |
| `ANALYSIS_FAILED` | query/database/tool failure; intention-to-analyze miss |

Không trạng thái `UNVERIFIED_*` nào được báo thành final vulnerability finding.

## 3. Chạy vulnerable-only pilot

Pilot nhỏ nhất, không cần evaluator labels hoặc fixed database:

```bash
bash scripts/tools/run_phase11_verification.sh \
  --run-id p11_vuln_pilot_004 \
  --mode pilot \
  --verification-mode vulnerable-only \
  --project-id proj_7341ff37e347ec3be4ce \
  --spec-limit 1

bash scripts/tools/validate_phase11.sh \
  --run-root results/verification/phase11/p11_vuln_pilot_004
```

Tăng dần bằng cách bỏ `--spec-limit`, hoặc dùng `--limit N` thay
`--project-id`. Clean pilot 004 tại commit `8bdfcc7` đã pass với 1 spec/2
queries/zero LLM; spec đó resolve
5 source expressions nhưng không resolve sink nên được ghi rõ
`UNVERIFIED_UNRESOLVED_SINK`.

## 4. Chuẩn bị fixed-version databases

Bước này là evaluator-only vì cần đọc fix revision. Script chỉ chọn development
split, kiểm development/test disjointness, đọc upstream URL từ opaque vulnerable
checkout, khởi tạo checkout tạm và fetch đúng fixed revision, rồi chỉ persist DB
dưới opaque project ID. Nó không sửa vulnerable checkout và không persist commit
ID/identity mapping trong status/manifest.

Thử một project trước:

```bash
export MAXVERA_DATA_ROLE=evaluator
bash scripts/tools/prepare_phase11_fixed_databases.sh \
  --project-id proj_7341ff37e347ec3be4ce
unset MAXVERA_DATA_ROLE
```

Sau khi pilot build pass, build toàn bộ 78 development projects có B9 specs:

```bash
export MAXVERA_DATA_ROLE=evaluator
bash scripts/tools/prepare_phase11_fixed_databases.sh
unset MAXVERA_DATA_ROLE
```

Các build failure được giữ trong
`data/interim/phase11_fixed_codeql_databases/build_status.jsonl`; không được drop
khỏi denominator.

## 5. Chạy differential

Pilot một project đã có fixed DB:

```bash
bash scripts/tools/run_phase11_verification.sh \
  --run-id p11_diff_pilot_001 \
  --mode pilot \
  --verification-mode differential \
  --project-id proj_7341ff37e347ec3be4ce \
  --spec-limit 1

bash scripts/tools/validate_phase11.sh \
  --run-root results/verification/phase11/p11_diff_pilot_001
```

Full development run chỉ chạy từ clean commit và cấm `--limit`, `--project-id`,
`--spec-limit`:

```bash
bash scripts/tools/run_phase11_verification.sh \
  --run-id p11_diff_dev_full_001 \
  --mode full \
  --verification-mode differential

bash scripts/tools/validate_phase11.sh \
  --run-root results/verification/phase11/p11_diff_dev_full_001
```

Nếu tiến trình dừng, dùng lại cùng command và thêm `--resume`; nếu artifact final
đã tồn tại phải dùng run ID mới.

## 6. Output chính

```text
results/verification/phase11/<run-id>/
  manifest.json
  dependency_status.json
  fixed_database_preparation.json        # differential only, immutable snapshot
  fixed_database_build_status.jsonl      # differential only, immutable snapshot
  project_status.jsonl
  verification_results.jsonl
  taint_paths.jsonl
  negative_evidence.jsonl
  query_attempts.jsonl
  generated_queries/
  query_results/{vulnerable,fixed}/
  query_logs/{vulnerable,fixed}/
  useg_delta/{nodes,edges}.jsonl
  resource_usage.jsonl
  phase11_summary.json
  checksums.sha256
  STATUS
```

Phase 11 chưa được khóa chỉ vì vulnerable-only pilot pass. Canonical lock cần
fixed DB preparation hoàn tất, differential pilot pass, full run từ clean commit
và validator pass. `test_locked` vẫn đóng cho tới protocol final-experiment.

Differential pilot `p11_diff_pilot_002` tại clean commit `4705c03` đã pass với
immutable fixed-dependency snapshot: 1 spec, 4 query invocations, zero LLM. Cả
vulnerable/fixed database đều
resolve 5 source và 0 sink, nên kết quả đúng vẫn là
`UNVERIFIED_UNRESOLVED_SINK`, không phải verified finding.
