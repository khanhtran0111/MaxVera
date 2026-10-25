# Full research pipeline enablement — 24/10/2026

Đã nâng cấp đường chuẩn bị và chạy research trên branch hiện tại
`refactor/pipeline-first-v2`, giữ công việc trước đó. **Source/recipe đủ 120/120;
full benchmark chưa chạy.** Hướng dẫn vận hành ở
[full runbook](research_full_runbook_2026-10-24.md).

## Trạng thái được kiểm chứng

| Điều kiện | Kết quả mới |
|---|---|
| Manifest và snapshots chuẩn bị | 120/120, không case preparation thất bại |
| Audit exact Git objects | 120/120; 370.676 Java và 14.498 build inputs; không thiếu file trong phạm vi audit |
| Full `graph_only` execution preflight | `execution_ready=true`, `--require execution` exit 0 |
| Truth aligned | Pilot 6/10; full 6/120 |
| Scientific approval | False; confirmatory acceptance chưa đạt |
| Default tests | **712 passed, 5 skipped**, 33,57 giây |
| CodeQL thật | **2 passed**, 237,14 giây; gồm CLI v2/resume và exact SARIF verification |
| Ruff / mypy / diff check | Pass; mypy kiểm 126 configured `src` files |
| Frozen runs/evaluations cũ | Cả 7 checksum inventories được xác minh nguyên vẹn |
| Offline preparation resume | 120/120 reuse; 121 source seals/manifest không đổi; 0 fetch/model call |

Các byte khác Git blob đã được audit phân loại: 8.796 Java có Git `$Id$`
expansion, năm build inputs có CRLF conversion và tám build inputs đúng kết quả
pinned upstream build patch. Không có byte difference chưa phân loại trong audit
mới. Đây là xác minh source preparation, không phải chứng minh mọi project build
được hay mọi source commit upstream ghi nhãn là vulnerable đều đúng.

## Các sửa đổi thực chất

1. **Chuẩn bị toàn cohort bằng CLI.** `dataset prepare --sources --view` xác minh
   frozen release, fetch exact commit vào Git object cache, áp dụng pinned build
   patch và ghi immutable source view. Chạy lại cùng lệnh để resume; `--offline`
   chỉ dùng nguồn/cache đã có. Không ghi lại canonical release hoặc snapshot cũ.
   Git timeout kết thúc process group và chỉ dọn lock do chính fetch đó tạo.
2. **Giữ đủ tracked source.** Audit phát hiện policy cũ loại nhầm 223 Java và ba
   build XML inputs ở 12 case do tên thư mục `build/target/classes`. Policy
   `pinned-git-archive-normalized-v2` giữ các inputs đó qua archive, inventory và
   private build copy. View cũ không bị chỉnh sửa hay reseal.
3. **Chuẩn hóa không lộ oracle metadata.** Alias nội bộ không chứa Java được
   materialize khi target hợp lệ; test-resource links không được follow.
   Advisory documents mang CVE trong tên và patch/diff resources được loại theo
   policy chung, kèm trusted transformation receipt. Analyzer chỉ nhận summary
   count/digest; raw paths/targets ở trusted logs. Java/executable path không thể
   chuẩn hóa an toàn vẫn thất bại rõ ràng.
4. **Build và tài nguyên.** Gradle cài sẵn và wrapper đều `clean build -x test`,
   để lượt build dưới CodeQL thực sự compile. CSV graph được giới hạn khi đọc;
   subprocess output dùng bounded redacted streaming. Disk reserve mặc định
   20 GiB được kiểm trước stage và trong command; process group bị dừng nếu vượt
   reserve/deadline. Mọi case vẫn có terminal accounting khi có lỗi.
   Nếu extraction bị dừng vì tài nguyên sau ingest, evaluator vẫn xác minh frozen
   input và tính known-truth case đó là analysis failure/recall zero; không bỏ khỏi
   evaluable denominator. Hai regression mới kiểm cả workspace nguyên và bị sửa.
5. **Execution và khoa học được báo riêng.** Preflight có `execution_ready`,
   `evaluation_ready`, `scientific_approved`; `--require execution` chọn gate cho
   exit code và giữ nguyên báo cáo tổng hợp. Flag này không cấp quyền vượt guard
   của pipeline.
6. **Prospective exploratory protocol.** Sau actual paired fixed-pilot
   `static_only`/`graph_only` measurements và review, `experiment register` có thể
   freeze một full exploratory run. Protocol bind đủ selection, source, code,
   config, executable/runtime trees, effective model parameters và development
   evaluations; credentials không được lưu. Điều kiện evaluator được recompute
   từ frozen run, đối chiếu aggregate/per-case accounting. Đây là amendment cho
   thí nghiệm có thể cho kết quả âm theo mục tiêu gốc, giữ
   `graph_signal_approved=false`; không phải scientific approval.

Các P1 về source omission, oracle receipt, evaluator-condition binding và runtime
identity đều được tái lập bằng RED trước sửa. Review độc lập cuối không còn
confirmed blocker trong phạm vi các sửa đổi;
`logs/research_full_enablement_20261024/review_final_scoped.md` ghi scope và giới hạn.

## Input, mapping và lệnh chạy

View mới:
`data/processed/analysis_input/full_20261024_v2/D_extended_projects.csv`.
Hai profiles là `research_full120_execution.yaml` và
`research_pilot10_execution.yaml`; cả hai dùng runtime_fast/Groq và giữ approval
false. Pilot giữ nguyên mười IDs, development/locked split không đổi.

Mapping v3 ở
`data/processed/evaluator_only/full_20261024_v2/reviewed_pilot_alignment_v3.json`.
Nó chỉ rebind inventory sau khi kiểm đúng commit và byte/range của 55 mapped
targets; giữ nguyên 67 rows, 55 mapped/12 unresolved, target/status/reason/reviewer.
Không tạo adjudication mới. Root đã kiểm riêng equality các nonidentity fields;
old evidence được copy byte-for-byte. Whole-cohort recall vẫn phải `null` khi
truth chưa đủ.

Kiểm tra execution readiness hiện tại:

```bash
.venv/bin/python -m maxvera preflight \
  --config configs/pipelines/research_full120_execution.yaml \
  --variant graph_only --mode full --require execution \
  --truth-alignment data/processed/evaluator_only/full_20261024_v2/reviewed_pilot_alignment_v3.json
```

Lệnh trên đã chạy exit 0: source/recipe 120/120, execution ready, evaluation chưa
ready. `static_only` và `graph_only` có thể chạy full với profile này. Với đầy đủ
LLM/verification, thực hiện paired development measurements, register protocol
và chạy `graph_llm_verify --experiment-protocol ... --execute` theo runbook.
Không cần bật approval thành true để giả kết quả review.

Dry-run full `graph_llm_verify` đã resolve đủ 120 case và chín stage. Ngưỡng cấu
hình là tối đa 3.600 calls/$120 toàn cohort, 7.200 giây/case; đây là stop threshold,
không phải prepaid cap. Không có model API call hoặc paid full120 execution trong
đợt enablement này. Actual paired pilot và benchmark là các lượt chạy tiếp theo
của operator, không được báo là đã hoàn tất.

## Bằng chứng và kiểm chứng

Trong `logs/research_full_enablement_20261024/`:

- `source_inventory_audit.json` và `source_inventory_audit_v2.json`: so sánh old
  view/new view với exact Git objects và phân loại byte transformations.
- `full_preparation_v2.log`, cùng
  `logs/source_preparation/full_20261024_v2/status.json`: đủ 120 preparations.
- `full120_execution_gate.json`: readiness đã chạy với `--require execution`.
- `full120_resolved_dry_run.json`: selection, DAG, budgets và resolved config.
- `default_suite_final.log`, `actual_v2_codeql_checks.log`: kết quả test mới.
- `truth_rebinding/`: audit/rebinding script, receipt, independent field check
  và pilot preflight; frozen evaluator artifact có checksum riêng.
- `preserved_artifacts.json`: full verification bảy frozen inventories cũ.
- `preparation_offline_resume_receipt.json`: 120 verified reuses, không đổi source
  seals hay full manifest, không fetch/model call mới.
- `initial_state.json`, `initial_dirty_files.tar.gz`, `initial_tracked.patch`:
  trạng thái khi bắt đầu; diff bàn giao giữ cả công việc trước đó.

CodeQL CLI fixture thật kiểm build/trích xuất/graph/candidates trong Landlock,
tracked Java trong package `build`, source không đổi, evaluator sentinel không
đổi, same-identity resume giữ nguyên frozen checksums và không có model call.
Fixture này dùng `graph_only`; LLM và targeted verification không bật trong lượt
CLI đó, nên không dùng nó làm bằng chứng full LLM benchmark.
SARIF fixture kiểm endpoint UTF-16, exact unique binding, modeled flow và giữ
unsupported khi không bind được. Các fixtures không phải benchmark results.

Chưa commit/push. Không xóa artifact, đổi pinned `third_party`, sửa nhãn gốc,
giảm cohort hoặc chạy lại IRIS reproduction.
