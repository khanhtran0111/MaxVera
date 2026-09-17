# Experiment Log

**Mục đích:** index các run và thay đổi vận hành; không lưu secret hoặc số liệu
chép tay.

| Date | Run/phase | Status | Pointer |
|---|---|---|---|
| 2026-08-26 | Phase 0 protocol 1.0.0 | frozen | `docs/00_*`, `docs/01_*` |
| 2026-08-26 | Phase 1 scaffold | implemented | repository commit/working tree |
| 2026-08-29 | Phase 2 data/build gate | passed | 104 DB success, 16 recorded failures |
| 2026-08-29 | Phase 3 smoke pass | passed/cleaned | endpoint through evaluator; 0 artifact |
| 2026-08-29 | Phase 3 injected failure | passed/cleaned | failed after analysis; 0 artifact |
| 2026-08-29 | Phase 4 one-project technical pilot | passed | B0/B1/B2, 120 statuses, all IRIS stages |
| 2026-09-01 | Protocol/model migration | implemented | GPT-OSS 20B/OpenRouter, protocol 1.1.0, D-009 |
| 2026-09-01 | Legacy Phase 4 full run | stopped/removed | tmux stopped; B2 full/pilot outputs moved to trash |
| 2026-09-01 | GPT-OSS pilot 001 | failed/diagnosed | filesystem-unsafe model ID and truncated 1,024-token JSON; D-010 |
| 2026-09-01 | GPT-OSS pilot 002 | passed | B0/B1/B2 validated; 4/4 LLM calls stopped normally; D-010 |
| 2026-09-02 | GPT-OSS full 001 | metrics generated; strict gate failed | 99 B2 successes, 5 analysis failures; run ID `phase4_gptoss20b_full_001` |
| 2026-09-03 | Phase 5 B3-B5 implementation | ready/offline-tested | controlled runner, budget estimator, evaluator and validator; no API run |
| 2026-09-03 | Phase 5 provider migration | configured/not run | AkashML route pinned, protocol 1.2.0, D-012; no API call |
| 2026-09-13 | Phase 5 pilot 1 project | passed | B3/B4/B5 analysis, evaluator và validator đều pass |
| 2026-09-13 | Phase 5 gate20 attempt 001 | B3 pass; B4 19/20 | B4 lặp hallucinated file path qua generic repair; B5 chưa chạy |
| 2026-09-13 | Phase 5 repair feedback | implemented | prompt v2, protocol 1.2.1, D-013; rerun bằng ID mới |
| 2026-09-13 | Phase 5 gate20 attempt 002 | B3 pass; B4 19/20 | validation feedback vẫn bị bỏ qua ở cùng path; B5 chưa chạy |
| 2026-09-13 | Phase 5 strict structured output | implemented | dynamic file enum, prompt v3, protocol 1.2.2, D-014 |
| 2026-09-13 | Phase 5 gate20 attempt 003 | B3 19/20 | one project exhausted four rapid HTTP 429 attempts; B4/B5 chưa chạy |
| 2026-09-13 | Phase 5 429 backoff | implemented | Retry-After/bounded 5–60s backoff, protocol 1.2.3, D-015 |
| 2026-09-13 | Phase 5 gate20 attempt 004 | passed | B3/B4/B5 20/20 success; evaluator/validator pass; API cost `$0.00791760` |
| 2026-09-13 | Phase 5 full budget-matched B3 | scientifically complete with one miss | run `p5_akashml_bm_full_001_b3`: 119 success, 1 `ANALYSIS_FAILED` after six HTTP 429 attempts; evaluator covers 120/120; API cost `$0.02110620` |
| 2026-09-13 | Phase 5 failure-accounting alignment | implemented | validator accepts fully recorded final failures as intention-to-analyze misses; suite continues B4/B5; D-016 |
| 2026-09-14 | Phase 5 full budget-matched suite | validated | B3 119/120, B4 119/120, B5 120/120; two final failures counted as misses; leaderboard generated; B3+B4 API cost `$0.04568004` |
| 2026-09-14 | Phase 6 implementation/pilot 003 | passed | development-only static/hybrid runner; static pilot analyzer/evaluator/validator 1/1, zero API calls; provenance signals compacted to referenced set; hybrid spend guard passed; protocol 1.3.0, D-017 |
| 2026-09-14 | Phase 6 static gate4 001 | passed | 4/4 development projects including corrected-revision checkout; Recall@1 0.75, Recall@3/5/10 1.0, MRR 0.8333; zero API calls |
| 2026-09-14 | Phase 6 static v1 full 001 | validated | 96/96 development projects; Recall@1/3/5/10 0.3333/0.4479/0.5208/0.5625, MRR 0.4020; candidate pool contains the correct CWE for 68/96; zero API calls |
| 2026-09-14 | Phase 6 family-balanced ranking v2 gate4 001 | passed | 4/4 development projects; candidate-pool Recall@40 1.0, Top-10 Recall@10 1.0, MRR 0.875; zero API calls; v1 artifact preserved; protocol 1.3.1, D-018 |
| 2026-09-14 | Phase 6 static v2 full 001 | selected/locked | 96/96 success; Recall@1/3/5/10 32/79/84/84 (0.3333/0.8229/0.8750/0.8750), MRR 0.5547; candidate-pool Recall@40 84/96 and MRR 0.5547; 30 Top-10 gains and zero regressions versus v1; 12 pool misses; zero API calls; D-019 |
| 2026-09-14 | Phase 7 Program Graph implementation | implemented/pilot passed | CodeQL source-backed nodes and seven edge kinds; deterministic IDs/digests, database alias/builder, integrity validator and bounded neighborhood/slice query; protocol 1.4.0, D-020 |
| 2026-09-14 | Phase 7 pilot 001 | failed/diagnosed | decoded node CSV used inconsistent column prefixes; stopped before graph finalization, zero API calls; schema corrected for pilot 002 |
| 2026-09-14 | Phase 7 pilot 002 | failed/diagnosed | unbounded all-Expr/Stmt graph reached 1,008,798 nodes and 1,602,982 edges on one project, exceeding cap; extractor narrowed to security-relevant source-backed nodes for pilot 003; zero API calls |
| 2026-09-14 | Phase 7 pilot 003 | failed/diagnosed | repository-wide security-relevant graph still reached 583,701 nodes and 913,250 edges; scope changed to locked Phase 6 hypothesis files plus one adjacent edge endpoint for pilot 004; zero API calls |
| 2026-09-14 | Phase 7 pilots 004/005 | passed/deterministic | same development project produced 699 nodes, 868 edges across all seven edge kinds, 100% edge resolution and identical graph digest `14fb1a2...c346`; peak runner RSS about 89 MiB; neighborhood query passed; zero API calls |
| 2026-09-14 | Phase 7 gate2 002 | passed with recorded failure | 2/2 final statuses: one expected missing-database miss and one successful 699-node/868-edge graph; validator reports 868/868 edge references (100%); zero API calls |
| 2026-09-15 | Phase 7 full 001 | completed/not lockable | 96/96 final statuses and checksums valid; 14 missing-database failures, one edge-query timeout, 80 non-empty valid graphs, and one empty graph incorrectly classified as `SUCCESS`; validator correctly rejected the run; zero API calls |
| 2026-09-15 | Phase 7 full 002 | completed/not lockable | substantive graph/status counts repeat full 001 because the empty-graph runner bug was not patched before rerun; the formerly timed-out database instead failed from an overlapping CodeQL cache lock left by an orphan query process; checksums pass, validator rejects the same zero-node `SUCCESS`; zero API calls |
| 2026-09-15 | Phase 7 failure hardening/pilot | implemented/passed | zero-node graph becomes recorded `ANALYSIS_FAILED`; timed-out CodeQL commands terminate their process group and persist timeout logs; active database cache locks fail early; orphan from full 001 stopped and lock released; regression pilot validates as `PASS_WITH_ANALYSIS_FAILURES`; D-021 |
| 2026-09-16 | Phase 7 full 003 | completed/not lockable | intended 80 success/16 recorded failures and checksums pass, but validator found 52 invalid node spans across five successful projects: 38 reversed ranges and 14 ranges beyond their persisted source file; diagnosed as independent multi-location getter bindings in QL; zero API calls |
| 2026-09-16 | Phase 7 location-binding repair/pilots | implemented/passed | node/edge QL binds one `Location` per descriptor; runner validates each project graph before `SUCCESS`; all five formerly affected projects pass validator, totaling 22,400 nodes/35,354 edges with 100% edge resolution; D-022 |
| 2026-09-16 | Phase 7 full 004 | selected/locked | 96/96 final statuses; 81 graph successes, 14 missing-database misses and one zero-node miss; 275,674 nodes, 442,786 edges, 100% resolved references; checksums and validator pass; clean commit `13a6016`; zero API calls; D-023 |
| 2026-09-17 | Phase 8 pilot 001 | passed/diagnostic | full public-source parse pass with 6,117 nodes/9,467 edges; audit exposed that upstream generated-only CodeQL models were still admitted, so policy was tightened before selection |
| 2026-09-17 | Phase 8 pilot 002 | passed | reviewed-provenance-only API policy; 2,619 nodes/5,285 edges, 7,904 deterministic facts, four CWE audits pass, zero inferred facts/LLM calls |
| 2026-09-17 | Phase 8 full 001 | validated candidate/not locked | `p8_skg_global_full_001`; graph digest matches pilot 002; exact source/dependency checksums and validator pass; manifest records dirty working tree, so canonical lock awaits a clean commit/reproduction run |
| 2026-09-17 | Phase 8 full 002 | selected/locked | `p8_skg_global_full_002`; clean commit `50ed53e`; 2,619 nodes/5,285 edges, 7,904 deterministic facts, zero inferred facts/LLM calls; digest reproduces pilot 002/full 001; provenance, checksum, dependencies and four-CWE audit pass; D-025 |
| 2026-09-17 | Phase 9 pilot 001/failure pilot 001 | passed | positive project: 82 nodes/159 edges and one fully traceable candidate path; Phase 7 failure project remains a recorded `ANALYSIS_FAILED` with no placeholder graph |
| 2026-09-17 | Phase 9 pilot 002 | passed | four successful projects: 355 nodes/683 edges, 21/21 candidate paths trace Program and Security layers, zero cycles, lossless round-trip |
| 2026-09-17 | Phase 9 full 001 | validated candidate/not locked | `p9_useg_dev_full_001`; 81/96 successful and 15 inherited misses; 7,527 nodes/16,398 edges, 823/823 candidate paths fully traceable, zero cycles, lossless round-trip, zero LLM/network calls; manifest is dirty, so clean reproduction run remains required |
| 2026-09-17 | Phase 9 full 002 | validated diagnostic/not locked | `p9_useg_dev_full_002`; substantive graph and audit results reproduce full 001, but the run was started while Phase 9 changes were staged and its manifest records a dirty worktree; artifact remains immutable and is not used downstream |
| 2026-09-17 | Phase 9 full 003 | selected/locked | `p9_useg_dev_full_003`; clean commit `2395d21`; 81/96 successful and 15 inherited misses; 7,527 nodes/16,398 edges, 823/823 candidate paths fully traceable, zero cycles, lossless round-trip, zero LLM/network calls; graph digest reproduces full 001/002; D-027 |
| 2026-09-17 | Phase 10 B6-B9 dry 006 | passed | four one-project dry-runs validate exact Phase 9 lock, deterministic strategy-specific retrieval, compact-context plus strict-schema token caps and zero network/API calls; endpoint preflight reports B6/B7 8/10 and B8/B9 10/10 API-eligible contexts, maximum conservative request estimate 7,469/8,192 tokens, with ineligible contexts required to fail before any call; generated specification/compile paths remain unexecuted until an explicitly authorized API pilot; D-028 |
| 2026-09-17 | Phase 10 B9 pilot 001 | diagnosed/not locked | one project, 7/10 grounded specifications and 7/7 final queries compiled for $0.00092432; three CWE-78 calls failed at HTTP 400 because optional zero-candidate roles emitted an invalid empty JSON-Schema enum; no token, grounding or compile failure; schema fix required a new immutable pilot ID |
| 2026-09-17 | Phase 10 B6-B9 dry 007 | passed | post-fix offline reproduction; strict schemas contain no empty enum, all four strategies reproduce from canonical Phase 9, B9 remains 10/10 API-eligible, request estimates remain below 8,192 tokens and no network/API call occurred |
| 2026-09-17 | Phase 10 B9 pilot 002 | passed/not locked | one development project, 10/10 grounded specifications and 10/10 final queries compiled; 49,540 input tokens, 3,892 billed output tokens, $0.00138; three transient AkashML HTTP 429 retries all recovered, zero failed calls/fallbacks, max prompt 6,167/8,192 tokens; dirty implementation manifest means pilot only, not canonical |
| 2026-09-17 | Phase 10 B6 pilot 001 | accepted with expected analysis failures/not locked | one development project, 8/10 grounded specifications and 8/8 final queries compiled for $0.00043732; two hypotheses had no grounded Program-layer source and failed before API, exactly matching dry-run preflight; zero API failure/retry/fallback |
| 2026-09-17 | Phase 10 B7 pilot 001 | accepted with expected analysis failures/not locked | one development project, 8/10 grounded specifications and 8/8 final queries compiled for $0.0011979; two hypotheses had no grounded Security-layer source and failed before API, exactly matching dry-run preflight; two transient HTTP 429 retries recovered, zero failed calls/fallbacks |
| 2026-09-17 | Phase 10 B8 pilot 001 | passed/not locked | one development project, 10/10 grounded specifications and 10/10 final queries compiled for $0.00125018; two transient HTTP 429 retries recovered, zero failed calls/fallbacks; unpruned retrieval remained within the shared request-token cap |
| 2026-09-17 | Phase 10 B6-B9 full dry 001 | diagnosed/superseded | all 96 statuses and 806 contexts/baseline reproduced with zero API calls, but whole-request preflight found 1/49/86/3 over-budget contexts for B6/B7/B8/B9 respectively; fail-closed prevented calls, but implementation was extended with deterministic adaptive context serialization before any full API run |
| 2026-09-17 | Phase 10 B6-B9 full dry 002 | passed | post-adaptation full development preflight over 96 statuses and 806 contexts/baseline; B6/B7/B8/B9 adapted 1/49/86/3 contexts, left zero whole-request overflow and reported 763/619/801/801 API-eligible contexts; remaining ineligible contexts have no grounded source in the selected ablation/subgraph, and all dry artifacts record zero network/API calls |

Các smoke run đã bị cleanup theo protocol. Pilot dùng backend trước protocol
1.1.0 chỉ là kiểm tra kỹ thuật và đã bị xóa cùng partial full run; không số liệu
legacy nào được dùng.
Pilot 002 là kiểm tra kỹ thuật một database, không phải scientific result. Full
GPT-OSS 20B run 001 đã có metrics intention-to-analyze trên đủ 120 status; 5/104
B2 analysis failures được tính là miss nên strict all-success gate chưa pass.

## Phase 7 full 001 failure analysis

Run `p7_pg_dev_full_001` hoàn tất đủ 96 project và artifact checksum pass, nhưng
không được chọn hoặc khóa làm kết quả Phase 7 vì validator phát hiện
`proj_2b679a12fa55f6c07bae` có `nodes=0`, `edges=0` nhưng runner lại ghi
`SUCCESS`. Đây là lỗi phân loại trạng thái của implementation, không phải bằng
chứng rằng project không có lỗ hổng. Runner phải chuyển mọi graph không có node
thành `ANALYSIS_FAILED`, sau đó full run phải dùng run ID mới; không sửa hậu kỳ
artifact immutable này.

Các failure mode quan sát được trong run:

- 14 project không có CodeQL database sau các build attempt đã pin. Log cho thấy
  các nguyên nhân gồm snapshot/parent artifact không còn tồn tại, repository cũ
  không phân giải hoặc bị Maven HTTP blocker, dependency/cache JAR lỗi, frontend
  hoặc code-generation task thất bại, và Maven/Gradle/JDK không tương thích.
- `proj_885aa60aedd0b17be65a` vượt timeout 1.800 giây khi chạy edge query. Đây là
  analysis failure hợp lệ và phải được giữ làm intention-to-analyze miss.
- `proj_2b679a12fa55f6c07bae` có bảy seed files nhưng node và edge query đều trả
  kết quả rỗng. Khả năng kỹ thuật gồm database chỉ compile một phần module,
  source path trong database không khớp seed path, hoặc query không nhận diện
  source entity tương ứng. Trường hợp này cũng phải là intention-to-analyze miss.

Do đó, cách đọc đúng run này là 80 graph không rỗng và 16 analysis misses về mặt
ngữ nghĩa, dù `status_summary.json` cũ ghi 81 `SUCCESS` và 15
`ANALYSIS_FAILED`. Failure không được loại khỏi mẫu, không được coi là negative
finding, và không được dùng để suy luận rằng repository không có vulnerability.
Artifact nguồn gồm `project_status.jsonl`, `graph_summary.json`, các per-project
query log và `data/interim/phase7_database_build_status.jsonl`.

Run `p7_pg_dev_full_002` không khắc phục lỗi trên vì code runner vẫn chưa có
zero-node guard. Run tạo cùng 274.547 nodes, 441.719 edges và cùng phân bố trạng
thái/node/edge theo project như full 001, nên cũng không được chọn hoặc khóa.
Ngoài ra, `proj_885aa60aedd0b17be65a` đổi từ edge-query timeout ở full 001 sang
nodes-query exit 2: CodeQL báo IMB disk cache đang bị khóa bởi process khác tại
database này. Kiểm tra process cho thấy query Java con của lần timeout trước vẫn
chạy với parent PID 1. Đây là failure mode vận hành riêng: timeout handler phải
chấm dứt cả process group, và preflight trước rerun phải phát hiện query mồ côi
hoặc database cache lock đang được giữ. Không được xóa lock file khi process vẫn
còn sống.

Sau D-021, regression pilot `p7_pg_zero_guard_pilot_001` chạy trực tiếp trên
`proj_2b679a12fa55f6c07bae`, ghi đúng một final `ANALYSIS_FAILED` với reason
`Phase 7 graph has no nodes after seed filtering`, và validator trả
`PASS_WITH_ANALYSIS_FAILURES`. Pilot dương
`p7_pg_failure_hardening_pilot_001` vẫn tạo đúng 699 nodes/868 edges với 100%
edge reference và validator `PASS`. Đây chỉ là implementation regression pilot,
không run nào được nhập vào full-run metrics.

Full 003 `p7_pg_dev_full_003` đạt đúng 80 `SUCCESS` và 16
`ANALYSIS_FAILED`, nhưng chưa hợp lệ để khóa. Validator phát hiện 52 node location
không hợp lệ trên năm project: 38 span có end line nhỏ hơn start line và 14 span
vượt quá số dòng của file được ghi trong node. Root cause là một CodeQL element
có thể có nhiều `Location`, trong khi query cũ gọi độc lập `getFile()` và nhiều
lần `getLocation()` trong cùng select tuple; QL vì vậy ghép chéo file/start/end
từ các location khác nhau của cùng element, đặc biệt ở repository có duplicate
class giữa nhiều module. Artifact full 003 giữ immutable làm diagnosed attempt.

Sau D-022, node và hai edge endpoint đều bind một biến `Location` duy nhất trước
khi đọc file/start/end. Runner cũng gọi per-project integrity validator trước khi
ghi `SUCCESS`, nên location lỗi tương lai trở thành recorded
`ANALYSIS_FAILED` thay vì làm full artifact không validate được. Regression
pilots trên cả năm project từng có invalid nodes đều validator `PASS`, tổng cộng
22.400 nodes/35.354 edges hợp lệ với 100% edge resolution; các pilot không được
nhập vào full-run metrics.
