# Experiment Log

**Mục đích:** index các run và thay đổi vận hành; không lưu secret hoặc số liệu
chép tay.

## Development audit cho pipeline v2 (2026-10-05)

Run `p6_p10_dev_audit_v2_001`, scope 96 development projects, diagnostic-only.
Entrypoint `src.experiments.development_audit`, config design-only
`configs/experiments/pipeline_v2.yaml`. Output tại
`results/audits/p6_p10_dev_audit_v2_001/`: summary, 1.398 observation records,
input file hashes, manifest và checksum index. Mọi input trong tám historical
development runs có checksum coverage hợp lệ và không đổi trước/sau audit;
zero LLM/CodeQL calls, không mở raw evaluator labels hoặc test artifacts.

Các số liệu được tính từ input records: Phase 6 có 251/956 hypotheses thiếu
source; Phase 9 có 238/806 hypotheses thiếu source gốc và 197 source/sink
assertions không map Program; B9 có 233/801 specifications từ hypothesis thiếu
source. Cached annotated evaluator B9 có 254/762 CWE-correct và 14 fix-location
proxy matches. Nonmatching proxy không được coi là false positive.

D-038 và `docs/19_PIPELINE_V2_RESTART.md` ghi thiết kế/gates và disposition
corrective/incomplete cho Phase 13 cũ bên ngoài immutable run. Không chạy lại
pipeline hoặc triển khai Phase 6–11 v2/v3 trong lượt audit này. Kiểm tra audit
runner: 5 unit tests pass; full suite 152 tests pass; `ruff check .`, `mypy src`
(103 source files) và `git diff --check` pass. Checksum output audit được kiểm
tra độc lập sau finalization.

## Historical run index

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
| 2026-09-18 | Phase 10 B9 adaptive pilot 001 | passed/not locked | clean commit `e3ddccf`; targeted `proj_aff72cca32a2f43c0147` exercised adaptive serialization on `hyp_f0eef19181ba14128564` (context budget 4,854→4,701); 10/10 grounded specs and final queries compiled, actual adapted prompt 5,201 tokens, project max 6,092/8,192, zero retry/failure/fallback, $0.0013405; full development runs are now permitted |
| 2026-09-18 | Phase 10 B6–B9 full development 001 | validated/selected | clean commit `184fef1`; B6/B7/B8/B9 have 54/34/78/78 project successes and 763/619/801/801 grounded specifications; all final queries compile; every run has 96 final statuses and validator `PASS_WITH_ANALYSIS_FAILURES`; failures remain intention-to-analyze misses |
| 2026-09-20 | Phase 10 annotated spec gate 003 | passed/selected | evaluator-only clean run at `6117b00`; 91 development projects have fix-location annotations and 5 are explicitly unannotated; B9 has 14/762 paper-compatible proxy-positive specs and detects 6/91 projects; proxy is not static verification; aggregate reproduced byte-identically across diagnostic runs; D-029 |
| 2026-09-20 | Phase 10 lock | locked | full B6–B9 run IDs and evaluator checksums pinned in `configs/experiments/main.yaml`; development synthesis is frozen for Phase 11; protocol remains 1.7.0; D-029 |
| 2026-09-20 | Phase 11 vulnerable-only pilot 001 | rejected | CodeQL execution succeeded, but independent validator found a USEG cycle across TAINT_PATH → HYPOTHESIS → VERIFICATION_RESULT → TAINT_PATH; immutable diagnostic retained and edge materialization corrected |
| 2026-09-20 | Phase 11 vulnerable-only pilot 003 | passed/diagnostic | one B9 spec on `proj_7341ff37e347ec3be4ce`; 2 CodeQL queries, zero LLM calls/tokens; source resolved to 5 expressions, sink resolved to 0, final state `UNVERIFIED_UNRESOLVED_SINK`; validator pass after acyclic USEG update and exact query-attempt accounting |
| 2026-09-20 | Phase 11 fixed DB pilot | passed | evaluator-only preparation fetched the development fixed revision into an isolated temporary checkout and built one opaque CodeQL database; vulnerable checkout unchanged, no identity/fix commit persisted in analyzer artifacts |
| 2026-09-20 | Phase 11 vulnerable-only pilot 004 | passed/clean | clean implementation commit `8bdfcc7`; one B9 spec, 2 query invocations, zero LLM calls/tokens, explicit `UNVERIFIED_UNRESOLVED_SINK`; independent validator pass |
| 2026-09-20 | Phase 11 differential pilot 001 | passed/clean | same clean commit and frozen spec over vulnerable/fixed databases; 4 query invocations, both versions resolve 5 sources/0 sinks, zero paths and explicit `UNVERIFIED_UNRESOLVED_SINK`; zero LLM; independent validator pass; full fixed DB preparation remains before full run |
| 2026-09-20 | Phase 11 differential pilot 002 | passed/selected pilot | clean hardening commit `4705c03`; same 1-spec/4-query result as pilot 001, plus immutable in-run fixed preparation/status snapshots so later database preparation cannot invalidate provenance; validator pass; full run remains pending |
| 2026-09-21 | Phase 11 differential full 001 | validated diagnostic/not locked | clean commit `9f3026e`; 96/96 final project statuses, 65 successes and 31 intention-to-analyze failures; 656 final specification states, 23 `VERIFIED_DIFFERENTIAL`; validator `PASS_WITH_ANALYSIS_FAILURES`; 12 fixed databases were still unavailable, so recovery continued under a new immutable run ID |
| 2026-09-22 | Phase 7 failed-project recovery pilots | passed/not locked | all 14 formerly missing development DBs built in an isolated pilot root with 100% Phase 6 seed-file node coverage; the 14 projects plus the formerly empty Spring graph each passed a separate Phase 7 graph validator (15/15, 50,275 nodes, 78,191 edges, 100% edge references); no canonical Phase 7 or downstream lock was changed |
| 2026-09-22 | Phase 11 fixed DB recovery | passed | all 12 remaining fixed revisions produced validated Java CodeQL databases with `build-mode=none` after ordinary builds failed; acceptance required non-empty Java nodes and Phase 10 endpoint-file coverage; full fixed preparation reached 78/78 with no locked-test preparation or persisted identity mapping |
| 2026-09-23 | Phase 11 differential full 002 | selected/locked | `p11_diff_dev_full_002` from clean commit `4b898bf`; 96/96 final project statuses, 78 successes and 18 inherited Phase 10 misses; 776 final specification states, 28 `VERIFIED_DIFFERENTIAL`, 748 explicit `UNVERIFIED_*`, 213 taint paths and 1,513 query invocations; zero LLM calls/tokens; checksums pass and validator returns `PASS_WITH_ANALYSIS_FAILURES`; D-032 |
| 2026-09-30 | Phase 11 lock gate | passed/locked | lock commit `faff962`; canonical checksum index reverified; Phase 11 validator returned `PASS_WITH_ANALYSIS_FAILURES`; Ruff pass, strict mypy pass on 85 source files, and full pytest 112/112 pass; canonical hashes and Phase 12 handoff pinned without opening `test_locked` |
| 2026-09-30 | Phase 12 calibration pilot 001 | passed/diagnostic | evaluator-only dirty-tree run over all 28 `VERIFIED_DIFFERENTIAL` findings (5 CWE-correct, 23 incorrect) in 8 repository groups; grouped OOF selected Platt with Brier 0.182758, ECE-width 0.237719 and AURC 0.966607; development could not support precision-0.8 auto-accept, so fail-closed `tau_accept=1.0`, 25 `VERIFY`, 3 `ABSTAIN`; zero LLM/network calls and validator pass under the pre-tier artifact contract; superseded by pilot 002 after explicit abstention-tier materialization; D-033 |
| 2026-09-30 | Phase 12 calibration pilot 002 | passed/diagnostic | post-tier dirty-tree pilot reproduced Platt and all metrics/thresholds byte-for-byte; routing materialized 25 `VERIFY`, 2 conservative `ABSTAIN`, 1 high-confidence `ABSTAIN`, zero `ACCEPT`; checksum-complete artifact and independent validator pass; clean-commit pilot remains required before full |
| 2026-09-30 | Phase 12 calibration pilot 003 | passed/selected pilot | clean commit `9fd1661`; reproduced all 28 rows, Platt metrics and fail-closed thresholds/decisions; 25 `VERIFY`, 3 `ABSTAIN`, zero `ACCEPT`; manifest records `locked_test_used=false`, checksum coverage and independent validator pass; full development run is permitted |
| 2026-09-30 | Phase 12 calibration full 001 | selected/locked | `p12_calibration_dev_full_001` from clean commit `581f0dc`, lock commit `faa06a1`; 28 differential findings (5 positive/23 negative) across 8 repository groups; grouped OOF selected Platt with Brier 0.182758, ECE-width 0.237719, ECE-mass 0.307860, AURC 0.966607; frozen thresholds route 0 `ACCEPT`, 25 `VERIFY`, 3 `ABSTAIN`; `locked_test_used=false`, zero LLM/network, checksums and validator pass; main config frozen for Phase 13; D-034 |
| 2026-09-30 | Phase 13 analyzer preflight + plumbing pilot | implementation validation | Preflight verified 24 disjoint opaque test IDs, 24 source aliases, CodeQL/OpenRouter readiness and exact Phase 12 model/threshold locks. One-project static Phase 6 plumbing pilot returned `PASS` without evaluator labels, LLM or network; its ignored output is not a paper/canonical run. Frozen retrieval/model/threshold semantics were unchanged; D-035. |

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

## 2026-10-05 — Triển khai development pipeline v2 và verifier v3 (D-039)

Người dùng cho phép tự động triển khai/chạy và dùng tmux cho phiên dài. Runner
riêng `src/pipeline_v2` và config `pipeline_v2_execution.yaml` đăng ký protocol
2.0.0; giữ toàn bộ historical artifact/config locks, test cũ diagnostic-only.
Chạy typed vulnerable endpoint inventory, candidate discovery, semantic endpoint/
callable graph, grounded USEG, precise B6–B9 role enums, frozen endpoint queries,
fail-closed semantic differential v3 và conditional group-aware calibration.

P6 pilot 001 phân tích thành công nhưng có 0 eligible hypotheses, giữ empty result
và downstream miss. Pilot 002/003 có 10 grounded hypotheses, graph và dry B6–B9
pass; B8 serialization ban đầu làm rơi role endpoints, đã sửa bằng cách giữ các
binding của hypothesis hiện tại trước context khác. Không gọi API trong plumbing.

Pilot 004 giữ compile failure của QL role-binding function; bản sửa chạy ở 005
và 006. Source return và consumption sink argument/receiver được mô tả riêng,
với target signature, exact source fingerprint, UTF-16 columns và source checksum.
Inventory/query select QL entity để không gộp các internal nodes có cùng descriptor;
ambiguous endpoint rows bị loại trước hypothesis selection và được lưu riêng.

Diagnostic verifier live `results/grounding/v3_query_dev_pilot_v2_001` đã resolve
vulnerable endpoints, tìm một path và trả UNVERIFIED_FIXED_ENDPOINT_MAPPING khi
mapping ambiguous. Diagnostic 002 chạy cả vulnerable/fixed endpoint/path queries
(5 invocations, 0 LLM), source/sink đều resolve và path vẫn còn ở fixed side:
UNVERIFIED_PERSISTS_FIXED. Không promote diagnostic thành scientific full output.

Full controller `dev_restart_v2_001` dùng IDs D-038: P6/7/9 → full development dry
B6–B9 → API pilot từng baseline → full → evaluator P11 v3 → conditional P12.
Tmux `maxvera-pipeline-v2-dev`, log `logs/pipeline_v2/development_full.log`; stage
progress/gate failures ghi trong controller artifact. Full chỉ sau clean local
implementation commit. Không chạy P13 hoặc claim confirmatory performance.
Calibration minima/target/routing được pin ở D-039 trước cohort/fitting.

Kiểm tra immutable checksums của tám historical development input runs đều PASS;
không sửa old result roots. Regression test timeout cho orphan process được sửa
để chờ tối đa 2s cho PID reaping sau SIGKILL, vẫn fail nếu child còn tồn tại.

Pilot 007 aggregate QL quá nặng được dừng, artifact giữ ANALYSIS_FAILED. Bản cuối
dùng BQRS JSON internal entity IDs, không gộp labels trùng và kiểm uniqueness xuyên
model bases trong Python. Pilot 008 có 10 hypotheses; graph và dry B6–B9 đều pass,
0 API. Internal numeric IDs chỉ dùng trong inventory để kiểm uniqueness, không
dùng như stable IDs hoặc cross-version mapping. Launcher có sẵn:
`bash scripts/tools/run_pipeline_v2_tmux.sh`; từ chối duplicate session/dirty
snapshot/completed controller, tự dùng --resume cho controller đang dở.

Validation cuối: 182 tests pass, Ruff toàn repo, mypy 113 source files,
`bash -n` launcher và `git diff --check` pass. Development full chưa tự khởi chạy
ở lượt hướng dẫn tmux; người dùng bắt đầu bằng launcher từ clean local snapshot.

## 2026-10-06 — Development recovery v2, D-040

Recovery config `pipeline_v2_recovery.yaml`; launcher
`scripts/tools/run_pipeline_v2_recovery_tmux.sh`; controller `dev_restart_v2_002`.
Historical controller001 giữ nguyên STOPPED_AT_GATE. Read-only audit xác nhận hai
P6 failures đều No space left on device; 14 missing DB đều có opaque source tree.
15 zero-hypothesis successes gồm 5 thiếu một/hai modeled roles, 10 có source/sink
nhưng không supported candidate relation. B6 pilot rejected request là upstream
HTTP429; chín specs trước đó đã resolve vulnerable endpoints. Không mở test/labels.

Recovery triển khai separate DB root/no-build provenance, science-compatible P6
inheritance, P10 exact context/schema/frozen binding revalidation và inherited API
reservations. Transient API giữ unfinished checkpoint/exit75, bounded cooldown;
nonretryable API/budget được tách khỏi grounding rejection. Pilots bắt buộc trước
full, full kế thừa pilot budgets. Query cache/debug cleanup sau mỗi project.

Validation trước launch: 187 tests pass, Ruff toàn repository pass, mypy 114 source
files pass, bash syntax và git diff checks pass. Snapshot/checksum của legacy P6,
B6 pilot và P9 đã xác minh; cả 10 legacy pilot context text/schema còn tương thích.
Actual vulnerable re-resolution của 9 inherited specs sẽ chạy trong pilot002 trước API.

Startup002 phát hiện no-build fallback minimal JDK vì chưa truyền toolchain environment;
đã ngắt trước API, giữ partial controller/preparation diagnostic. Snapshot003 sửa
JAVA_HOME/PATH từ pinned opaque source metadata; all14 pinned toolchains preflight pass.
Run configs/scripts002 giữ nguyên; active launcher sau freeze là
`run_pipeline_v2_recovery_003_tmux.sh`, controller `dev_restart_v2_003`. Cancellation
regression bảo đảm subprocess process group được terminate khi interrupt.

Validation snapshot003 trước launch: 189 tests pass (8.10s), Ruff toàn repo pass,
mypy 114 source files pass, bash syntax/diff checks pass. Legacy P6 và B6 pilot
scientific compatibility contracts đều PASS sau cancellation/toolchain fixes.

## 2026-10-08 — B9 v2 end-to-end plumbing and pilot budget correction (D-041)

Source snapshot `30f0b7b`: 198 tests, Ruff, mypy117files, shell/diff/smoke checks pass.
Full96 input preflight passes, zero API. Separate pinned AkashML connectivity probe
succeeds. Dedicated B9 controller skips unrelated B6–B8 full gates, selects actual
v2 synthesis cohort for fixed preparation and preserves partially failed specs.

`b9_e2e_dev_pilot_v2_004`: synthesis10/10, no grounding rejects/API fatal/budget
exhaustion; 10 successful calls plus eight recoveredHTTP429 attempts, 59,903 prompt
and3,881 completion tokens. Fixed preparation reuses one parent DB with hash provenance.
Verifier40 attempts yields9 UNVERIFIED_PERSISTS_FIXED and1 UNVERIFIED_QUERY_OR_BUDGET_FAILURE;
routing10 ABSTAIN, calibration/ACCEPT disabled. Controller correctly STOPPED_AT_GATE.
Do not treat this as an end-to-end pass, Full lock or vulnerability precision result.

Root cause: ten specs need41queries (4/spec plus fixed inventory), cap40unchanged.
Endpoint predicates are now batched per specification on each side; expected23queries
when all ten mappings resolve. Ambiguous entity rows, source/model semantics and
per-spec vulnerable/fixed paths remain mandatory. Regression covers all10specs within
40, checkpoint/hash isolation, ambiguity and rejection of changed synthesis prompts.
Pilot005 must inherit the immutable004 synthesis, recheck actual vulnerable resolution,
preserve every API reservation/call, then run verification/routing/independent validator.

Validation correction snapshot trước launch005: 202 tests pass (8.67s), Ruff toàn
repository, mypy117sourcefiles, shell syntax và git diff checks pass. Full96 input
preflight (zeroAPI) và compatibility check của actual004 synthesis đều PASS.

Actual pilot005 (`149041f`) completes15:29:25 Asia/Saigon, exit0; independent
controller validator PASS. One project/ten specifications, zero analysis misses;
P11 completes23query attempts, all ten UNVERIFIED_PERSISTS_FIXED, no query/budget
failures. P12 routes10 ABSTAIN, no calibrated probabilities or ACCEPT. No verified
vulnerability claim. Controller findings/report/operational metrics/development lock
and each stage have immutable manifests/checksums.

Ten inherited004responses and all ten reservations are unchanged; every HTTP call
record retains lineage, no new LLM HTTP attempt in005. Reported10successfulcalls,
eight429 and59,903/3,881tokens describe the inherited synthesis. Both actual endpoint
batches match all ten individual004query results, including internal QL entity IDs.
A final literal-preservation guard changes only declaration renaming; regenerating
both actual005batch queries gives byte-identical strings. Full96 not run, twelve
missing fixed DBs not yet built, calibration/ACCEPT and confirmatory gate remainclosed.
Final verification: 202 tests pass (8.81s), Ruff/mypy117files, diff/smoke assertion
pass; independent005validator PASS. All completed004stage checksums and parentfixed
preparation locks remain unchanged. Local commits only, no full96 launch.

## 2026-10-08 — Registered B9 all120 diagnostic comparison (D-042)

User requests all120cases for published-paper comparison. New registered benchmark
profile extends selection to exact96dev+24historicaltest without changing splits,
prompts/models/budgets or discovery/verification semantics. Test has diagnostic
disposition; fitting remains dev-only. No actual full120 result at registration.
Input preflight:120cases,119existing vulnerableDBs,120source repos,0APIcalls.
Evaluator uses patched-method path metric formulas and retains everycase, with
4variants and120/96/24breakouts; published Table1 reference is descriptive because
D_extended revisions/model/toolchain/zero-hint differ from original paper conditions.
Pre-launch checks:209tests (10.61s), Ruff/mypy120files, shell/diff/smoke PASS;
actual005synthesis compatibility PASS for both profiles; independent005validator PASS.

Trial b9_benchmark_120_v2_001 on0adfd50 started20:37:35+07, stopped beforeAPI atP6
because prior inherited_from collided with new lock. Inputs recorded119DBready and
1dirty-source rejection. Trial artifacts retained. Corrected forwarding and isolated
vulnerable checkout preserve parent source; checkpoint beforemove supports resume.
Next run002 reuses unchanged config/scientific inputs under new clean source snapshot.

## 2026-10-09 — B9 full120 pacing90s recovery (D-043)

User requests90s requestspacing and restart tmux. Register90s config +newrun003,
retain frozen partial002checkpoint247specs/24success/5failed/91pending and all
reservations/responses/terminalstates. Reuse9completed002input/upstream/dry/pilotstages
after lock/scientific checks. Model/provider and all analysis/LLM budgets unchanged;
interval15→90, mincontrollercooldown60→90, clientvalidationcap90. No retry-policy
relaxation or new holdout claim. Old artifacts and sourceconfigs unchanged.
Validation:216tests (12.34s), Ruff/mypy121files/shell/diff/smoke PASS; actual9stage
reuse and120/120DB90s preflight PASS with0APIcalls. Clean commit required beforelaunch.
