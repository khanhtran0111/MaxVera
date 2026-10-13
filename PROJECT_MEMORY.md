# MaxVera — Project Memory

> Cập nhật: 2026-10-08 (Asia/Saigon)
> Phase 11 canonical run commit:
> `4b898bfe9a3f16c494ec1942caf95f51e29db221`
> Phase 11 development lock commit:
> `faff962b48998ad6f2e596297f9b424810398be4`
> Phase 12 development lock commit:
> `faa06a1176320eb133d26a06c368d6181932fa16`
> Hiện trạng: Phase 0–12 giữ historical locks. Phase 13
> `p13_test_analysis_001` là corrective/incomplete; split đã dùng để debug
> verifier nên mọi rerun chỉ diagnostic. Development audit Phase 6–10
> `p6_p10_dev_audit_v2_001` đã hoàn tất; thiết kế pipeline v2/verifier v3 được
> ghi trong D-038. D-039 triển khai runner `src/pipeline_v2` protocol 2.0.0;
> full development chạy qua gated controller trong tmux, chưa có confirmatory v2.

## Mục đích và cách dùng

Đây là context nạp nhanh cho các lần chạy mới tiếp theo, không phải nhật ký đầy đủ. Chỉ giữ
các invariant, quyết định, mốc canonical, lỗi có ảnh hưởng downstream và handoff
hiện tại. Chi tiết nằm tại:

- `docs/06_EXPERIMENT_LOG.md`: diễn biến run và chẩn đoán;
- `docs/07_DECISION_LOG.md`: quyết định D-001 trở đi;
- runbook từng phase: quy trình vận hành;
- manifest/config/checksum của canonical run: nguồn có thẩm quyền cao nhất.

Thứ tự xử lý mâu thuẫn: canonical manifest/checksum → resolved config → decision
log → experiment log/runbook → file này → hội thoại.

### Tự cập nhật sau mỗi phase

Agent phải tự cập nhật file này trước khi báo phase hoàn tất, commit khóa hoặc
chuyển phase; người dùng không cần nhắc. Chỉ thêm:

1. trạng thái phase (`implemented`, `validated`, `locked` hoặc `blocked`);
2. quyết định/invariant mới ảnh hưởng các phase sau;
3. run ID, metrics chính và lock commit lấy từ artifact đã validate;
4. lỗi/giới hạn còn ảnh hưởng downstream;
5. handoff ngắn cho phase kế tiếp và Git snapshot mới.

Không chép toàn bộ log chạy. Nếu chưa có canonical run, ghi rõ blocker và không
tuyên bố phase đã khóa. Không ghi secret, API key, raw advisory hay label
evaluator-only.

## Snapshot hiện tại

| Hạng mục | Giá trị |
|---|---|
| Bài toán | Zero-hint, repository-level vulnerability research |
| Ngôn ngữ / static engine | Java / CodeQL |
| Protocol | Historical `1.9.0`; development execution v2 `2.0.0` (D-039), final pipeline lock sau full |
| Dataset chính | `D_extended`: 120 rows, 77 repository groups, 4 CWE |
| Development | 96 opaque projects |
| Test lịch sử | 24 opaque projects đã được dùng để debug verifier; diagnostic-only |
| Phase 6 lock | `p6_static_v2_dev_full_001`, static Top-10 |
| Phase 7 lock | `p7_pg_dev_full_004`, 81/96 graph success |
| Phase 8 lock | `p8_skg_global_full_002`, 2,619 nodes / 5,285 edges |
| Phase 9 lock | `p9_useg_dev_full_003`, 81/96 graph success |
| Phase 10 | Locked: B6–B9 full 001 + annotated gate 003 |
| Phase 11 lock | `p11_diff_dev_full_002`, 78/96 success, 28 differential verified |
| LLM cho run mới | `openai/gpt-oss-20b` qua OpenRouter/AkashML |
| CodeQL chính | CLI `2.26.2`, `codeql/java-all@9.2.2` |
| Phase 12 lock | `p12_calibration_dev_full_001`, Platt, 25 VERIFY / 3 ABSTAIN |
| Phase 13 | `p13_test_analysis_001`: corrective/incomplete; giữ nguyên artifacts |
| Audit development | `p6_p10_dev_audit_v2_001`: complete, zero API/CodeQL calls |
| Phase tiếp theo | Triển khai inventory/grounding Phase 6–7 v2 trên development |

Các Phase 6–12 rows phía trên là historical locks, không phải v2 locks.
`configs/experiments/main.yaml` đã `frozen` sau Phase 12 threshold lock. Phase 11
dùng historical protocol `1.8.0`; Phase 9/10 artifacts giữ contracts
`1.6.0`/`1.7.0`.

## Invariant không được phá

- Analyzer chỉ thấy source repository, opaque project ID và metadata build tối
  thiểu; không thấy CVE/CWE thật, advisory, patch/fix, identity mapping hay kết
  quả công bố.
- Split theo repository group. Holdout confirmatory mới phải chưa được dùng để
  tune/debug. Split `test_locked` lịch sử chỉ được rerun diagnostic; không dùng
  nó để chọn prompt, ranking, schema, knowledge hoặc threshold v2.
- Primary evaluation là intention-to-analyze: mọi selected project phải có final
  status; build/database/analysis failure tính là miss, không bị loại khỏi mẫu.
- Immutable run không sửa/overwrite. Rerun dùng run ID mới; resume chỉ dành cho
  `.inprogress` cùng implementation/config.
- Một project, một graph build và một LLM request chạy tuần tự; không chạy CodeQL
  và LLM đồng thời.
- B6–B9 phải fail-closed cho tới khi dependency thật tồn tại; không tạo kết quả
  placeholder.
- B1/B2 là oracle references, không phải fair zero-hint comparators.
- IRIS track chỉ được gọi **IRIS pipeline reproduction with GPT-OSS 20B via
  OpenRouter**, không claim exact/numerical reproduction.

## Technical contract

### Dataset

| Track | Upstream commit | Rows / groups / CWE |
|---|---|---|
| `D_repro_v1` | `698fb7248ae30cb7f7782d59c841f05ad70ea9cc` | 120 / 77 / 4 |
| `D_extended` | `afe0ebd0adc237abb46255f9cd479b1d71819136` | 120 / 77 / 4 |

`D_extended` hiện chỉ có CWE-22/78/79/94, không phải bộ 213 CVE/49 CWE từng
được upstream mô tả. Split development/test là 96/24.

Phase 2 đã tạo final build status cho 120/120: 104 CodeQL DB thành công, 11
`BUILD_FAILED`, 5 `CODEQL_DB_FAILED`.

### LLM runtime

- Model/route: `openai/gpt-oss-20b`, OpenRouter provider `akashml`;
- không provider fallback; temperature 0, top-p 1, seed 1234;
- strict Structured Outputs và validation cục bộ cho file/location;
- Phase 4 dùng Groq lịch sử; Phase 5+ dùng AkashML, nên không coi chênh lệch
  giữa hai phase là tác động retrieval thuần túy.

## Các mốc Phase 0–10

### Phase 0–3 — Nền tảng

- **Phase 0:** khóa scope Java/CodeQL, RQ1–RQ6, B0–B9, leakage firewall,
  metrics/statistical protocol và ba track reproduction/baseline/proposed.
- **Phase 1:** dựng scaffold reproducible, `uv`/Python 3.10, config/provenance,
  atomic immutable outputs và entrypoint B0–B9. Commit nền:
  `19dc32d Implement research protocol and Phase 1 scaffold`.
- **Phase 2:** materialize hai dataset, group split 80/20 bằng seed 1234, pinned
  toolchains, fetch/build/CodeQL DB; kết quả 104 success/16 recorded failures.
- **Phase 3:** disposable smoke trên 4 project, kiểm cả pass và injected failure;
  cleanup về 0 artifact. Smoke không được promote thành scientific result.

Quyết định nền tảng: D-001–D-007.

### Phase 4 — B0/B1/B2 và IRIS reproduction

Canonical: `phase4_gptoss20b_full_001`, chạy đủ 120 projects.

| Baseline | Analysis success | Detected | Macro F1 trên success |
|---|---:|---:|---:|
| B0 CodeQL zero-hint | 104 | 36 | 0.08383 |
| B1 CodeQL CWE-oracle | 104 | 21 | 0.13763 |
| B2 IRIS + GPT-OSS | 99 | 36 | 0.10931 |

Toolchain IRIS gốc không đọc được DB mới nên D-008 cho phép CodeQL 2.26.2;
GPT-OSS/OpenRouter thay model gốc. Đây là pipeline reproduction có substitution.
Commit: `cc3399c Complete Phase 4 reproduction with GPT-OSS 20B`.

### Phase 5 — Controlled baselines B3/B4/B5

Chạy trên `D_repro_v1` 120 rows để so cùng Phase 4; chưa phải main locked-test
claim. B3 raw/chunked LLM, B4 lexical text-RAG, B5 deterministic static.

| Baseline / run | Success | Detected | Recall ITA | Hyp R@10 | MRR |
|---|---:|---:|---:|---:|---:|
| B3 `p5_akashml_bm_full_001_b3` | 119/120 | 3 | .0250 | .0667 | .0583 |
| B4 `p5_akashml_bm_full_001_b4` | 119/120 | 11 | .0917 | .3833 | .3226 |
| B5 `p5_akashml_bm_full_001_b5` | 120/120 | 9 | .0750 | .8500 | .6076 |

Hai final HTTP 429 được giữ làm miss. Structured Outputs, validation-aware repair
và bounded Retry-After/backoff là các hardening chính (D-011–D-016).

### Phase 6 — Zero-hint hypothesis generation

Chạy development-only. Static v1 đạt R@10 `0.5625`; audit phát hiện ranking
lệch CWE-22. D-018 thêm family-balanced interleaving, không đổi candidate pool.

Canonical: `p6_static_v2_dev_full_001`, 96/96 success, deterministic static:

- Recall@1/3/5/10: `0.3333 / 0.8229 / 0.8750 / 0.8750`;
- MRR: `0.5546875`; candidate-pool Recall@40: `0.8750`;
- còn 12/96 candidate-pool misses;
- run commit `6483e10aaa59a63a0811900430dc16d8b174871c`, lock commit `cbdbf2e`.

### Phase 7 — Source-backed CodeQL Program Graph

Input là Phase 6 Top-10. Graph gồm `EXPR/STMT/CALLABLE/TYPE` và các edge
AST/CALL/DEF_USE/DATA_FLOW/CONTROL_DEP/TYPE/TAINT_CANDIDATE; scope bị bounded
bởi hypothesis files cộng một edge endpoint kề.

Các lỗi đáng nhớ vì ảnh hưởng implementation:

- zero-node phải là `ANALYSIS_FAILED`, không phải success;
- CodeQL timeout phải TERM/KILL toàn process group để không để orphan giữ DB lock;
- bind đúng một CodeQL `Location` cho toàn bộ file/start/end, tránh Cartesian
  location tạo reversed/out-of-range spans;
- runner phải validate integrity từng project trước khi ghi `SUCCESS`.

Full 001–003 chỉ là diagnostic, không dùng downstream. Canonical:
`p7_pg_dev_full_004` tại commit
`13a60162949b0a297b51050cccf6ed5cd4fbd241`:

- 96/96 final statuses; 81 `SUCCESS`, 15 `ANALYSIS_FAILED`;
- 15 misses = 14 missing DB + 1 graph rỗng sau seed filtering;
- 275,674 nodes; 442,786 edges; 100% edge references resolved;
- validator: `PASS_WITH_ANALYSIS_FAILURES`; static analysis only;
- lock commit `cef6a01` (D-023).

`STATUS=FAILED` của run là đúng do còn 15 misses; validator pass và đủ 96 final
statuses mới là gate authoritative.

### Phase 8 — Global Security Knowledge Graph

D-024 khóa một KG toàn cục, versioned và build offline; scope là bốn root CWE
22/78/79/94 cộng closure một hop theo quan hệ incident của MITRE CWE view 1000.
Nguồn preparation đã pin checksum và license:

- MITRE CWE `4.20` XML và CWE Terms of Use;
- OWASP Top 10:2021 tại commit
  `66ebc4798d2ca72973967a20264bdeb70dcf0a13`, CC-BY-SA-4.0;
- CodeQL `java-all@9.2.2`, build commit
  `94101634db019b00637dd5cfe241f7e570da290d`, MIT.

Schema gồm `CWE/OWASP_CATEGORY/SOURCE/SINK/SANITIZER/PROPAGATOR/PRECONDITION/
MITIGATION`; mọi fact có stable ID, source locator, version, license, artifact
checksum, extraction method và confidence. CodeQL API facts chỉ lấy các model
origin đã review (`manual`, `df-manual`, `ai-manual`, `hq-manual`); generated và
experimental models bị loại. Deterministic và LLM-inferred facts nằm ở hai file
riêng; policy hiện tại cấm network/LLM trong build nên inferred file phải rỗng.

Canonical full run `p8_skg_global_full_002` tại clean commit
`50ed53ee5b99ce3adeae81fbbf9c41c33e4fe70a` (D-025):

- 2,619 nodes; 5,285 edges; 7,904 deterministic facts; 0 inferred/LLM facts;
- graph digest
  `8685f50d8e5f3727aa8cba9361f739c58fc57fb3ba444d59a9577dc413fbc805`;
- đủ source/sink/sanitizer/propagator/precondition/mitigation và related-CWE theo
  audit policy; dependency/source/provenance/checksum validation đều pass;
- manifest SHA-256
  `91ca35b8ee2b9f153ba8dedfe75a4e165231b5a3b86cc5219e7623a2497f270a`;
- checksum index
  `a051e41e7e5194f25d3ac08f9654a30af6f7cab0e14846952cce0fb64cb8953c`;
- manifest ghi `git.dirty: false`; graph digest khớp pilot 002 và dirty-tree
  diagnostic full 001. Full 002 được khóa cho Phase 9 trở đi.

### Phase 9 — Evidence Graph và USEG iteration 0

D-026 định nghĩa Evidence nodes `HYPOTHESIS/ASSERTION/CODEQL_FINDING/TAINT_PATH/
SANITIZER_EVIDENCE/CONTRADICTION/VERIFICATION_RESULT`, reference Program/Security
nodes và năm edge `SUPPORTS/CONTRADICTS/VERIFIED_BY/DERIVED_FROM/MATCHES`. Mọi
record có analysis iteration, stable ID, artifact provenance; confidence giữ dạng
component độc lập, không aggregate sớm.

Iteration 0 map exact candidate CWE, source location theo same-file line
containment ưu tiên symbol, API theo exact symbol/role, và precondition theo CWE
membership. Phase 7 `TAINT_CANDIDATE` chỉ trở thành `unverified_candidate`, không
phải verified vulnerability. Không materialize placeholder sanitizer evidence,
contradiction hoặc verification result khi upstream chưa có bằng chứng thật.

Canonical full run `p9_useg_dev_full_003` tại clean commit
`2395d219789ad5401e1fecdb26cee9030208c19b` (D-027):

- đủ 96 statuses: 81 `SUCCESS`, 15 `ANALYSIS_FAILED` kế thừa Phase 7;
- 7,527 nodes, 16,398 edges; 806 hypotheses và 2,634 assertions trên 81 graph;
- 823 CodeQL candidate findings/taint paths; 823/823 trace được tới cả Program
  location và Security fact;
- graph digest
  `918707ee3bbb59858b2b2d8dd9aafb762467f983bf579c97e35ba4191a1a41fa`;
- zero cycle, JSONL round-trip lossless, zero LLM/network call;
- hai successful projects không có incident taint candidate phù hợp, giữ 0 path;
- manifest ghi `git.dirty: false`; graph digest khớp dirty-tree diagnostics
  full 001/full 002. Full 003 được khóa cho Phase 10 trở đi;
- manifest SHA-256
  `83dce921c979db710762bd205588c667033bc10fb6c64c4581fce9a8c84810c7`;
- checksum index
  `45d1ed92e1a8f7adb365aa0bced3872f21e5815fe574a4d62838cb7747784235`.

### Phase 10 — Graph retrieval và specification synthesis

D-028 pin exact Phase 9 full 003 và triển khai chung runner cho B6/B7/B8 cùng
phần synthesis-only của B9. B6 giữ Evidence anchors + Program, B7 giữ Evidence
anchors + Security, B8 lấy unpruned connected component, B9 lấy tối đa 4 hop/80
node. Compact JSONL phân biệt structural pruning với token truncation và giữ
context dưới 8.192 input tokens/call.

GPT-OSS 20B/AkashML dùng strict schema chỉ cho chọn node ID trong context.
Source/sink phải có grounded Program, exact-role Security hoặc Phase 6/9 location
assertion; thiếu role thì fail trước API. Mỗi hypothesis tối đa 3 calls, mỗi
project tối đa 30 calls/160.000 input tokens. Spec được render thành deterministic
CodeQL template và `query compile --check-only`; trạng thái luôn
`SYNTHESIZED_UNVERIFIED`, zero final finding trước Phase 11.

Implementation có offline estimator, atomic/resumable runner, exact-dependency
validator, numbered B6–B9 dispatch, dry-run/suite scripts và runbook. Bốn
one-project dry-run 007 pass với zero API/network call; endpoint/token preflight
ghi B6/B7 8/10 context API-eligible, B8/B9 10/10 và request estimate cao nhất
7.469/8.192 tokens. Đây là pre-full diagnostic; canonical full lock được ghi ở
D-029 và phần cuối mục này.

B9 API pilot 001 là diagnostic immutable: 7/10 grounded specs compile thành
công, chi phí `$0.00092432`; ba CWE-78 request bị HTTP 400 do optional role không
có candidate tạo `enum: []`. Schema đã được sửa fail-closed bằng `maxItems: 0`
với non-empty fallback enum; phải chạy pilot ID mới, không sửa artifact 001.

B9 API pilot 002 pass: 1/1 project, 10/10 grounded specs và 10/10 final query
compile; 49.540 input tokens, 3.892 billed output tokens, chi phí `$0.00138`.
Ba retry đều là HTTP 429 tạm thời từ AkashML và sau đó thành công; zero failed
call, zero fallback, max prompt thực tế 6.167/8.192 tokens. Artifact vẫn mang
dirty manifest nên chỉ là implementation pilot, không phải canonical full run.

B6/B7/B8 pilot 001 cũng được validator chấp nhận. B6 và B7 mỗi baseline sinh
8/10 grounded specs, compile 8/8; hai hypothesis còn lại fail trước API vì
layer ablation không có grounded source, đúng như dry-run preflight. B8 sinh
10/10 grounded specs và compile 10/10. Chi phí lần lượt `$0.00043732`,
`$0.0011979`, `$0.00125018`; B7/B8 có HTTP 429 retry tự phục hồi, zero failed
call và zero fallback. Cả ba là dirty implementation pilots, không canonical.

Full-coverage dry 001 sau commit đầu tiên phát hiện request-estimate overflow dù
context cap riêng vẫn pass: B6/B7/B8/B9 lần lượt 1/49/86/3 context. Runner được
bổ sung adaptive serialization: chỉ context bị ảnh hưởng mới giảm token budget,
rebuild strict schema và lặp preflight trước API; mọi lần giảm được ghi trong
context metadata. Full dry 002 trên 96 project/806 context mỗi baseline pass với
zero overflow: B6/B7/B8/B9 có 1/49/86/3 adapted context và lần lượt
763/619/801/801 API-eligible context.

Targeted B9 adaptive pilot 001 trên `proj_aff72cca32a2f43c0147` pass từ clean
commit `e3ddccf`: context `hyp_f0eef19181ba14128564` giảm budget 4.854→4.701,
actual prompt 5.201 tokens; toàn project 10/10 specs compile, zero retry/failure,
max prompt 6.092/8.192, chi phí `$0.0013405`. Implementation đủ gate để chạy
full development B6–B9.

Canonical Phase 10 full runs được tạo từ clean commit `184fef1` và khóa bởi
D-029: B6/B7/B8/B9 có 54/34/78/78 project success, tạo 763/619/801/801 grounded
specifications và compile 100% final query. Mọi run giữ đủ 96 statuses; 15 failure
upstream từ Phase 7/9 tiếp tục là intention-to-analyze misses.

Evaluator-only gate `p10_dev_spec_eval_003` tại clean commit `6117b00` dùng 91
development projects có fix-location annotation, không mở `test_locked` và không
sửa synthesis artifact. B9 có 14/762 paper-compatible proxy-positive specs và
phát hiện 6/91 projects. Đây không phải verified path; kết quả được đóng băng để
Phase 11 kiểm chứng, không dùng sửa prompt/retrieval/specification.

### Phase 11 — Static differential verification

Canonical `p11_diff_dev_full_002` được tạo từ clean commit `4b898bf` sau
khi evaluator-only fixed preparation hoàn tất 78/78 opaque databases. Run có
đủ 96 final project statuses: 78 `SUCCESS` và 18 inherited Phase 10 misses;
776 specification states gồm 28 `VERIFIED_DIFFERENTIAL` và 748 explicit
`UNVERIFIED_*`; 213 taint paths, 1.513 query invocations, zero LLM calls/tokens.
`STATUS=FAILED` là aggregate failure-as-miss expected; validator authoritative
trả `PASS_WITH_ANALYSIS_FAILURES`. Chỉ 28 verified-positive được chuyển sang
Phase 12; `UNVERIFIED_*` không phải negative label.

## Canonical artifacts và code map

- Phase 4: `results/reproduction/phase4_gptoss20b_full_001__*`;
- Phase 5: `results/aggregate/phase5_baseline_leaderboard.csv` và raw B3/B4/B5;
- Phase 6: `results/hypotheses/static/p6_static_v2_dev_full_001/`;
- Phase 7: `results/graphs/program/p7_pg_dev_full_004/`;
- Phase 8: `results/graphs/knowledge/p8_skg_global_full_002/`;
- Phase 9: `results/graphs/useg/p9_useg_dev_full_003/`;
- Phase 10 run root: `results/specifications/phase10/<baseline>/<run-id>/`;
- Phase 10 evaluator: `results/evaluations/phase10/p10_dev_spec_eval_003/`;
- Phase 11: `results/verification/phase11/p11_diff_dev_full_002/`;
- Phase 12: `results/calibration/phase12/<run-id>/`;
- configs/locks: `configs/experiments/`;
- Phase 5/6/7/8/9/10/11 code: `src/baselines/`, `src/hypotheses/`,
  `src/graphs/program/`, `src/graphs/knowledge/`, `src/graphs/evidence/`,
  `src/graphs/useg/`, `src/retrieval/`, `src/specification/`, `src/verification/`;
- runbooks: `docs/10_PHASE5_RUNBOOK.md`, `docs/11_PHASE6_RUNBOOK.md`,
  `docs/12_PHASE7_RUNBOOK.md`, `docs/13_PHASE8_RUNBOOK.md`,
  `docs/14_PHASE9_RUNBOOK.md`, `docs/15_PHASE10_RUNBOOK.md`,
  `docs/16_PHASE11_RUNBOOK.md`.

Checksum chi tiết nằm trong từng canonical run. Raw results/DB thường bị Git
ignore; clone khác có thể chỉ có compact exports và manifests.

## Giới hạn còn hiệu lực

- Dataset chỉ có 4 CWE; chưa được claim broad-CWE generalization.
- Phase 4 có tool/model/provider substitution; không phải exact reproduction.
- Phase 5 là implementation validation trên `D_repro_v1`, chưa phải final test.
- Phase 6 còn 12/96 pool misses.
- Phase 7 chỉ có 81 graph successes; 15 failures tiếp tục tính là miss downstream.
- Program Graph là hypothesis-bounded, không phải full-repository CPG.
- Phase 8 chỉ có một CodeQL barrier model được map thành sanitizer (CWE-79);
  validator yêu cầu coverage thật, không tạo placeholder cho CWE khác.
- Phase 8 full 001 chỉ là dirty-tree diagnostic; downstream phải pin full 002.
- Phase 9 iteration 0 chưa có final verified finding, contradiction hoặc
  verification result; các fact này thuộc Phase 11 và không được suy diễn từ
  candidate path.
- Phase 9 full 001/full 002 chỉ là dirty-tree diagnostics; downstream phải pin
  full 003. Hai trong 81 graph success không có incident candidate path.
- Phase 10 compile-only không phải static verification; chỉ Phase 11
  `VERIFIED_DIFFERENTIAL` được chuyển sang calibration. Dry-run không chứng
  minh provider/schema behavior thật.
- Phase 11 có 18 inherited Phase 10 misses và 748 `UNVERIFIED_*`; không được
  drop misses hay coi unverified là negative. 12/78 fixed DB dùng validated
  `build-mode=none`, nên cần giữ provenance này trong sensitivity analysis.
- Hosted model không có project-controlled weight hash.
- `test_locked` đã dùng để debug verifier; không còn eligible cho confirmatory
  v2. Chưa đăng ký holdout mới, chưa được claim final paper performance v2.

## Handoff pipeline v2

Theo D-038, người dùng chọn audit và thiết kế trước implementation. Run audit
`results/audits/p6_p10_dev_audit_v2_001/` đã kiểm checksum trước/sau của tám
development inputs: 251/956 Phase 6 hypotheses thiếu source; 238/806 vẫn vào
Phase 9; B9 tạo 233/801 specifications từ hypothesis thiếu source gốc. Có 197
source/sink assertions không map Program. Phase 6 Recall@10 0.875 chỉ đo CWE
membership; không chứng minh localization/endpoint correctness. Không mở raw
labels/test artifacts và không gọi LLM/CodeQL.

`configs/experiments/pipeline_v2.yaml` là design-only, execution disabled; pin
audit inputs, external historical dispositions và planned run IDs. Code audit:
`src/experiments/development_audit.py`. Hướng implementation/gates:
`docs/19_PIPELINE_V2_RESTART.md`. Theo yêu cầu tiếp theo, Phase 6–12 v2 và controller
đã triển khai trong `src/pipeline_v2`, config thực thi riêng
`configs/experiments/pipeline_v2_execution.yaml` protocol 2.0.0, quyết định D-039.
Inventory typed CodeQL, role-specific slots và exact source fingerprints; P7 scope
selected endpoint/callable graph, P9 grounded model bindings, P10 precise role enums
và vulnerable query recheck. Historical entrypoints/configs vẫn dùng protocol cũ.

Phase 11 v3 phải reverify development cohort trước Phase 12. Calibration target
lịch sử là candidate-CWE correctness, không phải vulnerability FDR. Group-support
minima phải khóa trước fitting; nếu cohort thiếu classes/groups thì bỏ calibrated
Full và dùng conservative VERIFY/ABSTAIN với ACCEPT tắt. D-039 khóa minimum 8 groups,
5 records/class, 2 groups/class và mọi OOF training fold có hai classes trước fit.
Chưa có confirmatory holdout mới; test split lịch sử chỉ diagnostic.

Kiểm tra lượt audit 2026-10-05: full suite 152 tests pass; Ruff toàn repo và mypy
103 source files pass; checksum audit output hợp lệ.

Autonomous execution: `uv run --frozen python -m src.pipeline_v2 auto --confirm-api-spend`
trong tmux `maxvera-pipeline-v2-dev`, log `logs/pipeline_v2/development_full.log`.
Controller root `results/pipeline_v2/.dev_restart_v2_001.inprogress` ghi steps/failure;
auto chạy P6/7/9 → dry toàn development B6–B9 → API pilots → full → v3 → conditional
calibration. Gate failure dừng downstream; resume chỉ cùng snapshot. Không mở Phase 13.
Khi toàn development xong mới final controller và ghi development_lock.json; final
test claim vẫn cần unopened repository-group split. Không chỉnh tracked code/config
trong khi controller full đang chạy vì các stage tiếp theo yêu cầu clean snapshot.

Live query diagnostics `results/grounding/v3_query_dev_pilot_v2_*` không gọi API.
Pilot 001 resolve vulnerable endpoints/path rồi fail-closed ở fixed ambiguous mapping;
002 resolve cả hai sides và giữ UNVERIFIED_PERSISTS_FIXED; có expression fingerprint
và role-specific return/argument. Quality suite: 182 tests pass, Ruff toàn repo,
mypy 113 source files, git diff --check pass. Tám historical input checksums PASS.
P6 pilot 001 không có hypothesis; các pilot sau có grounded candidates; pilot 004 có
QL binding compile error và giữ nguyên, các pilot mới kiểm unique internal node count
và UTF-16 source fingerprints. Pilot 007 dừng aggregate QL nặng; bản cuối dùng
BQRS internal IDs để reject ambiguity trước API, pilot 008 có 10 hypotheses và
graph/dry B6–B9 pass. Launcher: `bash scripts/tools/run_pipeline_v2_tmux.sh`.
Quality suite cuối: 182 tests. Không promote pilots.

## Checklist agent

1. Đọc file này và phần liên quan trong decision log.
2. Kiểm tra Git status; không đè thay đổi của người dùng.
3. Xác minh config lock và artifact trực tiếp, không dựa vào hội thoại.
4. Không mở `test_locked` hoặc evaluator-only trong analyzer task.
5. Dùng run ID mới, atomic outputs, final statuses và validator.
6. Ghi decision/experiment log nếu thay đổi reproducibility hoặc protocol.
7. Trước khi báo phase hoàn tất, tự cập nhật ngắn gọn file này.
8. Chỉ commit khóa khi memory, config, decision log, experiment log và runbook
   đã đồng bộ.

Quality checks chuẩn:

```bash
uv run --frozen ruff check .
uv run --frozen mypy src
uv run --frozen pytest -q
```

Tại Phase 11 lock: canonical differential validator và full quality suite pass;
exact command/kết quả được ghi trong experiment log và lock commit.

## Recovery v2 — 2026-10-06, D-040

Người dùng đã yêu cầu tự động phục hồi. Historical 001 bất biến: P6 80 successes/
16 failures (14 no DB, 2 disk errors), P7/P9 65 graphs, dry B6–B9 pass, B6 pilot
9 specs/1 HTTP429; controller STOPPED_AT_GATE. Sau storage cleanup, project ~77 GiB,
free disk ~228 GiB; scientific artifacts/indexes preserved.

Config `configs/experiments/pipeline_v2_recovery.yaml`, controller `dev_restart_v2_002`,
namespace suffix002; launcher `scripts/tools/run_pipeline_v2_recovery_tmux.sh`, tmux
`maxvera-pipeline-v2-recovery`, log `logs/pipeline_v2/development_recovery_002.log`.
Preparation uses separate `data/interim/phase7_codeql_databases_v2_002`, recorded
no-build extraction for missing development DBs; no overwriting old DB/status.
P6 science compatibility checks + original archive/metadata hashes allow 80 inherited
successes; two disk failures and 14 missing DB are reconsidered. Zero-hypothesis
cases keep misses (5 role gaps, 10 unsupported candidate relationships), no label tuning.
P10 reuse requires exact context/schema/model, frozen bindings and actual vulnerable
query, inherits all reservations/logs; full inherits validated pilots without budget reset.
Transient API -> unfinished checkpoint/exit75, six bounded cooldown retries. Budget
and fatal API distinct from grounding rejection; three semantic failures/hypothesis,
30 logical requests/160k tokens/project unchanged. Model/provider/queries/verifier/
calibration support gates unchanged, source Git/model config frozen at every stage.
Query caches/internal traces cleaned after each project, scientific outputs retained.
No P13 execution; new confirmatory split remains required. Do not edit tracked files
while recovery controller runs; inspect steps.json, failure.json and live stage logs.

Recovery validation trước launch: 187 tests pass, Ruff/mypy (114 files) pass,
launcher bash syntax/diff check pass; legacy P6/B6 pilot/P9 snapshots và cả 10 pilot
contexts/schemas tương thích. Actual inherited endpoint queries vẫn phải chạy trong
pilot002. Pilot project được pin `proj_7341ff37e347ec3be4ce` cho cả B6–B9, để tái
kiểm cùng cohort và giữ nine-spec lineage ngay cả khi missing DB được phục hồi.

Startup correction: 002 bị ngắt trước API do no-build thiếu Maven/JDK PATH và fallback
minimal JDK; giữ diagnostic partial output, không resume/promote 002. Canonical recovery
chuyển sang `pipeline_v2_recovery_003.yaml`, `dev_restart_v2_003`, suffix003,
`run_pipeline_v2_recovery_003_tmux.sh`, tmux `maxvera-pipeline-v2-recovery-003`, log
`logs/pipeline_v2/development_recovery_003.log`. Pinned Java/Maven/Gradle environment
explicit từ opaque source metadata, binaries all14 preflight pass; cancellation
terminates subprocess group. Source/query scientific compatibility vẫn fail-closed.

Validation snapshot003 trước launch: 189 tests pass (8.10s), Ruff toàn repo pass,
mypy 114 source files pass, bash syntax/diff checks pass. Legacy P6 và B6 pilot
scientific compatibility contracts đều PASS sau cancellation/toolchain fixes.

## B9 end-to-end fixes — 2026-10-08, D-041

Controller003 thực tế STOPPED_AT_GATE tại B6 full vì HTTP429/retry exhaustion.
P6: 93/96 success, 694 hypotheses; P7/P9: 76/96 success, 20 explicit misses.
B9 dry/pilot003 checksum valid; 10 specs trên một project, chưa có full/v3/calibration.
12/76 project cần fixed DB mới do preparation cũ chỉ chọn cohort historical.

Implemented `src/pipeline_v2/b9.py`, `fixed.py`, `validate.py`; config
`configs/experiments/b9_pipeline_v2.yaml`; numbered B9 nhận --pipeline-v2.
Controller reuse inputs003 và chạy riêng B9 dry → pilot end-to-end → full →
fixed preparation → verifier v3 → conditional calibration → validator/report.
Parent fixed DB/status giữ nguyên; DB mới ở namespace v2_004. Partial synthesis
specs có UNVERIFIED_UPSTREAM_ANALYSIS_FAILURE; pacing15s và WAITING_FOR_API/exit75
giữ bounded retries/budgets. No new holdout, không claim calibrated Full khi thiếu support.

Validation snapshot trước pilot: 198 tests pass, Ruff/mypy (117 files), bash syntax,
diff checks và smoke cleanup assertion pass. Chưa có canonical B9 full lock. API connection
probe 2026-10-08 nhận nonempty response từ pinned AkashML/GPT-OSS20B; chưa chứng minh
full workload không429. Launcher scripts/tools/run_b9_v2_tmux.sh, validator
scripts/tools/validate_b9_v2.sh; live pilot/full phải kiểm result validator.

Pilot004 finished synthesis: 10/10 specs, 10 successful calls, eight recovered429
HTTP attempts, 59,903 input/3,881 output tokens. Parent fixed DB reused with provenance.
Verifier/routing finished but controller STOPPED_AT_GATE: 9 PERSISTS_FIXED, 1 query
budget failure. All004 artifacts retained unchanged, not a validated end-to-end lock.
Cause: 4×10+1 inventory = 41 needed versus frozen40. Correction batches unchanged
endpoint predicates on both sides (23 queries for ten fully mapped specs), keeping
entity ambiguity, descriptor/archive checks, per-spec path queries and verifier gates.
B9 --inherit-run revalidates synthesis scientific contracts and actual endpoint
resolution, retains all reservations/responses/log lineage; avoids duplicate API.
Pilot005 will inherit004 synthesis under the same config from a new clean commit.
Validation trước pilot005: 202 tests pass (8.67s), Ruff toàn repo và mypy117files pass;
shell syntax/diff checks pass. Full96 zero-API preflight và actual004 synthesis
compatibility PASS. Chưa có kết quả pilot005 hoặc B9 full lock.

## B9 pilot005 — end-to-end PASS, 2026-10-08

Frozen execution source `149041f`; start15:17:11, finish15:29:25 Asia/Saigon.
Controller `results/pipeline_v2/b9/b9_e2e_dev_pilot_v2_005` completed exit0.
Independent `validate_b9_v2.sh --run-root ...` PASS: one project, ten specs,
zero analysis misses. P11:23query attempts, ten UNVERIFIED_PERSISTS_FIXED,
zero query/budget failures. P12:ten ABSTAIN, calibrated_full=false/accept=false;
zero differential verified findings. This demonstrates technical execution only.

All ten responses/reservations inherited byte-for-byte from004, no new LLM HTTP
attempts. Operational usage includes inherited10calls, eight429, 59,903/3,881tokens.
Both endpoint batches return exactly the individual004 rows including entity IDs
on all ten specs. Fixed DB parent metadata/archive retained; all12 currently missing
fixed DB cohort projects have source repos, but their builds remain untested untilfull.
No canonical B9 full96 lock or new unopened confirmatory holdout.

Final descriptor-literal guard renames only the QL predicate declaration, leaving
source expressions containing frozenEndpoint(...) intact. Actual vulnerable/fixed
batch query strings remain byte-identical to the validated005 output; no rerun/API.
Next full run may use b9_e2e_dev_full_v2_005 with --inherit-run pointing to005_synth.
Tmux maxvera-b9-v2 currently holds an idle shell after exit0; inspect before closing
this completed session to reuse launcher. Source/config must stay clean duringfull.
Final checks sau literal guard/result documentation: 202 tests pass (8.81s), Ruff/mypy117
pass, git diff/smoke assertion pass, independent final005validator PASS. Completed
004stage checksums và parent fixed preparation vẫn nguyên vẹn. Chỉ local commits;
không push remote hoặc tự khởi chạy full96.

## B9 all120 paper-reference profile — 2026-10-08, D-042

User explicitly clarified all120cases for original-paper comparison. Registered
configs/experiments/b9_benchmark_120.yaml and --pipeline-v2 --benchmark-120;
96dev+24historicaltest, diagnostic only. Original dev-only entrypoint remains96.
Same120CVEs as D_repro_v1; declared refs differ (tag5,buggy10,fix5), and opaqueIDs
do not match. Do not claim identical snapshots/model/toolchain/hint conditions.

New benchmark.py/benchmark_inputs.py/benchmark_evaluate.py controller prepares120,
reuses119historical vulnerableDBs and93unchanged successful P6dev projects with
registeredlock/AST/archivechecks. Missing/upstream cases execute natively; P7/P9,
B9 dry/pilot/full, actual fixed preparation, verifier/routing/evaluator cover120.
Test fixed parents21 pinned separately. Calibration fits development only, frozen
model application on test features; fit_scope.json disallows test labels for fitting.

Paper-proxy metrics use strict patched-method path overlap, dedup paths; AvgFDR
only nonempty-path cases (N/A ifnone), AvgF1/detection denominatorall120 inclfails.
Four evidence/routing variants with all120/dev96/test24 breakouts +published IRIS
Table1 reference, legacy local macro metrics kept separately. Final raw case rows
and report locked/independently validated. No new holdout or vulnerability-FDRclaim.

Zero-API preflight PASS:120selection96+24,119availableDB,120source repositories.
Launcher scripts/tools/run_b9_benchmark_120_tmux.sh uses separate
maxvera-b9-benchmark-120/logs/pipeline_v2/b9_benchmark_120.log. Planned live ID
b9_benchmark_120_v2_001 requires clean frozen local commit; no result claimed yet.
See docs/19_PIPELINE_V2_RESTART.md commands and docs/07_DECISION_LOG.md rationale.
Before launch:209tests pass (10.61s), Ruff repo/mypy120sourcefiles, bash syntax,
diff/smoke checks pass. Actual005synthesis compatibility PASS for dev96 and benchmark120;
independent005validator stillPASS. New evaluator export/resume test covers120rows,
failed-case denominator, strict methods, emptyFDR; calibration test poisons test labels.

Trial001 snapshot0adfd50 started20:37:35+07, inputs119success/1miss (dirty oldsource),
then STOPPED_AT_GATE: P6seed003 has inherited_from already, duplicatekeyword forwarding.
0newAPIcalls; trial controller/stages kept intact. Own tmux idle shell closed afterexit1.
Correction excludes inherited_from before setting new registered lock, and missingDB
build uses isolated sourceHEAD checkout; original build.gradle.kts modification stays.
Provenance-before-move checkpoint supports interrupted extraction resume. New regression
tests prove both fixes. Next active IDb9_benchmark_120_v2_002, same frozen120config,
new clean code commit; source/config must stay clean while live stages execute.
Prelaunch002:211tests pass (11.00s), Ruff/mypy120files, diff/shell/smoke PASS;
actual005synthesis compatibility remains PASS for dev and diagnostic profiles.

## B9 90-second recovery — 2026-10-09, D-043

User explicitly requests90s between requests and restarting maxvera-b9-benchmark-120.
Run002 snapshotdb1a238 stopped HTTP429/APIretry exhaustion; inputs120ready, P6
118success/2timeouts/893hypotheses, P7/P9 98success/22misses, pilotE2EPASS. After
manualresume, checkpoint247specs,24SUCCESS/5FAILED/91PENDING. All old002 artifacts
kept. Frozen CHECKPOINT_ONLY snapshot results/pipeline_v2/benchmark_checkpoints/
b9_benchmark_120_v2_002_synth_90s_001 (source manifestc9b790ed...,checksumef84d67d...).

New config configs/experiments/b9_benchmark_120_90s.yaml; planned/active ID003.
Only interval15→90 and controller mincooldown60→90, new execution configpath and
explicit transport_recovery lock. Model/provider/science/budgets unchanged. OpenRouter
client validationcap60→90 only; pacing applies to every HTTPattempt/sharedclient.
benchmark_recovery.py validates exact permitted config/provider source differences,
reuses9locked completed stages, restores full sourcepartial with everyreservation,
response, rejection/terminal/pending state and LLMlog. Recoverymarker makes resume
idempotent without budgetreset. Controller/Run hooks keep P10scientific loop unchanged.

Prelaunch003:216tests pass (12.34s), Ruff/mypy121files/shell/diff/smoke PASS. Real9stage
reuse preflight PASS, full120/120DB90s zeroAPI preflight PASS. Run requires new clean
source commit; do not edit tracked code/config while live. Launcher must pass explicit
--config configs/experiments/b9_benchmark_120_90s.yaml --run-id b9_benchmark_120_v2_003.
Existing old session is idle afterexit75; inspect before closing/relaunching same name.

## B9 full120 completed and failure audit — 2026-10-12

Run003 finished 2026-10-11T11:56:41Z (18:56+07), controller exit0;
independent validator PASS_WITH_ANALYSIS_FAILURES. All120 retained,97analysis successes,
23failures,892specifications,1differential finding. Raw patched-method proxy24/120,
verified/routed1/120; ACCEPT disabled and calibration ineligible (dev verified0).
Tmux maxvera-b9-benchmark-120 is now idle; progress window only tails logs.

User authorized offline audit of17dev raw-detected cases and23analysis failures.
Final artifact results/diagnostics/b9_benchmark_120_v2_003_audit_005; intermediate001–004
retained. src.experiments.b9_failure_audit requires evaluator role, refuses overwrite,
pins/rechecks inputs and reconstructs all240raw/verified metric rows exactly. ZeroAPI
and zero newCodeQLqueries. Frozen benchmark artifacts/config/analysis code unchanged.

17dev cases:62overlap-producing specs (46persist,16mapping);10cases persistence-only,
2mapping-only,5mixed. All62candidateCWE22;4cases have trueCWE79/94, so location proxy
does not establish same-CWE detection. All892specs preserve P6physical endpoint pair,
no LLMsanitizers/propagators; preconditions not compiled into query. Mappingcounterfactual:
17/18unresolved endpoint occurrences have one exact unchanged-span semantic match;
existing policy explicitly rejects same-callable repetitions, so new version required.
This does not establish newverified findings or accuracy improvement.

23failures:13no candidate relation,2no modeled endpoints,3no modeled source,2no modeled
sink,2P6timeouts,1fatal API JSON decode. Dev20/testdiagnostic3. One bad hypothesis
caused9retained specs to be skipped downstream at project level. Prioritized repair/pilot
plan and17case notes: docs/20_B9_BENCHMARK_FAILURE_AUDIT.md. Audit completed; proposed
transport/partial-state/mapping/guard/discovery fixes and new pilots not yet implemented.

Additional source coverage evidence: Spring4Shell/CVE-2022-22965 vulnerable src.zip
contains3Java files, allbuildSrc and no annotated application file. DBbuild success
does not ensure application extraction; application-coverage gate and corrected build
are P0. Retrofit zero-endpoint has219Java files; HL7timeout cases7496/7514Java files.
Audit verification:46related unit tests PASS, Ruff/mypy PASS, guards/checksums PASS,
independent benchmark validator still PASS_WITH_ANALYSIS_FAILURES.


2026-10-12 completeness audit / current work:
New default benchmark profile: configs/experiments/b9_benchmark_120_complete.yaml.
Strict success gates, empty-discovery completion, bounded JSON-envelope retries,
coverage checks on vulnerable/fixed DBs, explicit resume retaining reservations,
and --validate-only (no LLM) implemented; model/mapping/scoring unchanged.
230 tests PASS; Ruff/mypy PASS. Original run003 remains immutable.
Readiness005: all120 accounted,64READY/56BLOCKED under current full-file coverage
policy; no queries certificate,0API. This is input quality, not56new analysis failures.
Bulk no-API repairs004 still running in exec session89905 (PID2680658); no paid
benchmark restarted. Critical xwiki/oauth vulnerable rebuilds full coverage PASS;
Spring rebuild3982/3983 missing spring-test MockEnvironment remains BLOCKED.
See docs/21_B9_PIPELINE_COMPLETENESS.md for status, gates and exact commands.

No-API real CodeQL pilot b9_application_db_pilot_001 PASS: xwiki1168/1168source,254endpoints,81relations,10hypotheses; oauth372/372source,71endpoints,0relations/0hypotheses(valid no-candidate). No LLM or P11 claim.
Maintenance monitor/follow-up: tmux maxvera-b9-readiness-120; waits bulk PID2680658, rescans with current code into readiness006, runs --validate-only only if input scan PASS.

2026-10-12 maintenance continuation (supersedes the running-job notes above):
Repair004 stopped after46cases; no final exception/exit code, no retained kernel OOM
evidence, root signal/cause unproven. Read-only scan006 completed120:68READY/52BLOCKED.
Repair007 intentionally interrupted with SIGTERM to switch to durable two-pass mode.
Current tmux maxvera-b9-readiness-120 window repair runs readiness008 with2workers.
It first scanned all120 (69READY/51BLOCKED), then reuses cache and repairs blocked
cases, retaining all120 rows. Snapshot gap_audit002:73READY/47BLOCKED,79blocked sides,
0API/0queries/0waivers. These are changing checkpoints, not final readiness.
Launcher scripts/tools/run_b9_readiness_120_tmux.sh logs lifecycle/exit status,
serializes cache writers, rescans into008_final and only auto-runs --validate-only
if all120 inputs PASS. It never starts paid synthesis. Window remains visible on exit.
Added production-vs-test no-build exclusion, testFixtures/test-*/src/it/demo path
classification, and DB metadata revision/finalization checks. No score/mapping change.
Real collision toy pilot PASS for production source selection; this is not proof that
Spring real DB is fixed. Duplicate-production-FQN index-files workaround rejected:
archive2files but only1of2methods queried, never applied to benchmark/cache inputs.
231 tests PASS, Ruff/mypy124src PASS. Offline gap auditor under scripts/tools pins
full120 snapshot and emits cases.csv + source/module hints without changing gates.

2026-10-13 unblock maintenance (supersedes prior running008 note):
008_final finished85READY/35BLOCKED,120/120 inspected,0API. 34coverage gaps,
1AWSfixed extraction Java heap OOM at4096MiB. New no-code blob check exempts only
empty/comment-only pinned sources; unavailable blobs stay missing, threshold1.0.
HL7 two cases now inputREADY (not query validated). Added extraction.py: native
init/trace, supplements by source root with distinct -d and class-origin tracking.
Toy pilot005 queries both duplicate-FQN methods a/b;003/004 failed without tracking.
Real DSpace vulnerable pilot001 PASS1445/1445 and modeled-type query, copied cache.
Supplement PENDING/BLOCKED cannot reuse; model check + extraction policy hashes pinned.
Strict vulnerable/fixed fallback share repair mechanism. Large>=50000Java uses12GiB,
others4GiB,2workers. 236testsPASS,Ruff/mypy125srcPASS,bash-n/diffcheckPASS.
Tmux maxvera-b9-readiness-120 new repair window3 runs009 --inputs-only: initial
full scan87READY/33BLOCKED then repairs. Final009_final authoritative after completion;
no paid B9, no automatic upstream validation in this input-only maintenance job.

2026-10-13 pinned-driver correction (supersedes009 checkpoint claims):
009 intentionally SIGTERM-stopped03:36:41Z (INTERRUPTED,exit130) after discovering
supplement wrapper used bundled Java instead of pinned project driver. Old model
markers now rejected without pinned-driver + exact extraction-policy provenance.
Helper now uses JAVA_HOME/bin/java wrapper (bundled native extractor still internal).
Toy006 runs production helper on pinnedJDK8:2/2source,bothmethods,bothlocalflowsPASS.
Real DSpace pilot002 pinned driver PASS1445/1445+typequery; installedcache withold
pilot001 copy preserved rejected. Pilot001/implementation001 markedSUPERSEDED.
238testsPASS,RuffPASS,mypy125src+promotiontoolPASS. Added same-SHA/same-side/same
JDK/Maven/Gradle reuse within readiness process; source/model checks still mandatory.
Tmux readiness010 started03:44Z,2workers,--inputs-only; final010_final authoritative.
Promotion tool can expose validated vulnerable DBs through canonical opaque cache
symlinks after complete PASS, then fresh scan; refuses premature/in-progress input.
No paid benchmark restarted. Old run003/config remains unchanged.

2026-10-13 follow-up, checkpoint 04:57Z: run010 has 107 READY/13 BLOCKED,
with 22/32 repair jobs finished. Extraction file formatting changed at 04:35Z
(logic unchanged), producing raw hash 6676fc7b; restored snapshot002's exact hash
d120d06c. Three Keycloak cases/four sides were rejected during this interval.
Do not edit markers into PASS. Run010 continues; recovery will reuse valid DBs.
Fixed readiness.extract to retain DBs on post-extraction gate exceptions too.
239 tests PASS, Ruff PASS, mypy 126 files PASS; frozen implementation003.

Tmux window `finish-inputs` runs `results/diagnostics/b9_finish_inputs_001.py`.
After launcher010 finishes, if BLOCKED, perform recovery011 and final scan012.
Only full PASS permits promotion001, scan013 and benchmark --dry-run (no LLM).
Acceptance002 requires all 35 formerly blocked IDs READY and 120 unique cases.
Final acceptance remains pending; do not claim full PASS yet.

2026-10-13 checkpoint 06:16Z:010 now116 READY/4 BLOCKED. AWS root extraction
passed at actual-Xmx12288m, raw archive109920 app Java files; finalize running.
All NiFi/Payara/Flink/Camel ready. Independent Keycloak recovery pilot002 has
2/3 unique DBs checked; covers4failed sides via same-revision vulnerable reuse.
Pilot001 intentionally interrupted to replace process-stop coordination; first
PASS DB reused with SHA recheck. Current tmux windows recovery-pilot-002 and
finish-inputs-002. Current scripts results/diagnostics/b9_keycloak_recovery_pilot_002.py
and b9_finish_inputs_002.py: pilot installs only AFTER010launcher+finalscan ends,
underlock; finisher waits for pilot terminal state before any recovery/scan.
Acceptance output is now b9_unblock_acceptance_003 (002 historical empty wait).
Final scan remains b9_full_pipeline_readiness_013_final; not yet120PASS.0LLM.

2026-10-13 FINAL INPUT ACCEPTANCE (supersedes pending notes above):35/35 formerly
blocked cases now READY; exact same120 IDs,240 sides at100% application coverage.
Readiness014 and014_final PASS120; promotion001 PASS120 (73 canonical vulnerable
cache paths updated);015_final PASS120/0BLOCKED/0PENDING. Benchmark--dry-run PASS,
96development+24diagnostic,90second pacing,0LLM. Authoritative certificate:
results/diagnostics/b9_unblock_acceptance_004/summary.json, final report015_final.
AWS fixed native12GiB extraction+finalize PASS109920/109920. Keycloak pilot002
installed3 checked DBs. Discovered011 PASS depended on transient peer pool;
012 fresh scan118/2failed. Fixed readiness peer reuse to persist missing/invalid
cache aliases, preserve valid physical DBs;240testsPASS,RuffPASS,mypy126filesPASS.
Frozen implementation004. All240 database archive/metadata/model SHA rechecked.
No full query validation/no paid end-to-end/no new detection numbers; workspace
still dirty, actual benchmark Run requires a clean snapshot. Original003 untouched.

2026-10-13: user explicitly authorized a new full B9 end-to-end run in tmux,
including the configured LLM calls. Prepare a clean commit of tested maintenance
changes, then launch run b9_benchmark_120_complete_001 in maxvera-b9-e2e-120.
Use configs/experiments/b9_benchmark_120_complete.yaml unchanged: all120 cases,
90-second request pacing, original LLM budgets and pinned provider. The full
controller performs inputs/discovery/graph/grounding checks before API synthesis;
do not duplicate those stages with a separate validate-only run. Launch metadata,
controller logs and monitoring live under logs/pipeline_v2/b9_benchmark_120_complete_001.
This is a fresh run; preserve original003 and all readiness certificates.
