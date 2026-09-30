# MaxVera — Project Memory

> Cập nhật: 2026-09-30 (Asia/Bangkok)
> Phase 11 canonical run commit:
> `4b898bfe9a3f16c494ec1942caf95f51e29db221`
> Phase 11 development lock commit:
> `faff962b48998ad6f2e596297f9b424810398be4`
> Hiện trạng: Phase 0–11 đã khóa cho development; Phase 11 canonical
> differential full run đã validated với 28 `VERIFIED_DIFFERENTIAL`; Phase 12
> đã implemented, clean pilot validated và đang chờ full calibration run;
> `test_locked` chưa mở/chạy.

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
| Protocol hiện hành | `1.9.0` |
| Dataset chính | `D_extended`: 120 rows, 77 repository groups, 4 CWE |
| Development | 96 opaque projects |
| Locked test | 24 opaque projects, chưa được analyzer truy cập |
| Phase 6 lock | `p6_static_v2_dev_full_001`, static Top-10 |
| Phase 7 lock | `p7_pg_dev_full_004`, 81/96 graph success |
| Phase 8 lock | `p8_skg_global_full_002`, 2,619 nodes / 5,285 edges |
| Phase 9 lock | `p9_useg_dev_full_003`, 81/96 graph success |
| Phase 10 | Locked: B6–B9 full 001 + annotated gate 003 |
| Phase 11 lock | `p11_diff_dev_full_002`, 78/96 success, 28 differential verified |
| LLM cho run mới | `openai/gpt-oss-20b` qua OpenRouter/AkashML |
| CodeQL chính | CLI `2.26.2`, `codeql/java-all@9.2.2` |
| Phase 12 | Implemented; clean pilot `p12_calibration_pilot_003` validated |
| Phase tiếp theo | Phase 12 full development run → threshold lock |

`configs/experiments/main.yaml` vẫn là `draft` cho tới khi Phase 12 clean full
run khóa calibration thresholds. Phase 11 dùng historical protocol `1.8.0`;
Phase 9/10 artifacts giữ contracts `1.6.0`/`1.7.0`.

## Invariant không được phá

- Analyzer chỉ thấy source repository, opaque project ID và metadata build tối
  thiểu; không thấy CVE/CWE thật, advisory, patch/fix, identity mapping hay kết
  quả công bố.
- Split theo repository group. Không dùng `test_locked` để tune prompt, ranking,
  schema, knowledge, threshold hoặc debug Phase 8–12.
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
- `test_locked` chưa mở; chưa được claim final paper performance.

## Handoff Phase 12

Phase 12 implementation/config/validator đã có tại commit `9fd1661`. Clean
pilot `p12_calibration_pilot_003` trên 28 differential findings chọn Platt nhưng
không đủ precision 0.8 để auto-accept; fail-closed `tau_accept=1.0`, 25
`VERIFY`, 3 `ABSTAIN`, zero `ACCEPT`. Tiếp theo chạy full
`p12_calibration_dev_full_001` từ clean commit, validate, rồi pin
model/threshold hashes và chuyển main config sang frozen. Không mở
`test_locked`.

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
