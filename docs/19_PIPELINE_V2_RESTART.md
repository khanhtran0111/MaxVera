# Pipeline v2: audit development và thiết kế chạy lại từ Phase 6

Ngày: 2026-10-05, Asia/Saigon. Quyết định: D-038 (audit), D-039 (implementation).
Audit development Phase 6–10 đã hoàn tất. Theo yêu cầu tiếp theo của người dùng,
runner mới thực thi protocol `2.0.0` trên development, tự động qua các gate trước
API/full/calibration. Chưa có kết quả confirmatory v2 hoặc holdout mới.

## Phục hồi development ngày 2026-10-06 — D-040

Controller `dev_restart_v2_001` dừng ở B6 pilot: 9 specifications resolve vulnerable
endpoints; một request thất bại vì HTTP 429 sau sáu HTTP attempts. Đây là lỗi API,
không phải bằng chứng endpoint sai. P6 có 80 successes, 14 missing DB và hai lỗi
hết đĩa; 15 successes không có grounded candidate (5 thiếu ít nhất một role,
10 có hai roles nhưng không có supported candidate relationship). Không sửa
models/queries/ranking theo observation này hoặc mở test.

Config phục hồi: `configs/experiments/pipeline_v2_recovery.yaml`, controller
`dev_restart_v2_002`; stage IDs dùng hậu tố `_002`. Khởi chạy:

```bash
bash scripts/tools/run_pipeline_v2_recovery_tmux.sh
tmux attach -t maxvera-pipeline-v2-recovery
tail -f logs/pipeline_v2/development_recovery_002.log
```

Preparation ghi immutable report ở
`results/pipeline_v2/database_recovery/p6_database_dev_recovery_v2_002`. Vùng DB
riêng `data/interim/phase7_codeql_databases_v2_002` symlink 82 DB gốc và thử
CodeQL `build-mode=none` cho 14 development source snapshots còn thiếu, tối đa
1.800s/project, 2 threads/8.192 MiB. Ghi Git revision, extraction mode, archive
hash và Java archive support; extraction success chưa chứng minh grounding.
Phase 6 kiểm models/slots/unique bindings thật trên từng DB. Build failures và
empty hypotheses tiếp tục được tính trong toàn cohort 96, không bị loại.

P6 tái sử dụng 80 project successes chỉ sau kiểm toàn checksum index, pin manifest,
scientific asset hashes, AST của discovery loop/inventory/query helpers và DB
source/metadata hashes. P7/P9/dry được tạo mới từ cohort phục hồi. P10 có thể
tái sử dụng specs dưới lineage riêng khi model/provider, context text/schema,
role bindings không đổi và actual vulnerable endpoint query resolve lại. Kế thừa
toàn bộ request/token reservations và call provenance, gồm failed transport;
full runs kế thừa pilot đã qua gate để không reset ngân sách của pilot project.

Transient API error giữ stage unfinished, project PENDING, hypothesis
`RETRYABLE_API_ERROR`; CLI exit 75. Controller cooldown 60/120/240/480/900/900s,
tối đa 6 automatic stage retries, checkpoint/budget vẫn giữ khi resume. HTTP
retry policy/model/provider không đổi. Nonretryable API và budget exhaustion
được tách khỏi grounding rejection. Tối đa ba semantic validation failures mỗi
hypothesis; mọi logical request vẫn nằm trong 30 requests và 160k input/project.

Sau mỗi project P6/P10/P11, dọn regenerable dataset cache và internal query debug
logs; giữ query outputs/logs trong run. Build reserve tối thiểu 30 GiB. Artifact
`_001`, historical test, frozen calibration policy và verifier v3 không bị sửa.
Pilot gates vẫn bắt buộc trước full; P11/P12 và new unopened holdout gate giữ nguyên.

`configs/experiments/pipeline_v2.yaml` là hồ sơ thiết kế, **không phải config
chạy pipeline**; giữ hồ sơ audit tại thời điểm D-038. Config thực thi riêng là
`configs/experiments/pipeline_v2_execution.yaml`, entrypoint `python -m src.pipeline_v2`.
Các entrypoint lịch sử tiếp tục dùng config/protocol lịch sử.

## Bảo toàn lịch sử và phân loại Phase 13

`p13_test_analysis_001` được ghi nhận là **corrective/incomplete**, giữ nguyên
toàn bộ output/manifest/checksum. Phân loại nằm trong hồ sơ v2 và D-038, không
sửa `STATUS` hay verdict bên trong immutable run. Theo yêu cầu người dùng và
audit D-037, test này đã được dùng để phát hiện lỗi verifier; mọi lần chạy lại
trên 24 projects hiện tại chỉ có giá trị diagnostic.

Phase 6–12 cũ giữ historical locks để tái lập. Phase 11 cũ cần được xác minh
lại bằng v3 trên development; không mặc nhiên chuyển 28 differential verdicts
hoặc model/threshold Phase 12 cũ sang v2. Audit này chưa chạy verifier v3 và
không kết luận cả 28 verdicts đều sai.

Phase 8 global KG có thể được tái sử dụng với exact checksum/version nếu
semantic coverage và endpoint contracts mới vẫn phù hợp. Nếu phải đổi API
models/roles, tạo Phase 8 run/version mới trước các downstream locks. Phase
2/build/vulnerable databases cũng có thể tái sử dụng khi source revision và
database provenance khớp; đổi extractor không bắt buộc rebuild mọi DB.

## Kết quả audit tái lập được

Run: `results/audits/p6_p10_dev_audit_v2_001/`.

- `summary.json`: thống kê development và diễn giải từng denominator.
- `cases.jsonl`: 1.398 observation records, có opaque project/hypothesis/node/
  specification ID; nhiều records có thể thuộc cùng hypothesis.
- `input_checksums.json`: hash mọi file trong tám input runs, đã đối chiếu
  với checksum index lịch sử và kiểm tra lại sau audit.
- `manifest.json`, `checksums.sha256`: provenance riêng cho diagnostic run.

Audit dùng đúng 96 development IDs; pin manifest và checksum Phase 6/7/9,
B6–B9, và cached development evaluator `p10_dev_spec_eval_003`. Không đọc
raw evaluator labels/patch, test split hoặc test artifact. Không chạy generator,
LLM, CodeQL, fixed-side query hoặc calibration. Đây là audit cấu trúc và cached
development metrics, chưa phải manual adjudication của vulnerability correctness.

| Quan sát | Kết quả | Hàm ý thiết kế |
|---|---:|---|
| Phase 6 selected hypotheses | 956 trên 96 projects | Top-10 không luôn đủ 10 |
| Hypothesis thiếu source | 251/956 | Gate source bắt buộc đang thiếu |
| Endpoint thiếu symbol | 109/2.239 | Vị trí dòng không đủ mô tả expression |
| Endpoint thiếu enclosing callable | 2.239/2.239 | Chưa ràng buộc method/signature |
| Candidate-pool CWE misses | 12/96 projects | Family balancing chưa giải quyết coverage |
| Phase 7 nodes thiếu enclosing callable field | 275.674/275.674 | Có CALLABLE nodes nhưng thiếu liên kết enclosing signature |
| Phase 9 hypotheses thiếu source Phase 6 | 238/806 | Thiếu grounding vẫn được chuyển downstream |
| Phase 9 source assertions không map Program | 100/1.022 | Assertion provenance chưa đảm bảo endpoint resolve |
| Phase 9 sink assertions không map Program | 97/806 | Cần rejection trước retrieval/synthesis |
| Phase 9 assertions có nhiều Program matches | 238/1.828 | Cần chứng minh tương đương hoặc ghi ambiguity |

Nhiều Program matches có thể là các AST elements hợp lệ của cùng expression.
Audit không coi mọi trường hợp này là mapping sai; contract cũ chưa chứng minh
semantic equivalence để phân biệt chúng.

| Baseline | Specs toàn development | Specs từ hypothesis thiếu source | Source/sink cùng node ID |
|---|---:|---:|---:|
| B6 | 763 | 195 | 96 |
| B7 | 619 | 51 | 0 |
| B8 | 801 | 233 | 16 |
| B9 | 801 | 233 | 18 |

Spec vẫn có thể chọn source từ context khác dù hypothesis gốc thiếu source.
Các số trên chứng minh thiếu gate lineage; chúng chưa chứng minh mọi source
được chọn đều vô nghĩa. Source/sink cùng node cũng cần phân biệt output và
argument/receiver slots thay vì suy ra verdict từ node ID.

Cached evaluator có 91 annotated development projects. Trong B9, chỉ 762/801
specs thuộc tập có annotation: 254 có CWE khớp, 14 khớp paper-compatible
fix-location proxy, và 240 có CWE khớp nhưng không khớp proxy. Không giao patch
vẫn là `UNKNOWN_UNREVIEWED`, không phải false positive. Recall@10 Phase 6
`0.875` chỉ đo **CWE membership**, không đo source/sink/callable hoặc vị trí fix.

## Nguyên nhân trong implementation hiện tại

1. `src/hypotheses/signals.py`: regex phân loại tên API mà chưa resolve receiver,
   declaring type, overload hoặc dataflow slot. `getHeader` của logging API có
   thể bị coi là HTTP source; `print/write/render` chưa chứng minh browser-visible
   output; archive/type mentions chưa chứng minh filesystem write hay evaluator.
   `_symbol()` lấy call cuối trên dòng, có thể khác occurrence mà rule match.
2. `_nearest()` ghép source/sink cùng file trong cửa sổ 120 dòng, không kiểm tra
   enclosing method hoặc def-use. `generate_candidates()` vẫn tạo hypothesis khi
   không có source. Family-balanced ranking cải thiện CWE diversity nhưng không
   kiểm chứng sự liên quan của endpoint.
3. `src/graphs/program/model.py`: ID hash file, span, symbol và type. ID ổn định
   trong cùng extraction nhưng đổi khi insert dòng; thiếu qualified enclosing
   signature và semantic occurrence descriptor.
4. `src/graphs/useg/builder.py`: containment cùng file/dòng và ưu tiên symbol có
   thể map sang enclosing node rộng. Hypothesis/assertion vẫn tồn tại khi endpoint
   không map được. Traceability tới một Program/Security fact chưa chứng minh
   cả hai endpoint của hypothesis có đúng role và semantics.
5. `src/specification/schema.py`: mọi Program node được phép đóng mọi role;
   evidence assertion hoặc global Security API fact cũng được phép làm endpoint.
   `compiler.py` compile query không kiểm tra nó resolve expression nào trên
   vulnerable DB. Generic API descriptors thiếu package/signature/argument slot.

Các quan sát này giải thích vì sao CWE recall, graph trace audit và compile
success cao vẫn có thể dẫn đến endpoint/localization quality thấp. Cần audit
vulnerable source trên development để adjudicate từng case khó; số liệu hiện
tại không đủ kết luận precision vulnerability của toàn pipeline.

## Contract v2

**Phase 6:** tách raw discovery seeds khỏi eligible hypotheses. Seeds thiếu
source được giữ cùng rejection reason để đo coverage, nhưng không được vào
Top-k cho synthesis. Dùng Java syntax/CodeQL inventory trên vulnerable revision
để resolve source/sink occurrence, receiver/declaring type, enclosing qualified
signature, expression kind, return/parameter/argument/receiver slot, file/span
và source checksum. Source signal phải thể hiện input/control boundary thật;
parameter có thể là source nếu có call-boundary provenance. Khoảng cách dòng
không thay flow evidence. Liên kết liên method cần call/def-use provenance.

Inventory này là bước chuẩn bị độc lập trên các vulnerable DB có sẵn, trước
Phase 6 selection; không phụ thuộc graph được seed từ Phase 6, nên không tạo
dependency cycle Phase 6↔7. Project không có database/grounding được giữ status
và ITA miss. Tăng coverage bằng API semantics và caller/callee expansion trên
development; analyzer tiếp tục không nhận ground-truth CWE, fix hoặc advisory.
Version pattern/schema mới phải phân biệt với historical ranking đã tên `v2`.

Đo riêng CWE Recall@k, localization proxy@k, source/sink resolvability,
role-validity và endpoint-grounded Recall@k. CWE diversity không thay localization.
Không đặt recall target mới dựa trên test; freeze targets sau development pilots.

**Phase 7:** giữ `node_instance_id` có revision/source hash và span cho provenance;
thêm semantic descriptor gồm normalized path, qualified enclosing type/method
signature, target symbol/signature, expression kind, dataflow slot và occurrence
fingerprint. File/method/symbol/expression kind vẫn có thể trùng: collision hoặc
duplicate occurrence phải giữ ambiguity, không gộp node tùy tiện. Quan hệ
`EQUIVALENT_TO` xuyên vulnerable/fixed là mapping có bằng chứng riêng, không
hứa một ID tự ổn định qua rename/refactor. Graph scope phải chứa cả hai
endpoints và call-boundary evidence, ghi rõ mọi truncation.

**Phase 9:** chỉ materialize eligible evidence chain khi cả source và sink có
source-backed role provenance, semantic descriptor và resolved Program bindings.
Giữ rejected/ambiguous hypotheses trong diagnostic artifact riêng. Candidate
flow vẫn `unverified_candidate`; generic CWE/Security membership chưa phải
bằng chứng taint chain hay verified vulnerability.

**Phase 10 B6–B9:** role allowlist dựa trên endpoint provenance/dataflow slot,
không chỉ layer membership. Trước API, candidate inventory phải resolve trên
vulnerable DB; sau synthesis, specification phải resolve lại đúng các endpoint
đã chọn. Compile gate giữ riêng. B7 có thể không đưa Program context cho LLM,
nhưng shared endpoint resolver vẫn phải bind global Security facts về occurrence
trong project; ghi việc này thành contract ablation mới cho cả bốn baselines.
Không chạy fixed-side query trong analyzer. API pilot chỉ sau khi dry-run toàn
development của cả B6/B7/B8/B9 không còn missing/ambiguous eligible endpoints,
token overflow hoặc unresolved descriptors; rejected cases vẫn là explicit misses.

**Phase 11 verifier v3:** resolve từng endpoint/slot, không dùng tổng count >0
để bỏ qua partial failure. Mapping tuần tự exact unchanged-line → path/rename
→ enclosing method/symbol/expression equivalence. Ghi source hashes, mapping
rule, alternatives và confidence/basis. Exact text/diff block đơn lẻ không đủ
chứng minh unique callable/occurrence khi có duplicate blocks. Semantic fixed-side
query kiểm tra frozen endpoint contract trong mapped scope; không nới role,
sanitizer hoặc source semantics để tìm một path khác.

Chỉ `VERIFIED_DIFFERENTIAL` khi vulnerable path tồn tại, các endpoint có mapping
tương đương đầy đủ, fixed semantic query chạy thành công và không có corresponding
path. Endpoint bị xóa/đổi, file rename không chứng minh được, mapping ambiguous,
compile/query failure hay thiếu DB đều unverified; endpoint-unresolved không
được chuyển thành fixed-no-path. Regression fixtures phải có line insertion,
rename, overload, duplicate symbol, changed/deleted endpoint, call-slot mismatch,
partial resolution, sanitizer changes và persistent fixed path.

**Phase 12:** chỉ nhận v3 verified findings. Khóa rõ target: contract hiện tại
là candidate-CWE correctness trên verified cohort, không phải vulnerability
correctness/FDR. Không lấy unverified, build failure hoặc patch-proxy nonmatch
làm negative. Nếu muốn calibration cho finding correctness, cần một development
adjudication contract và labels mới trước khi fit.

Group-support minima phải được định lượng và khóa trên development trước fitting;
đếm class support theo repository groups, kiểm tra mọi OOF training fold còn cả
hai classes, và giữ group-level validation. D-039 đăng ký trước full/fitting:
ít nhất 8 repository groups, 5 records mỗi target class, 2 groups mỗi class và
mọi leave-one-group-out training fold còn hai classes. Đây là minimum hỗ trợ
kỹ thuật, không phải chứng minh statistical power; không tái dùng cohort/model cũ.
Nếu không đủ positive/negative/group support thì ghi
`CALIBRATION_INELIGIBLE`, bỏ calibrated `Full`, không dùng probabilities/model cũ.
Routing bảo thủ giữ `ACCEPT` tắt, verified candidates đi `VERIFY` để review,
unresolved/failed candidates `ABSTAIN`; abstention không phải negative.

**Phase 13:** freeze code/config, descriptors, knowledge, budget, verifier,
calibration eligibility/target/model hoặc conservative-routing policy và metrics
trước khi mở holdout mới. `p13_test_analysis_v2_001` trên split hiện tại chỉ
diagnostic. Confirmatory run cần split mới theo repository groups chưa được
dùng cho tuning/debugging, đăng ký manifest/checksum và run ID riêng. Không chỉ
đổi seed/đổi tên split của 24 projects đã mở. Hiện chưa đăng ký holdout này.

## Thứ tự và điều kiện chuyển bước

1. Audit này hoàn tất; historical artifact dispositions được ghi ngoài run roots.
2. Triển khai inventory và Phase 6/7 semantic schema; unit/regression fixtures
   development-only trước pilot và full. Phase 9/10 downstream vẫn đóng tới khi
   đủ grounding contracts.
3. Chạy Phase 6 full v2, Phase 7 full v2 và Phase 9 full v2 bằng run IDs mới;
   validator phải kiểm source/sink semantics, coverage và rejection records.
4. Dry-run toàn development B6–B9; pilot API theo budget/model/provider lịch sử;
   full chỉ từ clean implementation/config snapshot với exact new dependencies.
5. Chạy Phase 11 v3 pilot/regressions rồi full development; audit verdict trước
   khi khóa cohort. Chọn nhánh Phase 12 calibrated/conservative theo eligibility.
6. Khóa toàn pipeline v2. Đăng ký holdout mới nếu cần canonical confirmatory
   claim; diagnostic test cũ có manifest/status ghi rõ diagnostic-only.

Namespace đã đăng ký trong config thiết kế:

```text
p6_hyp_dev_full_v2_001
p7_program_graph_dev_full_v2_001
p9_useg_dev_full_v2_001
p10_b6_dev_full_v2_001 ... p10_b9_dev_full_v2_001
p11_diff_dev_full_v3_001
p12_calibration_dev_v2_001
p13_test_analysis_v2_001  # diagnostic trên split đã sử dụng
```

Các full IDs được controller sử dụng sau khi khóa source snapshot. Pilot/dry-run có IDs
riêng; không dùng full ID cho plumbing. Không cần chạy lại Phase 0–5 trừ khi
source/database provenance hoặc shared comparator contracts yêu cầu.

## Chạy lại audit

```bash
uv run --frozen python -m src.experiments.development_audit \
  --config configs/experiments/pipeline_v2.yaml \
  --run-id p6_p10_dev_audit_v2_002
```

Run mới từ chối test scope, mixed-split records, manifest/hash sai, checksum thiếu
coverage và output đã tồn tại. Tests dùng fixtures không có test split/raw labels,
kiểm immutable inputs và tình huống hypothesis thiếu source vẫn sinh specification.

Validation audit 2026-10-05: 5 audit unit tests trong toàn bộ 152 tests pass;
Ruff, mypy 103 source files và `git diff --check` pass. Audit output checksum
được kiểm tra độc lập sau finalization.

## Implementation và vận hành tự động

`src/pipeline_v2` chứa runner, graph builder, synthesis, verifier v3,
conditional calibration và controller riêng. Các output roots có suffix/version
riêng; không sửa artifact/lock cũ. Full runs yêu cầu working tree sạch và pin
code, query pack, model config, dependency manifests/checksums và development selection.

Phase 6 dùng CodeQL Java models cho CWE-22/78/79/94, remote input, runtime
configuration và archive-entry name. Discovery gồm global taint candidate,
cùng callable hoặc tối đa hai caller/callee steps. Hai loại sau chỉ là structural
candidate, không materialize `TAINT_PATH` hoặc được gọi là flow proof. Ranking
family-balanced Top-10 có score 0.9/0.7/0.6 theo relation; giảm 0.3 khi source/sink
nằm trong path segment `test/tests/testsuite/examples/samples`. Quy tắc chung này
ưu tiên application sources và không dùng ground truth/advisory/fix để chọn hypothesis.

Semantic descriptor pin callable/signature, expression kind, role-specific
return/argument/receiver/parameter slot, target signature, exact expression source
fingerprint và source archive hash. `getProperty(...)` của CodeQL không đủ phân
biệt argument khác nhau. Source-return và sink-argument có thể cùng AST span
nhưng là hai role bindings riêng; binding không phân biệt được vẫn bị loại.
Phase 7 v2 là graph endpoint/callable của các selected hypotheses, không phải
historical CPG đầy đủ. B6–B9 là ablations của graph contract mới, không so trực
tiếp số node hay kết quả với historical runs như cùng một implementation.

Phase 9 dùng CWE facts từ Phase 8 đã pin và project-specific typed role-model
bindings có provenance, không dùng generic API fact làm resolved endpoint.
Phase 10 lưu context/schema/response, reserve API attempts trước request để
resume không reset budget, checkpoint từng hypothesis, resolve lại mọi frozen
endpoint trên vulnerable DB. Context serialization giữ các role bindings của
hypothesis hiện tại, kể cả khi B8 retrieve rộng.

Verifier v3 kiểm source hashes trước query, unique resolution từng role, exact
unchanged-line và full semantic equivalence; rename phải có unique match.
Fixed inventory và fixed path query đều có provenance. Duplicate occurrences,
đổi symbol/slot/expression/model, thiếu database và query/budget failures đều
giữ trạng thái `UNVERIFIED_*`. USEG iteration-1 delta chỉ có `VERIFIED_BY` khi
hai sides chứng minh differential; unresolved không trở thành negative evidence.
Giới hạn 40 query invocations/project gồm cả query thất bại hoặc timeout.

Phase 12 chỉ fit Platt/isotonic/logistic và chọn theo group-OOF Brier/ECE/AURC
nếu eligibility gate pass. ACCEPT còn cần ít nhất 20 accepted OOF records,
3 groups và Wilson lower bound 95% ≥ 0.8; bound này ở cấp observation, không
chứng minh độc lập giữa observations cùng repository. Thiếu support thì ACCEPT
tắt. Khi calibration ineligible: bỏ calibrated Full, verified → VERIFY,
unverified → ABSTAIN. Không gán probability cho unresolved hoặc dùng chúng làm negative.

Chạy full trong tmux, sau clean local implementation commit:

```bash
bash scripts/tools/run_pipeline_v2_tmux.sh
tmux attach -t maxvera-pipeline-v2-dev
tail -f logs/pipeline_v2/development_full.log
```

Controller tự chạy Phase 6 → 7 → 9 → **dry-run toàn 96 development projects
của B6–B9** → API pilot từng baseline → full B6–B9 → evaluator Phase 11 v3 →
conditional Phase 12. Không chạy Phase 13. Process evaluator tách khỏi analyzer.
Stage/gate failure dừng controller và lưu `failure.json`, không mở downstream
hoặc bỏ qua failed pilot. Khi không có grounded hypothesis, skip pilot ghi rõ
API chưa được validated; không tạo specification hay calibration giả.

Tiến độ nằm trong `results/pipeline_v2/.dev_restart_v2_001.inprogress/steps.json`
và các stage `project_status.jsonl`. Resume dùng cùng command với `--resume`,
chỉ khi code/config/inputs không đổi. Nếu cần sửa implementation sau gate failure,
giữ run cũ và đăng ký namespace mới, không sửa hay promote diagnostic pilot.
Kết thúc development mới ghi `development_lock.json` và finalize controller;
`confirmatory_test_ready=false` đến khi đăng ký holdout chưa mở.

Pilot plumbing được giữ trong `results/hypotheses/grounded_v2/p6_hyp_dev_pilot_v2_*`,
`results/graphs/*_v2/*pilot*` và `results/specifications/v2/*/*drypilot*`.
Diagnostic live verifier `results/grounding/v3_query_dev_pilot_v2_001` đã resolve
vulnerable endpoints và một path, rồi trả `UNVERIFIED_FIXED_ENDPOINT_MAPPING`
khi fixed mapping ambiguous. Đây là diagnostic không LLM, không phải API pilot
hoặc canonical full. Các pilot lỗi/không có hypothesis vẫn giữ nguyên để audit.

Quality validation: 182 tests pass, Ruff toàn repo, mypy 113 source files và
`git diff --check` pass. Tám historical development input runs giữ valid checksums.
Live diagnostic 002 resolve cả hai sides và trả `UNVERIFIED_PERSISTS_FIXED`;
đây không phải một verified differential finding.

Pilot 007 dừng aggregate QL quá nặng và giữ analysis failure/log riêng. Bản cuối
decode BQRS với internal entity IDs, kiểm unique node theo role/descriptor xuyên
model bases trong Python; không dùng các IDs này để map xuyên phiên bản. Pilot
008 có 10 hypotheses và graph/dry B6–B9 pass, 0 API. Launcher tmux từ chối duplicate
session, dirty snapshot và completed controller; tự thêm --resume cho controller
chưa hoàn tất. Detach bằng Ctrl+b rồi d, phiên vẫn chạy khi đóng terminal.

### Snapshot khởi chạy đã sửa: 003

Preflight thực tế phát hiện 002 không truyền pinned Maven/JDK vào PATH, extractor
fallback minimal JDK. Controller002 được ngắt trước API; partial preparation và
DB trial giữ diagnostic, không được promote hoặc tái dùng. Config/script002 giữ nguyên.
Snapshot003 dùng `configs/experiments/pipeline_v2_recovery_003.yaml`, controller
`dev_restart_v2_003`, stage suffix003, DB root `phase7_codeql_databases_v2_003` và
launcher `scripts/tools/run_pipeline_v2_recovery_003_tmux.sh`, tmux
`maxvera-pipeline-v2-recovery-003`, log `logs/pipeline_v2/development_recovery_003.log`.

Extraction environment chọn pinned JDK/Maven/Gradle từ opaque analysis manifest,
đặt JAVA_HOME và PATH, ghi toolchain provenance. Preflight xác minh binaries cho
cả 14 source trees trước launch. Cancellation của subprocess giờ terminate toàn
process group để không để lại extractor giữ lock. Legacy scientific reuse checks
chỉ bỏ qua đúng cancellation handler đã đăng ký; query/extraction helpers khác,
model/provider payload, inventories và discovery vẫn phải tương thích.

### B9 development end-to-end — D-041 (2026-10-08)

Controller003 đã STOPPED_AT_GATE ở B6 full/HTTP429. Controller B9 riêng reuse pinned
inputs003; fixed preparation chọn actual v2 cohort và giữ parent DB/status nguyên vẹn.

```bash
bash scripts/10_run_b9_full_useg.sh --pipeline-v2 --mode full \
  --run-id b9_e2e_dev_full_v2_005 --dry-run
bash scripts/tools/run_b9_v2_tmux.sh --mode pilot \
  --run-id b9_e2e_dev_pilot_v2_005 \
  --inherit-run results/specifications/v2/b9/b9_e2e_dev_pilot_v2_004_synth \
  --confirm-api-spend
```

Preflight dry không gọi API. Controller chạy actual B9 dry → API pilot → fixed
DB → verifier v3 → conditional routing → validator. Full tự chạy pilot end-to-end
và kế thừa responses/budgets cùng snapshot, sau clean local commit:

```bash
bash scripts/tools/run_b9_v2_tmux.sh --mode full \
  --run-id b9_e2e_dev_full_v2_005 \
  --inherit-run results/specifications/v2/b9/b9_e2e_dev_pilot_v2_005_synth \
  --confirm-api-spend
bash scripts/tools/validate_b9_v2.sh \
  --run-root results/pipeline_v2/b9/b9_e2e_dev_full_v2_005
```

Launcher từ chối duplicate session; xem pane/log để biết job đang chạy hay đã dừng.
Resume numbered script với cùng flags và --resume; không sửa code/config giữa run,
không overwrite finalized output. HTTP retry exhaustion ghi WAITING_FOR_API/exit75,
giữ checkpoints/counters/budgets. Outputs: findings.jsonl, metrics_operational.json,
validation.json, report.md, development_lock.json và immutable stage IDs/checksums.
Conservative VERIFY/ABSTAIN vẫn hoàn tất kỹ thuật khi calibration ineligible,
nhưng không phải calibrated Full/confirmatory evaluation. Holdout mới vẫn chưa mở.

Pilot004 dừng đúng gate do verifier cần41 queries trong budget40. Giữ artifacts004;
pilot005 dùng endpoint batching (23 queries/10 fully mapped specs), kế thừa synthesis004
qua --inherit-run với scientific compatibility và actual vulnerable re-resolution.
Không resume004 bằng source đã thay đổi. HTTP429 vẫn có thể xảy ra dù pacing15s.

Pilot005 đã PASS validator độc lập: 10 specs, 23 query attempts, 0 verifier failures;
10 UNVERIFIED_PERSISTS_FIXED → 10 ABSTAIN, 0 differential verified. Không gọi API mới;
responses/reservations004 được kế thừa. Report:
`results/pipeline_v2/b9/b9_e2e_dev_pilot_v2_005/report.md`.
Full96 và 12 missing fixed DB builds chưa chạy; holdout/calibration claims chưa đủ.
Nếu tmux maxvera-b9-v2 chỉ còn idle shell sau Controller exit code:0, đóng session
đã hoàn tất (`tmux kill-session -t maxvera-b9-v2`) trước khi dùng launcher cho full005.

### B9 đủ 120 cases — D-042 (2026-10-08)

Profile riêng chọn96development +24historical test, diagnostic-only; calibration
fit96development. Same120CVEs, một số source refs của D_extended khác D_repro_v1.
Model/toolchain/zero-hint khác bài gốc; paper-reference report ghi rõ scope.

```bash
bash scripts/10_run_b9_full_useg.sh --pipeline-v2 --benchmark-120 \
  --run-id b9_benchmark_120_v2_001 --dry-run
bash scripts/tools/run_b9_benchmark_120_tmux.sh \
  --run-id b9_benchmark_120_v2_001 --confirm-api-spend
tmux attach -t maxvera-b9-benchmark-120
tail -f logs/pipeline_v2/b9_benchmark_120.log
```

Dry input preflight gọi0API; registered selection120,119 historical vulnerable DBs,
120source repos. Inputs/P6/P7/P9 → grounding dry → pilot end-to-end → full120
synthesis/fixed/v3/routing → evaluator. Missing DB/build/query/API failures vẫn có
explicit statuses; completion counts120, không có nghĩa mọi120 phân tích thành công.
Giữ source/config clean trong suốt run; tmux chạy nền khi terminal detach.

Resume interrupted controller bằng numbered script và cùng frozen snapshot:

```bash
bash scripts/10_run_b9_full_useg.sh --pipeline-v2 --benchmark-120 \
  --run-id b9_benchmark_120_v2_001 --resume --confirm-api-spend
bash scripts/tools/validate_b9_v2.sh \
  --run-root results/pipeline_v2/benchmark/b9_benchmark_120_v2_001
```

Không chạy resume đồng thời với tmux controller còn active. Final controller có
report.md, table_paper_comparison.csv, metrics_paper_proxy.json, case_alignment.json,
benchmark_lock.json, validation.json, findings.jsonl. Evaluator giữ120rows/variant,
AvgFDR chỉ cases có paths; AvgF1 và detection rate denominator120 gồm analysismisses.
Validator kiểm lineage/checksums, fitdevonly, full cohort và regenerate aggregates.
Chưa có full120 result tại thời điểm đăng ký profile; preflight/test không thay cho
actual live-run completion hoặc claim calibrated Full.
