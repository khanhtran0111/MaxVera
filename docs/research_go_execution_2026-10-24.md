# Research Pipeline — thực thi các bước để GO, 24/10/2026

Branch `refactor/pipeline-first-v2`, HEAD `92416c8`. Giữ nguyên các sửa đổi từ
đợt readiness trước; không reset, reinitialize, chạy IRIS reproduction, sửa frozen
artifacts hoặc checkout `third_party`. Bản sao toàn bộ working tree đầu tác vụ
được giữ trong `logs/research_go_20261024/initial_worktree.patch` và
`initial_state.json`.

**GO cho engineering smoke hai case đã chạy. NO-GO cho scientific pilot10 và
full120.** Gate nguồn/recipe hiện đạt 10/10 pilot và 11/120 ở full prepared view;
truth aligned đạt 6/10 pilot và 6/120 full. Không giảm cohort để thay đổi kết luận.

## Các blocker đã sửa

- **Truth alignment:** phân biệt tọa độ tại fix commit với vulnerable commit.
  Preflight/evaluator xác minh source provenance, inventory, hash và span. Nhãn
  không resolve vẫn unknown; report giữ nguyên cohort và để whole-cohort recall
  `null`. Mapping phải gắn với exact truth row/source inventory và review evidence.
- **Evaluation revisions:** output mới nằm ở
  `zero_hint_aligned_v1/<condition_hash>/`; sửa mapping không yêu cầu chạy lại
  analyzer hoặc ghi đè evaluation cũ. CLI trusted có `--truth-alignment` và
  `compare --evaluations` để chọn rõ revision.
- **Static verification:** giữ full SARIF source/sink spans và provenance, chuyển
  exclusive end column sang CodeQL inclusive column, kiểm UTF-16 và source
  boundary/hash. Chỉ query flow khi source và sink mỗi bên bind đúng một node;
  zero/multiple binding vẫn uncertain và không bị bỏ khỏi candidate pool.
- **Hai lỗi phát hiện qua review độc lập:** dedup static/graph phải khớp full
  source **và** sink span; overlap cùng dòng không được làm mất candidate. Mapping
  hợp lệ có thể cung cấp vulnerable span khi nhãn gốc thiếu span. Target hash
  null và malformed mapping objects bị từ chối rõ ràng.
- **Failed-extraction accounting:** nếu build thất bại trước analyzed inventory,
  evaluator vẫn có thể xác minh exact frozen input và tính case đó là analysis
  failure trong mẫu số recall. Chỉ cho phép bảy failure codes thực tế; không
  fallback qua inventory hỏng, SUCCESS thiếu inventory, source thay đổi hoặc
  active/unknown status. Không reseal artifacts để làm integrity pass.

Production code tương ứng: `maxvera/truth_alignment.py`, `preflight.py`,
`evaluation.py`, `evaluator_identity.py`, `cli.py`, `sarif_endpoints.py`,
`candidates.py`, `research.py`, `research_verification.py`.

## Kiểm chứng đã hoàn thành

- Regression đã quan sát RED trước GREEN, gồm hai fix wave sau independent review.
- Default suite cuối: **662 passed, 5 skipped**, 31,68 giây.
- Ruff toàn repository pass; mypy cấu hình `src` pass, 126 files; diff check pass.
- Fixture CodeQL/SARIF thật: **1 passed, 193,74 giây**. Official query tạo path từ
  Java độc lập có Unicode; adapter bind 1/1 và tìm modeled flow. Interior span
  không khớp AST bind 0 và giữ `UNSUPPORTED_SPEC`.
- Query inventory độc lập trên **bản sao** hai database cũ: cả sáu candidate từng
  unsupported đều bind 1 source / 1 sink. Database critical inventories và toàn bộ
  frozen run cũ không đổi. Đây là kiểm tra binding, chưa thay thế một pipeline run.
- Review cuối xác nhận không còn P0/P1 trong hai fix wave;
  `logs/research_go_20261024/final_repairs_review.md` ghi bằng chứng.
- Failed-extraction regression: RED 2 failures, sau fix và status hardening
  **9/9 pass**, review độc lập sạch; log `truth_failure_*` và
  `final_eval_failure_fix_review.md`. Các trường hợp corrupt/SUCCESS/nonterminal
  vẫn fail closed.

Các entry point để review: `truth_alignment.py:67` (source proof/failure fallback),
`candidates.py:208` (exact dedup), `sarif_endpoints.py:125` (raw provenance và source
binding), `research_verification.py:48` (targeted queries), `preflight.py:177`
(trusted readiness), `evaluation.py:228` (immutable evaluation).

## Pilot inputs và truth có bằng chứng

Đã chuẩn bị **10/10 source pilot**, gồm chín snapshot mới từ pinned vulnerable
commits và một Spring snapshot đã audit được reuse. Mỗi snapshot mới được so với
một git archive độc lập và upstream build patch. Giữ manifest đủ 120 rows và
đúng mười IDs cố định; profile mới là
`configs/pipelines/research_pilot10_prepared.yaml`. Chín project mới chưa được
build/resolve dependency; available recipe không chứng minh build thành công.

Trusted review đã thu thập bằng chứng Git cho 67 annotation của mười development
cases, không dùng locked cases để tuning. Hai row mapping được kiểm riêng:

- one-java-agent: `IOUtils.unzip`, vulnerable lines 106–161; actual fix xóa đúng
  method này. Annotation gốc dùng fix-side class span nên bỏ gần hết body.
- Spring: `DefaultHttpFirewall.getFirewalledResponse`, vulnerable lines 35–37;
  source blob, rename và actual first-parent fix chứng minh correspondence.
  Hai annotation Spring khác chưa resolve, nên toàn bộ Spring case vẫn unknown.

Mapping mới được lưu riêng tại
`data/processed/evaluator_only/go_20261024/reviewed_pilot_alignment_v1.json`, kèm
source/truth/evidence hashes. Đây là review tự động của code/source và Git diff,
không phải security adjudication hay phê duyệt graph signal. Không sửa nhãn gốc,
không đưa mapping vào analyzer view. Preflight với artifact này: **10/10 inputs,
1/10 truth aligned**, overall NO-GO.

Review tiếp theo đã xác minh thêm 53 row bằng AST và actual first-parent Git
objects. Root kiểm độc lập source Git blobs, full inventory, exact method bytes/
ranges, unique class/method/parameters và AST equality với fix parent trước khi
seal revision v2 riêng:
`data/processed/evaluator_only/go_20261024_v2/reviewed_pilot_alignment_v2.json`.
Giữ nguyên v1, đủ 67 original row digests và mười case IDs. V2 có 55 mapped rows,
12 unresolved; **6/10 case aligned**, gồm one-java, NiFi, Venice, Vert.x, ff4j và
Jolokia. Spring, Tika, AntiSamy và DolphinScheduler vẫn unknown. Preflight vẫn
NO-GO; location alignment không tự chứng minh annotation là một lỗ hổng đúng.

Jolokia có một metadata correction được ghi rõ: nested declaring class và
`String...` bị annotation upstream mô tả thiếu. Tika có helper mới không tồn tại
ở vulnerable commit; Dolphin có security-guard/API differences giữa hai nhánh;
không tự map các trường hợp này bằng method name. Evidence và receipt v2 ở
`additional_truth_mapping_review_notes.md`, `reviewed_truth_v2_receipt.json`.

Tiêu chí tối thiểu để mở rộng thí nghiệm đã được ghi nhận **trước scientific
pilot** trong [pilot acceptance](research_pilot_acceptance_2026-10-24.md): primary
strong Top-5, tín hiệu graph không trùng default alert, paired ranking, coverage
và engineering gates. Không có pilot khoa học nào được thực thi theo tiêu chí này.

## Smoke kỹ thuật mới

Run `research_go_20261024_smoke02` dùng hai snapshot đã xác minh của profile
`research_smoke_ready.yaml`, variant `graph_llm_verify`, GPT-OSS-20B/Groq,
Top-5/case, tối đa 60 calls và $1/case, 7200 giây/case, 900 giây/query,
RAM CodeQL 4096 MB / hai threads. `graph_signal_approved` vẫn false.

Mục đích là kiểm chứng engineering sau sửa endpoint verification. Truth của hai
case chưa đủ để chấm recall; lượt này không phê duyệt pilot khoa học hoặc full120.
Implementation hash trước chạy:
`cc37a8df34079180176df38f259f2defc317b96447746099c8cb3a36b84bdba8`.

Run hoàn thành **18/18 stage**, exit 0. Tổng thời gian hai case **1.847,1025 giây**
(khoảng 30 phút 47 giây):

| Kết quả | RocketMQ | Spring |
|---|---:|---:|
| Raw → retained → final | 396 → 5 → 5 | 409 → 5 → 5 |
| Giây/case | 1.063,8738 | 783,2287 |
| Assessment VALID | 5/5 | 5/5 |
| Verification | 1 FLOW_FOUND, 4 NO_FLOW_FOUND | 5 FLOW_FOUND |
| Exact unique source/sink | 5/5 | 5/5 |

`engineering_pass=true`, không quality blocker, verification supported **100%**,
không discovery truncation hoặc missing endpoint evidence. Hai bundle có interior
context truncation được ghi rõ nhưng đủ endpoint code. Sáu candidate từng
unsupported đã query được; không bỏ uncertain candidate hoặc đoán node theo dòng.

10 API attempts đều SUCCESS/RECEIVED qua Groq, 18.231 input + 2.593 output tokens,
reported cost **$0,002145225**, unknown-cost=0, không PENDING/UNCERTAIN còn mở.
`FLOW_FOUND` chỉ chứng minh modeled reachability; không chứng minh khai thác được,
và `NO_FLOW_FOUND` không chứng minh safety.

Resume **cùng implementation/config/input** pass trong **17,431 giây**, giữ nguyên
**15.539 file**, checksum index và journal; 10 calls trước/sau, **0 paid call mới**.
Sau freeze/resume mới sửa evaluator-only failure accounting và đồng bộ/thêm
prepared profiles. Analyzer/CodeQL/LLM implementation cùng smoke profile không đổi.
Current global implementation hash là
`66f8f8a74241f542bb4001543aa70602ba3d43ec6841552cf0bea85aaafac51c`.
Vì hash bao gồm cả trusted evaluator và toàn bộ configs, resume run cũ bằng code
cuối phải bị từ chối đúng identity guard; không nới guard để dùng lại checkpoint.
Exact code/config của smoke được lưu ở `smoke02_implementation.tar.gz` và JSON
hash manifest; chạy bản sửa mới dùng run ID mới. Negative resume với code cuối
đã được kiểm: bị từ chối trước stage/paid call, frozen run vẫn nguyên vẹn
(`changed_code_resume_rejection.json`).

Evaluator cuối xuất revision mới:
`results/evaluations/research_go_20261024_smoke02/zero_hint_aligned_v1/50a7164bc105d58881871028afab12d24eb20a3c52f688d9ec56d90540bc9367/`.
**0/2 case evaluable**, whole-cohort discovery/ranked recall đều `null`; engineering
acceptance không được chuyển thành scientific recall. Frozen smoke/evaluation cũ,
dataset release checksum và split giữ nguyên. Scan 23.212 file của run mới,
evaluation và task logs không thấy giá trị credential thực đã dùng.

## Gate còn lại và cấu hình resolved

| Profile đã chuẩn bị | Selected | Source/recipe preflight | Truth aligned | Gate |
|---|---:|---:|---:|---|
| Pilot10 prepared | 10 | 10 | 6 | NO-GO: bốn case cần semantic truth review |
| Full120 prepared | 120 | 11 | 6 | NO-GO: 107 source thiếu, hai snapshot thiếu manifest; truth chưa đủ |

Bảy case thiếu original truth vẫn nằm trong cohort120; không có annotation giả
để lấp coverage. Chín source mới chưa được build/resolve dependency; smoke chỉ
xác nhận hai project đã có audited inputs. Giữ nguyên development96/locked24 và
portable profiles cũ. Prepared views tham chiếu source đã xác minh, không sửa
canonical manifest hoặc snapshot cũ.

Prepared pilot và full profiles dùng runtime_fast với GPT-OSS-20B/Groq như smoke;
graph_only là mặc định, approval=false. Cutoffs [5,10,20], 30 calls/$1/case,
160.000 input/60.000 output tokens, 7200 giây/case, CodeQL query 600 giây,
8192 MB/một thread; traversal cap 4096 (pilot dùng code default). Đây là resolved
configuration/preflight, chưa là xác nhận performance của pilot/full. Smoke dùng
profile riêng đã ghi ở trên, không đồng nhất ngân sách hay resource usage hai lượt.

Resolved configs nằm trong `pilot_prepared_final_dry_run.json`,
`full120_prepared_final_dry_run.json` và run `config.resolved.yaml`.

## Lệnh thực tế và gate

```bash
.venv/bin/python -m pytest -q
.venv/bin/ruff check .
.venv/bin/mypy src

MAXVERA_RUN_CODEQL_FIXTURE=1 .venv/bin/python -m pytest -q -s \
  tests/integration/test_sarif_endpoint_codeql.py

.venv/bin/python -m maxvera preflight \
  --config configs/pipelines/research_pilot10_prepared.yaml \
  --variant graph_only --mode full \
  --truth-alignment data/processed/evaluator_only/go_20261024_v2/reviewed_pilot_alignment_v2.json

.venv/bin/python -m maxvera preflight \
  --config configs/pipelines/research_full120_prepared.yaml \
  --variant graph_only --mode full \
  --truth-alignment data/processed/evaluator_only/go_20261024_v2/reviewed_pilot_alignment_v2.json

MAXVERA_OPENROUTER_PROVIDER=groq .venv/bin/python -m maxvera pipeline research \
  --config configs/pipelines/research_smoke_ready.yaml \
  --variant graph_llm_verify --mode smoke --limit 2 \
  --run-id research_go_20261024_smoke02 --execute

.venv/bin/python -m maxvera evaluate \
  --run-id research_go_20261024_smoke02 --protocol zero_hint --missing-truth report \
  --truth-alignment data/processed/evaluator_only/go_20261024_v2/reviewed_pilot_alignment_v2.json

.venv/bin/python -m maxvera pipeline research \
  --config configs/pipelines/research_pilot10_prepared.yaml \
  --variant graph_only --mode full --run-id research_go_20261024_pilot10_graph_final --dry-run

.venv/bin/python -m maxvera pipeline research \
  --config configs/pipelines/research_full120_prepared.yaml \
  --variant graph_only --mode full --run-id research_go_20261024_full120_graph --dry-run
```

Preflight pilot exit 1 đúng vì truth còn thiếu alignment. Không thực thi pilot
khoa học khi gate này chưa đạt. Full120 còn cần source/build/provenance đầy đủ,
truth đủ và đúng vulnerable snapshot, quality acceptance, tiêu chí khoa học chốt
trước pilot và reviewed graph signal. Không dùng stage `COMPLETED`, một mapping
thành công hoặc flag cấu hình để thay thế các điều kiện đó.

Artifacts tác vụ ở `logs/research_go_20261024/`: receipts input, evidence mapping,
RED/GREEN logs, default-suite log, reviewer reports, actual CodeQL fixture và
`real_sarif_bindings/receipt.json`. Các frozen output trước đó được giữ nguyên.

- `research_go_complete.patch`: toàn bộ diff từ baseline, gồm cả file mới và công
  việc của đợt trước; reverse-apply check pass, không staging/commit/push.
- `go_changes.diff`: chỉ delta so với working tree khi bắt đầu tác vụ GO.
- `handoff_diff_verification.json`: patch/source hashes, số file và git status.
- `final_smoke_inspection.json`, `smoke02_resume_verification.json`,
  `changed_code_resume_rejection.json`: quality, usage, integrity và resume proof.
- `preflight_{pilot,full120}_prepared_final.json`: gate cuối với mapping v2.
- `smoke02_config.resolved.yaml`, `{pilot,full120}_prepared_final_dry_run.json`:
  cấu hình thực tế và cấu hình cho các lượt còn bị gate.

## Instruction cho coding agent tiếp theo

Tiếp tục trên `refactor/pipeline-first-v2`, baseline `92416c8`, giữ toàn bộ dirty
tree và các artifacts đã hoàn thành; không reset/stash, reinitialize, sửa frozen
artifacts, checkout `third_party` hoặc chạy IRIS reproduction. Đọc báo cáo này,
`final_smoke_inspection.json`, `reviewed_truth_v2_receipt.json` và các reviewer
reports trước khi sửa. Không làm lại các blocker code đã có regression pass.
Ưu tiên semantic adjudication cho Spring/Tika/AntiSamy/Dolphin bằng exact pinned
source/fix history; viết mapping revision v3 riêng nếu chứng minh được, giữ row
và case unresolved khi chưa đủ bằng chứng. Không dùng locked24 để tuning. Sau khi
pilot10 đủ truth, chạy static_only → graph_only theo preregistered acceptance,
review graph signal rồi mới mở LLM pilot. Chuẩn bị/xác minh các source/build còn
thiếu và freeze full120 config trước full execution. Không bật approval để vượt
guard; không sửa checksum/identity để resume code mới. Ghi nhận NO-GO nếu bất kỳ
gate nào chưa đạt, kèm evidence và next action cụ thể.
