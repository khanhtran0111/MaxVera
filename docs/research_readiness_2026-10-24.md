# Research Pipeline readiness — 24/10/2026

Đợt sửa tiếp theo và kết quả mới được ghi tại
[Research GO execution](research_go_execution_2026-10-24.md). Các số liệu bên dưới
là lịch sử của đợt readiness đầu tiên; coverage record không thay thế truth alignment.

Baseline: `92416c818f4daa7e5c496d008087d76ba0358ea7`, branch
`refactor/pipeline-first-v2`. Git sạch khi bắt đầu. Các thay đổi được thực hiện
trực tiếp trên branch này; không khởi tạo lại dự án, không thay checkout
`third_party`, không chạy IRIS reproduction và không sửa artifacts đã freeze.

**Full 120: NO-GO.** Profile full120 và các cơ chế kiểm tra đã được bổ sung;
điều đó chưa cung cấp 116 source còn thiếu, truth cho bảy case hoặc quyết định
graph-signal gate. Smoke mới hoàn thành 18/18 stage và 10/10 assessment hợp lệ,
nhưng sáu candidate chưa được hỗ trợ verification. Recall@5 tính được là 0/2;
kiểm tra bổ sung phát hiện truth chưa khớp vulnerable snapshot, nên chưa dùng
con số này để kết luận chất lượng discovery (xem phần bổ sung cuối báo cáo).
Không bật `graph_signal_approved` để vượt guard.

## Các sửa đổi và cách xác nhận

| Blocker | Thay đổi | Regression / bằng chứng |
|---|---|---|
| Selection 120/96 | Giữ `expected_cases` là tổng manifest, thêm `expected_selected_cases` sau lọc; giữ split 96/24 và thêm profile development pilot10/full120 | `test_research_input_preflight.py`; full120 dry-run chọn đúng 120 |
| Thiếu source/recipe | Kiểm tra toàn bộ selected inputs trước tool/model; báo tất cả source, build recipe, manifest hoặc tool còn thiếu | Preflight không gọi network/tool; fixture khẳng định execution bị chặn trước khi tạo run |
| Thiếu truth | Strict mặc định vẫn từ chối; `--missing-truth report` giữ đủ cohort, đánh dấu `GT_MISSING`/`GT_MISSING_SPAN`, full-cohort recall=null; subset có mẫu số riêng | `test_research_truth_coverage.py`: 120 row, 113 evaluable, 7 unknown; không giảm mẫu số ngầm |
| Preparation dừng ở snapshot tồn tại | Manifest versioned có hash/provenance; reuse sau xác minh, atomic temporary preparation và tiếp tục theo case; không ghi đè legacy | Reuse hai lần, interruption/partial failure, changed recipe/source, legacy preservation và audited copy |
| Metadata làm đổi Top-K | Tách semantic source identity khỏi full build identity; generated Java vẫn vào semantic inventory; canonical program-point traversal/rank keys | `test_discovery_readiness.py`: timestamp/workspace metadata đổi nhưng semantic candidates/ranks giữ nguyên; Java đổi vẫn invalidate |
| Expanded varargs | Dùng `Argument.getParameterPos()` trong query research | Tiny CodeQL thật: RED thiếu expanded argument; GREEN có complete flow cho expanded, ordinary và explicit-array control |
| Traversal giới hạn ngầm | `research.max_traversal_nodes`, diagnostics và candidate truncation flags | Graph fanout vượt cap phải báo `DISCOVERY_TRUNCATED`; cấu hình cap lớn tìm được path |
| Static alerts ngoài source | Source scope chung, giữ raw signals/SARIF, ghi excluded/mixed locations; unsafe path hoặc known-source mutation fail closed | External-only/mixed/source flows; hidden path, traversal, symlink, source hash mutation |
| Retrieval không đủ endpoint | Bundle ghi `evidence_complete`/`missing_evidence`; thiếu endpoint thực sự hoặc bị clip thì không gọi model; candidate vẫn còn | Graph/static endpoint omission, clipped column, missing safe evidence; source mutation vẫn lỗi |
| Deadline LLM | Absolute case deadline qua pacing/backoff/connect/response read; socket timeout clamp, không đưa deadline vào cache key | `test_llm_deadline.py`: slow success/error body, expired request, rate limit, replay/UNCERTAIN và timer restoration |
| COMPLETED che quality | `quality_report.json` riêng execution status; status/worker in acceptance summary; không prune uncertainty, không gọi no-flow là safety | `test_research_acceptance.py`: failed assessment, missing accounting, unsupported verification, traversal truncation |
| Retain quét toàn edges | Edge-ID index và path-only lookup | Counting-iterator regression trong `test_discovery_readiness.py` |

Full analyzed inventory, source hashes, DB identity và frozen run checksums vẫn
được giữ. Semantic identity không được dùng để bỏ qua integrity khi resume.
Paired evaluation so semantic candidate pool; full build provenance vẫn có riêng
trong evaluator output và bị ràng buộc bởi run checksum.

Retrieval có thể cắt bớt interior context theo budget và đếm
`retrieval_truncated_bundles`; chỉ được coi complete khi code của cả hai endpoint
thực sự hiện diện. Discovery traversal bị cắt là blocker engineering acceptance.
`FLOW_FOUND` chỉ chứng minh modeled reachability; `NO_FLOW_FOUND` không chứng minh
an toàn. Unsupported verification vẫn hiện diện và làm quality gate không đạt.

## Kiểm chứng

Các nhóm regression được chạy RED trước sửa rồi GREEN. Log đã lưu tại
`logs/research_readiness_20261024/` gồm root regressions, discovery/static
integrity và CodeQL varargs. Default-suite log bao phủ cả deadline/reasoning và
input/preparation; không gộp log lịch sử trong `/tmp` vào bằng chứng tác vụ mới.

- Default suite kiểm lại sau smoke: **569 passed, 4 skipped**, 25,13 giây.
- Ruff toàn repository: pass.
- Mypy phạm vi cấu hình `src`: pass, 126 files; không tuyên bố mypy bao phủ toàn `maxvera`.
- CodeQL identity fixture: **1 passed**, 193,81 giây, decoded source=1/sink=1/flow=1.
- CodeQL varargs fixture: **1 passed**, 136,55 giây sau RED.
- Các fixture này không dùng benchmark cases hoặc model.

## Input và cấu hình

`configs/pipelines/research.yaml` tiếp tục chọn 96 development cases.
`configs/pipelines/research_pilot10.yaml` chọn mười development IDs cố định;
cohort được lưu trong `research_pilot10.csv`, không chọn lại theo kết quả chạy.
`configs/pipelines/research_full120.yaml` chọn đúng 120 IDs, không lọc split.
Split development/test_locked gốc không đổi.

Profile smoke mới `research_smoke_ready.yaml` dùng hai case RocketMQ/Spring của
lượt engineering trước, không phải một phép đánh giá blind mới. Source được copy
sang view `readiness_20261024/projects/` sau khi so byte inventory với ingest của
run r3 đã kiểm checksum. Source/dependency/recipe cũ không bị ghi đè. Copy có
manifest versioned và proof SHA256 trỏ về audited ingest. Ledger:
`logs/research_readiness_20261024/prepared_smoke.json`.

Smoke dùng GPT-OSS-20B/Groq, temperature 0, top-p 1, output cap 2048, Top-5/case;
60 attempts và ngưỡng dừng $1/case, 7200 giây/case, 900 giây/query, CodeQL RAM
4096 MB và hai threads. Ngưỡng dollar không phải prepaid cap của provider.

Preflight hiện tại:

| Profile | Selected | Input sẵn sàng | Truth có span | Kết quả |
|---|---:|---:|---:|---|
| Smoke mới | 2 | 2 | 2 | GO cho engineering smoke |
| Pilot10 | 10 | 0 | 10 | NO-GO: 9 source thiếu, 1 legacy snapshot cần xác minh |
| Full120 | 120 | 0 | 113 | NO-GO: 116 source thiếu, 4 snapshot cũ chưa đạt manifest mới; thiếu truth 7 case |

Hai input smoke mới ở view riêng không tự thay đường dẫn của canonical manifest.
Không chuyển legacy snapshot thành verified chỉ bằng cách tính lại hash của
chính nó: phải có pinned source hoặc independently verified audit inventory.

## Lệnh đã xác minh và trình tự gate

```bash
.venv/bin/python -m pytest -q
.venv/bin/ruff check .
.venv/bin/mypy src

MAXVERA_RUN_CODEQL_FIXTURE=1 .venv/bin/python -m pytest -q -s \
  tests/integration/test_identity_verification_codeql.py
MAXVERA_RUN_CODEQL_FIXTURE=1 .venv/bin/python -m pytest -q -s \
  tests/integration/test_varargs_codeql.py

.venv/bin/python -m maxvera preflight \
  --config configs/pipelines/research_smoke_ready.yaml \
  --variant graph_llm_verify --mode smoke --limit 2

MAXVERA_OPENROUTER_PROVIDER=groq .venv/bin/python -m maxvera pipeline research \
  --config configs/pipelines/research_smoke_ready.yaml \
  --variant graph_llm_verify --mode smoke --limit 2 \
  --run-id research_readiness_20261024_smoke01 --execute

.venv/bin/python -m maxvera status --run-id research_readiness_20261024_smoke01
.venv/bin/python -m maxvera evaluate \
  --run-id research_readiness_20261024_smoke01 --protocol zero_hint

.venv/bin/python -m maxvera preflight \
  --config configs/pipelines/research_pilot10.yaml --variant graph_only --mode full
.venv/bin/python -m maxvera pipeline research \
  --config configs/pipelines/research_pilot10.yaml --variant graph_only --mode full \
  --run-id research_readiness_pilot10_v1 --dry-run

.venv/bin/python -m maxvera preflight \
  --config configs/pipelines/research_full120.yaml --variant graph_only --mode full
.venv/bin/python -m maxvera pipeline research \
  --config configs/pipelines/research_full120.yaml --variant graph_only --mode full \
  --run-id research_readiness_full120_v1 --dry-run
```

`--mode full` có nghĩa không truncate profile cohort: profile pilot10 vẫn chỉ
có mười case. CLI không có `--mode pilot`. Chỉ đổi `--dry-run` thành `--execute`
khi preflight và các gate trước đạt. Full LLM còn yêu cầu reviewed frozen
development signal; không tự đặt approval để chạy. Mọi execution mới phải có run
ID mới. Resume dùng nguyên code/config/input và thêm `--resume`, không sửa
checkpoint/journal để lách identity hoặc tính phí lại request chưa rõ kết quả.

Truth chưa đủ vẫn có thể xuất báo cáo coverage minh bạch sau một run đầy đủ bằng:

```bash
.venv/bin/python -m maxvera evaluate \
  --run-id research_readiness_full120_v1 --protocol zero_hint --missing-truth report
```

Đó không phải quyền tuyên bố full120 recall: full-cohort metrics phải null nếu
truth chưa đủ; chỉ evaluable subset có metric với mẫu số công khai.

Resolved config và preflight JSON được lưu trong
`logs/research_readiness_20261024/{smoke,pilot10,full120}_dry_run.json` và
`preflight_{smoke,pilot10,full120}.json`; execution còn lưu
`config.resolved.yaml` trong run để kiểm tra các runtime parameters thực sự.

## Kết quả smoke và quyết định cuối

Run `research_readiness_20261024_smoke01` hoàn tất `COMPLETED`, exit 0, lúc
11:58:35 ngày 24/10/2026 (giờ Việt Nam), sau **1.398,244 giây**
(23 phút 18 giây). Không sửa implementation/config/input trong lúc thực thi;
implementation hash khớp manifest trước và sau run.

| Kết quả | RocketMQ | Spring Security |
|---|---:|---:|
| Stage SUCCESS | 9/9 | 9/9 |
| Giây/case | 1.005,193 | 386,451 |
| Raw → retained → final | 396 → 5 → 5 | 408 → 5 → 5 |
| Assessment schema/citation hợp lệ | 5/5 | 5/5 |
| Evidence complete | 5/5 | 5/5 |
| Traversal bị cắt | 0 | 0 |
| Verifier | 4 NO_FLOW_FOUND, 1 UNSUPPORTED_SPEC | 5 UNSUPPORTED_SPEC |
| Discovery / ranked Recall@5 | 0/1 / 0/1 | 0/1 / 0/1 |

Tổng 10 API attempts qua đúng GPT-OSS-20B/Groq, 18.236 input + 2.605 output
tokens, reported cost **$0,0021492**, không có unknown-cost attempt. Schema/citation
valid không chứng minh rationale hoặc phán quyết bảo mật đúng. Hai bundle có
interior context truncation nhưng đủ endpoint evidence; không có missing evidence.

Static source boundary Spring giữ 133/148 alerts, loại rõ 15 alert không có
repository location và downgrade hai mixed-endpoint path thành partial evidence;
tổng 208 external locations được ghi trong scope artifact. Không lọc theo nhãn
hoặc phán quyết model. Raw SARIF/signals vẫn giữ nguyên trong extraction.

Verification thực sự chạy tám query cho bốn candidate có exact endpoint; cả bốn
không tìm thấy modeled flow. Sáu `UNSUPPORTED_SPEC` không có frozen explicit graph
source/sink endpoints; verifier không đoán endpoint để làm query chạy. Không có
query timeout/integrity failure. Vì coverage verification chỉ **4/10**, quality
report trả `engineering_pass=false`, blocker `VERIFICATION_INCOMPLETE`, dù execution
đã hoàn thành.

Evaluator riêng sau freeze: discovery Recall@5 **0/2**, ranked Recall@5 **0/2**,
`ranking_complete_cases=2`, verified detection **0/2**. Điểm mới là cả hai rerank
đều đầy đủ để chấm; đó không phải cải thiện chất lượng phát hiện. Không so trực
tiếp r3 với run mới để tuyên bố lợi ích causal của một bản sửa: ranking policy
và source boundary đã thay đổi, và hai case này đã được xem trước.

Checksum toàn run/evaluation pass; 174/170 critical database files được kiểm
độc lập. Run checksum index SHA256:
`a37203cb571c0ef56d61e299137e138ed38b2c78e84f5db3c3bf9628ec65709f`.
Resume cùng config/code/input pass trong 12,748 giây, giữ nguyên **15.328 file**,
checksum index, quality report và request journal; vẫn 10 attempts, **0 paid call
thêm**. Split gốc, source gốc và checksum index run/evaluation r3 không đổi.
Scan 15.381 file thuộc run mới, evaluation và log bàn giao không phát hiện giá
trị API key; giá trị credential không được in ra trong báo cáo scan.

**Pilot không được thực thi:** smoke chưa qua quality acceptance; ngoài ra
preflight pilot10 xác nhận chín source chưa có và một legacy snapshot cần xác
minh. **Full120 không được thực thi:** 116 source thiếu, bốn đường dẫn canonical
chưa có manifest đạt chính sách mới, bảy case thiếu truth và graph signal chưa
được duyệt. Preflight full LLM báo `GRAPH_SIGNAL_NOT_APPROVED`; mọi cấu hình vẫn
giữ approval false.

Công việc tiếp theo cần có quyết định cụ thể về coverage của static-only
candidate trong verification, cải thiện graph/discovery signal trên development,
chuẩn bị/xác minh đủ pilot inputs rồi mới mở rộng. Không đoán endpoint hoặc bỏ
candidate để vượt quality gate. Bảy case thiếu truth tiếp tục là unknown cho đến
khi có annotation có provenance; report-mode đã hỗ trợ giữ đủ cohort minh bạch.

Artifacts bàn giao:

- Source diff gồm cả file mới: `logs/research_readiness_20261024/research_readiness.patch`.
- Frozen run: `results/_smoke/research/research_readiness_20261024_smoke01/`.
- Evaluation: `results/evaluations/research_readiness_20261024_smoke01/zero_hint/`.
- Kết quả kiểm tra: `verification_final.json`, `smoke_inspection.json`,
  `resume_verification.json`, `independent_review.json` và `integrity_secret_scan.json`
  trong `logs/research_readiness_20261024/`.
- Resolved runtime thật: `logs/research_readiness_20261024/smoke_config.resolved.yaml`.

Diff đang ở working tree trên branch yêu cầu để review; chưa commit/push thay đổi
của tác vụ này. Bản sửa shared SARIF URI thuộc `src/reproduction/common.py` chỉ
nhằm giữ hidden paths và traversal cho research source-boundary validation; không
chạy lại reproduction để tạo kết quả mới.

## Bổ sung khi xác định các bước để GO

Read-only diagnostic tiếp theo cho thấy cả raw pool RocketMQ (396 candidate) và
Spring (408 candidate) không có strong truth match, kể cả khi bỏ cutoff Top-5.
Tuy nhiên, không được quy ngay kết quả đó thành lỗi discovery:

- RocketMQ: truth span `DefaultRequestProcessor.java:603–641`, nhưng source freeze
  chỉ có 618 dòng; truth file `RequestProcessorTest.java` không tồn tại.
- Spring: cả ba đường dẫn truth đều không tồn tại trong analyzed workspace.
  `DefaultHttpFirewall.java` có ở package/path khác; hai basename còn lại không có.

Coverage được báo trước đó là coverage của **record có file/span**, chưa phải
alignment đúng với vulnerable source. `preflight` và evaluator hiện chưa xác minh
đầy đủ điều kiện thứ hai. Do đó, 0/2 ở trên là kết quả tính toán theo annotation
hiện có, chưa là phép đo recall đủ tin cậy. Cần provenance/mapping truth về đúng
vulnerable commit trong evaluator-only view và regression cho rename, line shift,
file chỉ xuất hiện sau fix, hoặc mapping mơ hồ. Không sửa analyzer theo test_locked
labels, không tự map theo basename và không biến annotation không resolve thành
negative. Các frozen run/evaluation đã công bố không bị sửa.

Sáu candidate `UNSUPPORTED_SPEC` đều là `STATIC_CONFIRMED` với graph endpoint IDs
rỗng. Mỗi candidate khớp duy nhất một raw SARIF threadflow; đủ 12 endpoint spans
có file/start/end line/column. Không endpoint nào khớp exact node của graph freeze;
line-only matching có 2–10 khả năng. Hướng sửa là adapter giữ structured SARIF
endpoint provenance và kiểm chứng binding duy nhất trong CodeQL, kèm test cho
0/1/nhiều binding; không đoán node theo dòng.

Ưu tiên để GO: xác minh truth alignment → hoàn thiện exact endpoint verification
→ chuẩn bị pilot10 → chạy static_only/graph_only trên development và review signal
→ pilot LLM có kiểm soát → hoàn thiện toàn bộ 120 inputs/truth và freeze cấu hình.
Hiện chưa có ngưỡng recall khoa học được chốt trong repository; phải xác lập trước
khi dùng pilot để duyệt full, không chọn ngưỡng sau khi xem kết quả.
