# Experimental Protocol 1.7.0

**Mục đích:** định nghĩa dataset view, baseline, evaluation unit, metric, budget,
failure policy và kiểm định thống kê áp dụng cho mọi kết quả chính. Protocol này
được cập nhật và frozen ngày 17/09/2026; `configs/experiments/main.yaml` còn
`draft` vì threshold calibration Phase 12 chưa tồn tại.

## Dataset và label firewall

| Track | Vai trò | Label access |
|---|---|---|
| `D_repro_v1` | 120 CVE/4 CWE, reproduction | evaluator only; không tuning |
| `D_extended` | nguồn cho main study | group split theo owner/repository |
| `D_dev` | prompt/schema/threshold | labels được phép trong development |
| `D_test_locked` | kết quả paper chính | analyzer không có label access |
| `D_generalization_repo/cwe` | RQ6 | family chưa thấy khi tune |
| `D_smoke` | kiểm tra kỹ thuật | không phải scientific result |

`analysis_input/` chỉ có source, build metadata tối thiểu và opaque project
slug. `evaluator_only/` giữ CVE, CWE ground truth, advisory, patch/fix commit,
fixed method/line, vulnerable description và published result của đúng project.
Analyzer chỉ được mount analysis view; evaluator chạy ở process/job riêng mới
được mount cả hai. Không log, cache, prompt hay filename nào được chuyển field
cấm sang analysis view.

Split `D_extended` theo `github_username/github_repository_name`; mọi CVE/version
cùng repository nằm cùng split. Cấm random row split. Seed là `1234`; Phase 2
phải lưu manifest, split CSV và checksum, sau đó chuyển main config từ `draft`
sang `frozen` bằng decision record.

## Baseline matrix 1.2.3

| ID | Điều kiện | Phân loại | Vai trò paper |
|---|---|---|---|
| B0 CodeQL Security Suite | zero-hint, no LLM | fair | baseline |
| B1 CodeQL per-CWE | oracle CWE, no LLM | oracle | reference |
| B2 IRIS + GPT-OSS 20B/OpenRouter | oracle CWE | oracle | model-substitution reproduction |
| B3 raw/chunked GPT-OSS 20B | zero-hint | fair | baseline |
| B4 text-RAG | zero-hint | fair | baseline |
| B5 static hypothesis | zero-hint | fair | baseline |
| B6 Program Graph only | zero-hint | fair | baseline |
| B7 Security KG only | zero-hint | fair | baseline |
| B8 USEG unpruned | zero-hint | fair | nearest ablation |
| B9 Full USEG | zero-hint | fair | proposed method |

Machine-readable matrix: [`configs/baselines/matrix.yaml`](../configs/baselines/matrix.yaml).
B1/B2 không được dùng làm fair zero-hint comparator. Native-setting references
không vào main table nếu chưa có adapter công bằng.

## Budget và execution

Các baseline LLM từ Phase 5 dùng cùng `openai/gpt-oss-20b` và provider route
`akashml` đã pin, báo hai bảng: `budget_matched` và `best_effort`. Budget-matched
khóa 8,192 input context tokens/call, 2,048 output tokens/call, 30 calls/project,
160,000 total input tokens/project, temperature `0`, top-p `1`, seed `1234`.
Best-effort vẫn phải công bố chi phí thực tế.

Chạy tuần tự một project, một graph build và một LLM request. Không chạy CodeQL
và LLM đồng thời. CodeQL mặc định 4 threads/16 GB RAM. Hosted inference phải pin
model/provider route, tắt fallback, yêu cầu parameter support, ZDR và
`data_collection=deny`; mọi request ghi token usage, cost, latency và request ID.
Kết quả Phase 4 protocol 1.1.1 đã hoàn tất bằng route `groq` là snapshot lịch sử,
không được trộn vào so sánh model/provider-controlled với run Phase 5.

## Evaluation unit và ground truth

- Primary detection unit: một vulnerability/project row trong canonical manifest.
- Alert unit: unique normalized taint/evidence path; duplicate path bị collapse.
- Localization unit: ranked source location, báo Top-k khi có ranking.
- Bootstrap unit: repository/project, không bootstrap path.
- Mọi project phải có `SUCCESS`, `BUILD_FAILED`, `CODEQL_DB_FAILED`,
  `ANALYSIS_FAILED` hoặc `EXCLUDED_WITH_REASON`.

Primary intention-to-analyze tính build/analysis failure là miss. Báo thêm
sensitivity analysis chỉ trên tập build thành công. Không drop project im lặng.

Ground truth có ba lớp: (1) paper-compatible patch/fixed-point intersection;
(2) canonical một row ground truth/CVE-project; (3) stricter finding có ở
vulnerable version và biến mất/không còn đường tương ứng ở fixed version. Finding
không giao patch là `UNKNOWN_UNREVIEWED`, không tự động là false positive; manual
review phải mù với cấu hình phương pháp.

## Metrics đã khóa

- Effectiveness: project/vulnerability Recall, path Precision, F1, FDR, macro
  per-CWE, micro overall, vulnerable-fixed differential, localization Top-k.
- Zero-hint: CWE/Hypothesis Recall@1/3/5/10, MRR, candidate-set recall trước
  CodeQL, hypothesis-to-verified-path conversion.
- Calibration: ECE equal-width (10 bins canonical; equal-mass sensitivity),
  Brier Score, AURC/selective risk, coverage ở risk targets, post-abstention
  precision/recall và routing cost. `ABSTAIN` không phải negative.
- Efficiency: input/output/reasoning tokens, calls, retries/schema failures,
  wall/API latency, CPU time và peak RSS phía client, DB/query/indexing time,
  disk, API cost/project và cost/verified finding.

Metric aggregate luôn sinh từ immutable project outputs. Cấm copy số bằng tay.

## Statistical protocol

Chạy 10,000 paired bootstrap samples theo repository/project và báo effect size
cùng 95% CI. Dùng McNemar cho detected/not-detected paired outcomes. Dùng
Wilcoxon signed-rank khi assumptions phù hợp, nếu không dùng paired permutation
cho token/latency. Áp dụng Holm correction cho family multiple comparisons.
Sensitivity analyses gồm loại build failures và tính failures là miss.

Canonical run dùng temperature 0/seed 1234. Robustness dùng 5 seeds cho full
method và baseline mạnh nhất; nếu backend vẫn nondeterministic phải báo exact-
match rate và phân phối metric.

## Run integrity

Mỗi full result có immutable run ID, resolved config, command, logs, environment,
manifest, per-project status, raw findings, metrics và `checksums.sha256`. Không
có `--overwrite`; resume phải có parent run. Smoke output/cache bị cô lập, luôn
cleanup bằng trap và không được promote. Validator, không phải exit code đơn lẻ,
quyết định run hợp lệ.

## Security Knowledge Graph contract

Phase 8 tạo một KG toàn cục, không phải graph theo project. Scope gồm bốn CWE gốc
`22/78/79/94` và closure một hop của quan hệ MITRE CWE Research Concepts; project
view chỉ được tạo từ Phase 9. MITRE CWE, OWASP và CodeQL Java API models phải được
materialize ở preparation boundary với version/hash/license đã khóa; build KG sau
đó chạy offline và không đọc advisory, evaluator-only hay `test_locked`.

Fact deterministic và fact LLM-inferred dùng hai serialization riêng. Mọi node và
edge đều có URL, version, license, artifact checksum, locator, extraction rule và
confidence. Canonical Phase 8 không gọi LLM và lớp inferred phải rỗng. CodeQL model
experimental hoặc provenance chưa được manual review bị loại; `manual`,
`df-manual`, `ai-manual` và `hq-manual` được giữ với confidence policy versioned.

## Evidence Graph và USEG contract

Phase 9 iteration 0 chỉ dùng ba canonical development artifacts của Phase 6/7/8;
không đọc evaluator-only, advisory, patch hoặc `test_locked`, và không gọi mạng/
LLM. Evidence schema khai báo `HYPOTHESIS`, `ASSERTION`, `CODEQL_FINDING`,
`TAINT_PATH`, `SANITIZER_EVIDENCE`, `CONTRADICTION`, `VERIFICATION_RESULT`; edge
chỉ gồm `SUPPORTS`, `CONTRADICTS`, `VERIFIED_BY`, `DERIVED_FROM`, `MATCHES`.

`TAINT_CANDIDATE` từ Phase 7 chỉ được materialize thành finding/path với trạng thái
`unverified_candidate`, không được gọi là verified vulnerability. Node loại
verification/contradiction/sanitizer chỉ xuất hiện khi có upstream evidence thật;
không tạo placeholder. Confidence được giữ thành các component độc lập có basis,
không gộp thành scalar. Mọi record mang analysis iteration và provenance artifact.
Đồ thị dependency phải acyclic, JSONL round-trip lossless, và mọi candidate path
phải truy được tới Program location lẫn Security fact. 15 Phase 7 failures tiếp
tục là intention-to-analyze miss.

## Graph retrieval và specification synthesis contract

Phase 10 chỉ dùng canonical development USEG `p9_useg_dev_full_003`. B6 giữ
Evidence anchors và Program layer; B7 giữ Evidence anchors và Security layer;
B8 lấy connected component USEG không giới hạn hop/node; B9 lấy subgraph bốn hop
tối đa 80 nodes. Mọi strategy dùng cùng compact JSONL serializer, prompt, strict
JSON Schema, model/provider và budget. Structural pruning và truncation do token
cap phải được ghi riêng, không được gọi lẫn là cùng một thao tác.

Mỗi specification phải tham chiếu source/sink/sanitizer/propagator bằng node ID
có trong serialized context. Location assertion từ Phase 6/9 được phép làm
endpoint evidence; Security node chỉ được dùng đúng semantic role. Source và sink
bắt buộc có grounded candidate trước khi gọi LLM; context thiếu một role phải
fail-closed mà không tốn API. Một hypothesis có tối đa một initial call và hai
schema/semantic/compile repairs; tổng vẫn không vượt 30 calls và 160.000 input
tokens/project.

Input-token gate áp dụng cho toàn request gồm compact context, prompt và strict
schema, không chỉ riêng graph serialization. Nếu conservative preflight vượt
cap, serializer phải giảm context budget deterministic, dựng lại candidate enum
và kiểm tra lại; nếu không còn grounded source/sink hoặc vẫn vượt cap thì fail
trước API. Artifact phải ghi initial/final context budget và adaptation flag.

Phase 10 sinh strict JSON và deterministic CodeQL query template, sau đó chạy
`codeql query compile --check-only`. Compile success chỉ xác nhận cú pháp/type
QLL, không phải static verification. Mọi spec giữ trạng thái
`SYNTHESIZED_UNVERIFIED`; final finding, verified path và vulnerable/fixed verdict
chỉ được materialize từ Phase 11. Analyzer tiếp tục cấm evaluator-only, advisory,
patch và `test_locked`.
