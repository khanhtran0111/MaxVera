# Experimental Protocol 1.1.1

**Mục đích:** định nghĩa dataset view, baseline, evaluation unit, metric, budget,
failure policy và kiểm định thống kê áp dụng cho mọi kết quả chính. Protocol này
được cập nhật và frozen ngày 01/09/2026; `configs/experiments/main.yaml` còn `draft` chỉ vì
checksum split và threshold calibration chưa tồn tại ở Phase 0.

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

## Baseline matrix 1.1.1

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

Các baseline LLM dùng cùng `openai/gpt-oss-20b` và provider route đã pin, báo hai
bảng: `budget_matched` và `best_effort`. Budget-matched
khóa 8,192 input context tokens/call, 2,048 output tokens/call, 30 calls/project,
160,000 total input tokens/project, temperature `0`, top-p `1`, seed `1234`.
Best-effort vẫn phải công bố chi phí thực tế.

Chạy tuần tự một project, một graph build và một LLM request. Không chạy CodeQL
và LLM đồng thời. CodeQL mặc định 4 threads/16 GB RAM. Hosted inference phải pin
model/provider route, tắt fallback, yêu cầu parameter support, ZDR và
`data_collection=deny`; mọi request ghi token usage, cost, latency và request ID.

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
