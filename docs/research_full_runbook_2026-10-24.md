# Vận hành full research pipeline — 24/10/2026

Tiếp tục trên branch `refactor/pipeline-first-v2`, giữ working tree hiện tại. Không
reset, ghi đè snapshot/frozen output, đổi checkout `third_party` hoặc chạy lại IRIS
reproduction. Trạng thái đầu đợt enablement được lưu ở
`logs/research_full_enablement_20261024/initial_state.json` cùng bản sao tar/patch.

View mới đã được chuẩn bị và audit đủ 120/120 source/recipe; chưa chạy benchmark
full120 hoặc xác nhận build thành công cho mọi project. Chọn run ID, protocol và
comparison output chưa tồn tại. Chạy từ repository root bằng `.venv` hiện có.

## 1. Chuẩn bị source view mới, giữ đủ 120 case

```bash
.venv/bin/python -m maxvera dataset prepare \
  --config configs/datasets/cwe_bench_extended.yaml \
  --sources --view full_20261024_v2 \
  --fetch-timeout 900 --min-free-gib 20
```

Preparation xác minh frozen release/checksums, lấy exact pinned commit, áp dụng
pinned build patch và chỉ reuse snapshot đã qua kiểm provenance/inventory/recipe.
Manifest mới là
`data/processed/analysis_input/full_20261024_v2/D_extended_projects.csv`; luôn giữ đủ
120 canonical rows, kể cả case fetch/recipe thất bại. Không sửa release metadata
để chữa một upstream inconsistency.

Đọc `logs/source_preparation/full_20261024_v2/status.json`: `manifest_cases`,
`requested`, `prepared`, `reused`, `failed`, `ready` và lỗi từng case. `ready=true`
chỉ nói source/recipe đã chuẩn bị cho toàn bộ selection. `build_executed=false`
vẫn có nghĩa chưa build. Toolchain hiện diện và recipe hợp lệ không chứng minh
dependency resolve, compilation hay CodeQL extraction thành công.

Không có flag `prepare --resume`: chạy lại **nguyên lệnh trên** để reuse snapshot
hợp lệ và retry case thất bại. Để chỉ dùng verified snapshots/object cache đã có:

```bash
.venv/bin/python -m maxvera dataset prepare \
  --config configs/datasets/cwe_bench_extended.yaml \
  --sources --view full_20261024_v2 \
  --fetch-timeout 900 --min-free-gib 20 --offline
```

View v2 giữ tracked inputs theo archive policy mới. Không dùng `--reuse-manifest`
từ các view cũ đã bị audit thiếu tracked inputs để tạo view này; retry cùng view
sẽ reuse chính snapshot v2 đã xác minh. Offline thiếu pinned object sẽ báo
failure; không thay bằng commit gần nhất.
Giữ cùng view identity khi retry. Nếu cần đổi manifest identity, tạo view mới;
không sửa manifest cũ hoặc hạ disk guard để che thiếu dung lượng.

## 2. Kiểm tra điều kiện thực thi và điều kiện chấm điểm riêng

Hai profile dùng `runtime_fast.yaml`, GPT-OSS-20B qua Groq, manifest
`full_20261024_v2` ở trên và giữ `graph_signal_approved: false`:

| Profile | Selection ở `--mode full` |
|---|---|
| `configs/pipelines/research_full120_execution.yaml` | Đủ 120 case |
| `configs/pipelines/research_pilot10_execution.yaml` | Đúng 10 development case cố định trong `configs/pipelines/research_pilot10.csv` |

```bash
.venv/bin/python -m maxvera doctor --config configs/runtime_fast.yaml

.venv/bin/python -m maxvera pipeline research \
  --config configs/pipelines/research_full120_execution.yaml \
  --variant graph_only --mode full \
  --run-id research_full_20261024_plan01 --dry-run

.venv/bin/python -m maxvera preflight \
  --config configs/pipelines/research_full120_execution.yaml \
  --variant graph_only --mode full --require execution \
  --truth-alignment data/processed/evaluator_only/full_20261024_v2/reviewed_pilot_alignment_v3.json
```

`doctor` không gọi model để xác minh route trực tiếp. Dry-run không chạy stage và
không bảo đảm input hợp lệ chỉ vì exit 0; đọc `input_preflight.ready` và từng issue.
Standalone preflight giữ nguyên mọi gate. `--require execution` chọn điều kiện
thực thi cho exit code; mặc định `--require all` vẫn exit 1 khi truth chưa đủ.
Flag này không thay đổi guard của lệnh pipeline:

| Trường | Ý nghĩa |
|---|---|
| `input_preflight.ready` | Mọi selected source, snapshot provenance và recipe qua kiểm tra; chưa build |
| `execution_ready` | Input/tool/policy cho phép chạy; truth có thể vẫn unknown |
| `evaluation_ready` | Truth của toàn selection có coverage/alignment được xác minh |
| `ready` | Tổng hợp các gate, gồm cả truth; không dùng thay cho `execution_ready` |
| `scientific_approved` | Vẫn false; preflight/protocol không cấp scientific acceptance |

Mapping v3 chỉ rebind inventory cho view mới: giữ nguyên 10 case, 67 truth rows,
55 `MAPPED`, 12 `UNRESOLVED`, targets và nội dung review cũ. Cả 55 mapped
file/range đã được kiểm byte-identical cùng source commit; trusted alignment vẫn
6/10, bốn case unknown. Mapping và evidence được seal, chờ root/reviewer review
độc lập trước khi dùng. Script, full proof và receipts ở
`logs/research_full_enablement_20261024/truth_rebinding/`; không có adjudication
hoặc scientific approval mới.

Pipeline thực thi kiểm analyzer inputs mà không đọc ground truth. `static_only`
và `graph_only` có thể chạy full để đo engineering/development khi truth chưa đủ.
Full variant có LLM giữ guard reviewed signal mặc định; nhánh exploratory bên
dưới cần protocol đã đăng ký **trước** run. Không bật approval để vượt guard.

## 3. Đo development thật trên fixed pilot10

Hoàn tất code/config/source trước hai lượt này. Không thay code, config, input,
tool hoặc truth revision giữa hai điều kiện paired. Đây là full-mode development
measurement, không dùng smoke output làm bằng chứng thay thế.

```bash
STATIC_RUN=research_full_20261024_dev_static01
GRAPH_RUN=research_full_20261024_dev_graph01
FULL_RUN=research_full_20261024_exploratory01
LOG_ROOT=logs/research_full_enablement_20261024/operator01
mkdir -p "$LOG_ROOT"

.venv/bin/python -m maxvera pipeline research \
  --config configs/pipelines/research_pilot10_execution.yaml \
  --variant static_only --mode full --run-id "$STATIC_RUN" --execute

.venv/bin/python -m maxvera pipeline research \
  --config configs/pipelines/research_pilot10_execution.yaml \
  --variant graph_only --mode full --run-id "$GRAPH_RUN" --execute

.venv/bin/python -m maxvera status --run-id "$STATIC_RUN"
.venv/bin/python -m maxvera status --run-id "$GRAPH_RUN"
```

Chỉ evaluate frozen terminal run (`COMPLETED` hoặc
`COMPLETED_WITH_CASE_FAILURES`). Nếu pipeline exit khác 0, đọc status và failed
stage; terminal case failures vẫn phải được giữ đủ trong mười case. Lượt bị ngắt
chạy lại cùng lệnh, thêm `--resume`, giữ nguyên identity. Không bỏ case khó build.

Evaluator in exact immutable output path; lưu hai path này để chọn đúng revision:

```bash
STATIC_EVAL="$(.venv/bin/python -m maxvera evaluate \
  --run-id "$STATIC_RUN" --protocol zero_hint --missing-truth report \
  --truth-alignment data/processed/evaluator_only/full_20261024_v2/reviewed_pilot_alignment_v3.json)"

GRAPH_EVAL="$(.venv/bin/python -m maxvera evaluate \
  --run-id "$GRAPH_RUN" --protocol zero_hint --missing-truth report \
  --truth-alignment data/processed/evaluator_only/full_20261024_v2/reviewed_pilot_alignment_v3.json)"

printf '%s\n' "$STATIC_EVAL" "$GRAPH_EVAL" > "$LOG_ROOT/development_evaluation_paths.txt"

.venv/bin/python -m maxvera compare \
  --evaluations "$STATIC_EVAL" "$GRAPH_EVAL" \
  --output "results/comparisons/${GRAPH_RUN}_vs_static"
```

Kiểm tra từng lệnh evaluate exit 0 trước khi dùng biến path. Output có dạng
`results/evaluations/<run_id>/zero_hint_aligned_v1/<condition_hash>/`.
`--evaluations` chọn exact path, không chọn ngầm một revision qua run ID.
Comparator yêu cầu cùng case IDs và condition hash; không dùng `--paired-llm`
cho static-versus-graph vì candidate pools có thể khác.

Review `metrics_aggregate.json`, case failures, candidate provenance/coverage,
ranking và quality reports của cả hai lượt. Registration yêu cầu **đúng hai**
immutable full development evaluations, một `static_only` và một `graph_only`,
đủ fixed pilot10 thuộc development split, LLM tắt, cùng condition hash và ít nhất
một case evaluable ở mỗi lượt. Checksums/run hashes phải khớp. Mười case được
account đầy đủ không có nghĩa cả mười evaluable.

Thiếu paired evidence hoặc denominator evaluable bằng 0 thì dừng ở blocker cụ
thể; không tạo metrics giả hoặc thay cohort. Ghi kết quả âm/inconclusive nếu có.
Tiêu chí mở rộng xác nhận trong
[pilot acceptance](research_pilot_acceptance_2026-10-24.md) vẫn là policy khoa học
riêng; protocol exploratory không xác nhận đã đạt positive graph signal.

## 4. Đăng ký prospective exploratory full run

Chỉ đăng ký sau khi review measurement thật và toàn bộ full120 input qua
preflight. Chọn `FULL_RUN` chưa có ở bất kỳ result namespace nào, protocol path
chưa tồn tại, và ghi rationale phản ánh kết quả đã review. Ví dụ dưới đây không
khẳng định positive signal:

```bash
.venv/bin/python -m maxvera experiment register \
  --config configs/pipelines/research_full120_execution.yaml \
  --variant graph_llm_verify --run-id "$FULL_RUN" \
  --output "$LOG_ROOT/protocol.json" \
  --development-evaluations "$STATIC_EVAL" "$GRAPH_EVAL" \
  --rationale 'Reviewed paired fixed pilot10 measurements; retain negative or inconclusive findings and unknown truth; execute frozen full120 prospectively without claiming approved graph signal.'
```

Protocol là amendment vận hành `exploratory_full_execution`, đóng băng run ID,
resolved config, variant, toàn bộ case/source fingerprints, implementation hash
và development receipts. `scientific_approved=false`, approval trong profile vẫn
false. Protocol không sửa missing truth hoặc nới firewall. Không được đăng ký
hồi tố sau khi run đã tồn tại.

## 5. Chạy full và resume cùng identity

```bash
.venv/bin/python -m maxvera preflight \
  --config configs/pipelines/research_full120_execution.yaml \
  --variant graph_llm_verify --mode full --run-id "$FULL_RUN" --require execution \
  --experiment-protocol "$LOG_ROOT/protocol.json" \
  --truth-alignment data/processed/evaluator_only/full_20261024_v2/reviewed_pilot_alignment_v3.json

MAXVERA_OPENROUTER_PROVIDER=groq .venv/bin/python -m maxvera pipeline research \
  --config configs/pipelines/research_full120_execution.yaml \
  --variant graph_llm_verify --mode full --run-id "$FULL_RUN" \
  --experiment-protocol "$LOG_ROOT/protocol.json" --execute
```

Ở preflight này, kiểm `execution_ready` và `execution_policy`; `--require execution`
trả exit 0 khi điều kiện chạy đạt, trong khi truth issue vẫn làm `ready=false`.
Không gọi trạng thái này là scientific GO.
Resolved budgets là ngưỡng dừng của pipeline, không phải provider prepaid cap.
Theo dõi stage errors, disk, token/cost ledger và request `PENDING/UNCERTAIN`.

```bash
.venv/bin/python -m maxvera status --run-id "$FULL_RUN"

MAXVERA_OPENROUTER_PROVIDER=groq .venv/bin/python -m maxvera pipeline research \
  --config configs/pipelines/research_full120_execution.yaml \
  --variant graph_llm_verify --mode full --run-id "$FULL_RUN" \
  --experiment-protocol "$LOG_ROOT/protocol.json" --execute --resume
```

Resume dùng cùng code/config/input/run ID/protocol. Implementation hash bao gồm
cả source và configs; đổi một file liên quan có thể làm guard từ chối. Không sửa
checksum, manifest hoặc protocol để ép reuse checkpoint. Nếu identity thay đổi,
chọn run ID/protocol mới và review lại bằng chứng development phù hợp.

## 6. Đóng băng, evaluate và báo cáo đúng phạm vi

Sau terminal status và đủ 120 final case records:

```bash
FULL_EVAL="$(.venv/bin/python -m maxvera evaluate \
  --run-id "$FULL_RUN" --protocol zero_hint --missing-truth report \
  --truth-alignment data/processed/evaluator_only/full_20261024_v2/reviewed_pilot_alignment_v3.json)"
printf '%s\n' "$FULL_EVAL" > "$LOG_ROOT/full_evaluation_path.txt"
```

`--missing-truth report` giữ nguyên cohort, liệt kê missing/unaligned cases và
báo evaluable subset riêng. Khi truth chưa đầy đủ, whole-cohort Recall@K là
`null`; không suy recall của 120 case từ subset, không xem unknown là negative
hoặc thêm annotation đoán. Mapping location hợp lệ chưa chứng minh security
adjudication của annotation.

Báo cáo immutable run/evaluation paths, checksums, final statuses của **mọi**
case, quality/truncation/failure diagnostics, pre-LLM/post-LLM/verification metrics
đúng denominator, chi phí và hạn chế. `FLOW_FOUND` chỉ là modeled reachability;
`NO_FLOW_FOUND` không chứng minh safety. Không so paired full120 với pilot10 có
cohort khác. Không tune từ locked cases hoặc đổi metric/config theo locked
results đã xem.

Theo mục 10–11 của [kế hoạch v2](../ke_hoach_trien_khai_zero_hint_repository_vulnerability_research.md),
kết quả âm vẫn có giá trị khi protocol đúng, firewall đạt, case accounting đầy
đủ và kết quả tái tính được. Engineering completion, truth evaluability và
scientific acceptance cần bằng chứng riêng. Lưu bằng chứng thực tế trước khi
khẳng định bất kỳ gate nào đã đạt; runbook này không thay thế báo cáo thực thi.
