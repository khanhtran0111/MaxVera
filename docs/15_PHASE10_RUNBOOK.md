# Phase 10 Runbook

**Mục đích:** truy xuất graph context cho B6–B9 và sinh specification
`SYNTHESIZED_UNVERIFIED` có CodeQL template compile được. Phase này không chạy
query trên database và không tạo verified/final finding.

## Contract

- Input duy nhất: canonical development USEG `p9_useg_dev_full_003`; runner kiểm
  exact checksum trước mọi dry-run/API call.
- B6 = Evidence anchors + Program; B7 = Evidence anchors + Security; B8 = USEG
  connected component không structural pruning; B9 = USEG tối đa 4 hop/80 node.
- Context compact cùng strict schema phải nằm trong 8.192 input tokens/call;
  serializer chừa 3.072-token prompt/schema reserve và preflight lại request.
  Context overflow được giảm budget deterministic với margin, serialize và dựng
  schema lại; metadata phân biệt initial/final budget và adaptation.
- Mỗi hypothesis tối đa 3 calls (initial + 2 repair), mỗi project tối đa 30 calls
  và 160.000 input tokens.
- Source/sink phải có grounded node trước khi gọi model. Context thiếu role
  fail-closed với zero API call cho hypothesis đó.
- CodeQL `--check-only` chỉ là compile gate. Static verification thuộc Phase 11.
- Development-only; không mở evaluator-only hoặc `test_locked`.

## 1. Quality gate và budget offline

```bash
cd ~/Documents/MaxVera
uv run --frozen ruff check .
uv run --frozen mypy src
uv run --frozen pytest -q
bash scripts/tools/estimate_phase10_budget.sh --baselines 4
```

Estimator không gọi mạng. Con số nominal giả định một successful call cho mỗi
hypothesis; hard ceiling gồm toàn bộ repair allowance và không phải dự báo chi
phí thực tế.

## 2. Dry-run bốn strategy

Dry-run dựng context, kiểm Phase 9 lock và token cap nhưng không đọc API key,
không gọi OpenRouter và không compile model-generated query:

```bash
bash scripts/tools/run_phase10_suite.sh \
  --mode pilot --limit 1 --dry-run --run-id p10_dev_dry_001

for baseline in program_graph_only security_kg_only useg_no_pruning full_useg; do
  bash scripts/tools/validate_phase10.sh \
    --run-root "results/specifications/phase10/$baseline/p10_dev_dry_001"
done
```

Run ID là immutable trong từng baseline directory. Nếu ID đã tồn tại, tăng hậu
tố; không sửa hoặc xóa result để chạy đè.

`phase10_summary.json` ghi riêng `planned_api_eligible_contexts` và
`planned_fail_closed_contexts`. Context thiếu source/sink là một failure được
quan sát, không phải lý do nới schema hay gọi model không grounded.

Trước full API run, chạy một targeted pilot trên project có
`request_budget_adapted=true` trong full dry plan để exercise chính adaptive
path, không chỉ pilot project mặc định.

## 3. API pilot — nên chạy trong tmux

Xác nhận `.env` đã có `OPENROUTER_API_KEY`, route `akashml`, và spending limit
phù hợp. Connection validator tạo một request có thể tính phí; chỉ chạy khi cần:

```bash
bash scripts/tools/validate_openrouter.sh \
  --model-config configs/models/gpt_oss_20b_openrouter.yaml
```

Chạy B9 một project trước:

```bash
tmux new -s maxvera-p10-b9-pilot
cd ~/Documents/MaxVera
bash scripts/10_run_b9_full_useg.sh \
  --mode pilot --limit 1 --budget-mode budget_matched \
  --confirm-api-spend --run-id p10_b9_dev_pilot_001
```

Nhấn `Ctrl-b`, rồi `d` để detach; quay lại bằng:

```bash
tmux attach -t maxvera-p10-b9-pilot
```

Sau khi hoàn tất:

```bash
bash scripts/tools/validate_phase10.sh \
  --run-root results/specifications/phase10/full_useg/p10_b9_dev_pilot_001

jq . results/specifications/phase10/full_useg/p10_b9_dev_pilot_001/phase10_summary.json
```

Sau B9, chạy pilot riêng B6/B7/B8 bằng numbered script tương ứng. Không chạy
bốn API pilot song song; protocol yêu cầu một LLM request tại một thời điểm.

## 4. Resume sau khi tmux/process bị dừng

Chỉ resume directory `.inprogress` với cùng implementation/config và run ID:

```bash
bash scripts/10_run_b9_full_useg.sh \
  --mode pilot --limit 1 --budget-mode budget_matched \
  --confirm-api-spend --resume --run-id p10_b9_dev_pilot_001
```

Không dùng `--resume` nếu final directory đã tồn tại; khi đó run đã immutable và
mọi rerun phải có ID mới.

## 5. Full development runs

Chỉ chạy sau khi implementation/config/docs đã commit và `git status --short`
rỗng. Dùng một tmux session, chạy tuần tự B6 → B7 → B8 → B9:

```bash
tmux new -s maxvera-p10-full
cd ~/Documents/MaxVera

bash scripts/07_run_b6_program_graph_only.sh \
  --mode full --budget-mode budget_matched --confirm-api-spend \
  --run-id p10_b6_dev_full_001

bash scripts/08_run_b7_security_kg_only.sh \
  --mode full --budget-mode budget_matched --confirm-api-spend \
  --run-id p10_b7_dev_full_001

bash scripts/09_run_b8_useg_no_pruning.sh \
  --mode full --budget-mode budget_matched --confirm-api-spend \
  --run-id p10_b8_dev_full_001

bash scripts/10_run_b9_full_useg.sh \
  --mode full --budget-mode budget_matched --confirm-api-spend \
  --run-id p10_b9_dev_full_001
```

Validate từng run bằng `scripts/tools/validate_phase10.sh`. Full run có thể ghi
`STATUS=FAILED` do 15 Phase 9 misses hoặc synthesis failure; gate có thẩm quyền
là validator, final project coverage, budget, grounding và compile audit.

Trước khi khóa Phase 10 còn phải chấm spec precision/recall trên annotated
development subset theo protocol. Không dùng patch/test labels để sửa prompt,
retrieval hoặc spec sau khi xem kết quả; metric này hiện chưa thể tạo trước khi
có live specifications và annotation được khóa.

Evaluator chạy tách biệt và không sửa bốn synthesis artifact:

```bash
export MAXVERA_DATA_ROLE=evaluator
bash scripts/tools/evaluate_phase10_specs.sh --run-id p10_dev_spec_eval_003
bash scripts/tools/validate_phase10_evaluation.sh \
  --run-root results/evaluations/phase10/p10_dev_spec_eval_003
unset MAXVERA_DATA_ROLE
```

Gate dùng 91 development projects có fix-location annotation. Một specification
proxy-positive khi candidate CWE đúng và ít nhất một grounded source/sink location
giao method/class/file fix scope. Đây là paper-compatible proxy, không phải
static verification; 5 development projects không có fix-location annotation bị
ghi riêng và không nằm trong denominator của gate này.

## 6. Canonical development lock

Bốn full run được tạo tuần tự từ clean commit `184fef1`, đủ 96 final statuses,
khớp exact Phase 9 dependency và validator pass:

| Baseline | Run ID | Project success | Grounded specs | Compile rate |
|---|---|---:|---:|---:|
| B6 | `p10_b6_dev_full_001` | 54/96 | 763 | 100% |
| B7 | `p10_b7_dev_full_001` | 34/96 | 619 | 100% |
| B8 | `p10_b8_dev_full_001` | 78/96 | 801 | 100% |
| B9 | `p10_b9_dev_full_001` | 78/96 | 801 | 100% |

Canonical annotated gate là `p10_dev_spec_eval_003`, tạo từ clean evaluator
commit `6117b00`. Trên 91 annotated development projects, B9 có 762 emitted specs,
254 đúng candidate CWE, 14 paper-compatible proxy positives và phát hiện 6/91
projects. Kết quả thấp được giữ nguyên để Phase 11 kiểm chứng; không dùng nhãn để
repair prompt/retrieval/specification sau khóa.

## Output chính

```text
results/specifications/phase10/<baseline>/<run-id>/
├── contexts.jsonl
├── specifications.jsonl
├── generated_queries/<project>/*.ql
├── compile_attempts.jsonl
├── repair_log.jsonl
├── llm_calls.jsonl
├── project_status.jsonl
├── project_summary.jsonl
├── resource_usage.jsonl
├── phase10_summary.json
├── manifest.json
└── checksums.sha256
```

Không diễn giải `COMPILED` là vulnerability đã xác minh. Phase 11 mới chạy query
trên CodeQL database, lưu positive/negative evidence và cập nhật USEG iteration.
