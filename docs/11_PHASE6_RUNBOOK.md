# Phase 6 Runbook

**Mục đích:** tạo và đánh giá Top-10 vulnerability hypotheses trên development
split mà không đọc CVE/CWE/advisory/fix metadata trong analysis process và không
chạm vào `test_locked`.

## Phạm vi và contract

- Dataset: `D_extended`, chỉ 96 opaque project trong `development.csv`.
- `test_locked.csv` có 24 project và bị runner/validator cấm tuyệt đối.
- `static`: quét Java source để tìm input boundary, source, sink, sanitizer và
  public entry point; không gọi API.
- `hybrid`: dùng đúng static candidates rồi cho GPT-OSS 20B/AkashML đổi thứ tự;
  model không được thêm candidate, CWE, file hoặc line.
- Một hypothesis luôn có source/sink candidates, preconditions, locations,
  score và provenance về rule/source evidence.
- Primary metrics: Recall@1/3/5/10 và MRR; analysis failure được tính là miss.

## 1. Chuẩn bị source và kiểm tra offline

Phần lớn row của hai release trỏ tới cùng vulnerable revision nhưng dùng opaque
project ID khác nhau; 10 row D_extended có commit metadata đã được sửa. Lệnh sau
tạo alias cho revision trùng và fetch đúng corrected revision cho phần còn lại ở
data-preparation boundary; mapping identity không được ghi vào output analyzer:

```bash
cd ~/Documents/MaxVera
bash scripts/tools/prepare_phase6_sources.sh
uv run --frozen pytest -q tests/unit/test_phase6_hypotheses.py
bash scripts/tools/estimate_phase6_budget.sh
```

Estimator không gọi mạng. Với snapshot `$0.02/M` input và `$0.10/M` billed
output, hard ceiling của hybrid development run là `$0.02555904`; static luôn
có API cost bằng 0.

## 2. Dry-run và static pilot

Mỗi run ID là immutable, vì vậy dry-run và run thật phải dùng ID khác nhau:

```bash
bash scripts/tools/run_phase6_hypotheses.sh \
  --generator static --mode pilot --limit 1 --dry-run \
  --run-id p6_static_dev_dry_002

bash scripts/tools/run_phase6_hypotheses.sh \
  --generator static --mode pilot --limit 1 \
  --run-id p6_static_dev_pilot_004
```

Evaluate và validate là bước riêng có quyền đọc label:

```bash
export MAXVERA_DATA_ROLE=evaluator
bash scripts/tools/evaluate_phase6.sh \
  --run-root results/hypotheses/static/p6_static_dev_pilot_004
unset MAXVERA_DATA_ROLE

bash scripts/tools/validate_phase6.sh \
  --run-root results/hypotheses/static/p6_static_dev_pilot_004 \
  --require-metrics
```

## 3. Static full development run bằng tmux

Static mode không gọi API nhưng nên dùng tmux để tránh terminal disconnect:

```bash
tmux new -s phase6_static
cd ~/Documents/MaxVera
bash scripts/tools/run_phase6_hypotheses.sh \
  --generator static --mode full \
  --run-id p6_static_dev_full_001
```

Detach bằng `Ctrl+B`, rồi `D`; attach lại bằng:

```bash
tmux attach -t phase6_static
```

Sau khi hoàn thành, evaluate/validate tương tự pilot nhưng thay run root bằng
`results/hypotheses/static/p6_static_dev_full_001`.

## 4. Optional hybrid pilot

Chỉ thực hiện sau khi static full pass và đã kiểm tra số dư API:

```bash
bash scripts/tools/validate_openrouter.sh
bash scripts/tools/run_phase6_hypotheses.sh \
  --generator hybrid --mode pilot --limit 1 \
  --confirm-api-spend --run-id p6_hybrid_dev_pilot_001
```

Không có `--confirm-api-spend`, runner dừng trước request đầu tiên. Hybrid full
chỉ được chạy nếu pilot pass và metric/ranking contract được audit; dùng run ID
mới và tmux:

```bash
tmux new -s phase6_hybrid
cd ~/Documents/MaxVera
bash scripts/tools/run_phase6_hypotheses.sh \
  --generator hybrid --mode full --confirm-api-spend \
  --run-id p6_hybrid_dev_full_001
```

## Gate Phase 6

- Full status/metric coverage đúng 96 development projects.
- Không output nào chứa project ID thuộc locked-test split.
- Mọi hypothesis có location tồn tại, canonical CWE list và provenance.
- Static run có zero LLM call; hybrid tối đa một successful call/project và chỉ
  dùng `openai/gpt-oss-20b` qua AkashML, fallback tắt.
- Recall@1/3/5/10 và MRR được evaluator tái tạo, checksum pass.
- Không chạy test-locked; chỉ khóa generator/Top-k từ development metrics rồi
  chuyển sang Phase 7.
