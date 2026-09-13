# Phase 5 Runbook

**Mục đích:** chạy B3-B5 có kiểm soát sau Phase 4 mà không vô tình tiêu API,
không vượt label firewall và không coi B6-B9 placeholder là kết quả.

## Phạm vi hiện tại

- B0-B2: dùng kết quả Phase 4 đã có.
- B3: raw/chunked Java context + GPT-OSS 20B.
- B4: lexical text-RAG + GPT-OSS 20B.
- B5: static hypothesis, không dùng API.
- B6-B9: script/config tồn tại nhưng cố ý trả exit 78 cho đến khi dependency
  Phase 6-12 được triển khai.

B3-B5 dùng đủ 120 opaque project của `D_repro_v1`. Đây là bộ kiểm chứng triển
khai cùng release Phase 4, chưa phải main result trên `D_extended/test_locked`.
B3/B4 khóa route OpenRouter `akashml`; fallback sang provider khác bị cấm.

## 1. Kiểm tra offline

```bash
bash scripts/tools/assert_no_smoke_artifacts.sh
bash scripts/tools/preflight.sh --profile phase4
bash scripts/tools/estimate_phase5_budget.sh
```

Estimator mặc định dùng snapshot giá AkashML ngày 03/09/2026 là `$0.02/M`
input và `$0.10/M` billed output, đồng thời không gọi mạng. Có thể truyền giá
mới từ trang provider/dashboard để override snapshot:

```bash
bash scripts/tools/estimate_phase5_budget.sh \
  --input-price-per-million INPUT_USD \
  --output-price-per-million OUTPUT_USD
```

Với 120 project, nominal assumption là một call cho mỗi B3/B4 project: 240
calls. Con số hard ceiling lớn hơn nhiều vì protocol cho phép retry/call cap;
không nên dùng hard ceiling làm dự toán kỳ vọng.

`max_output_tokens` là trần billed completion, đã gồm reasoning. Dashboard có
thể vẽ Completion và Reasoning thành hai phần riêng, nhưng không cộng reasoning
thêm lần nữa khi tính giá output. Run thật lưu cả `output_tokens` (phần trả lời
không reasoning), `reasoning_tokens` và `billed_output_tokens` để tránh nhập
nhằng. `usage.cost` do OpenRouter trả về vẫn là nguồn chi phí chính xác nhất.

## 2. Dry-run không gọi API

```bash
bash scripts/04_run_b3_raw_context_gptoss20b.sh \
  --mode pilot --limit 1 --dry-run --run-id p5_b3_dry_001
bash scripts/05_run_b4_text_rag_gptoss20b.sh \
  --mode pilot --limit 1 --dry-run --run-id p5_b4_dry_001
bash scripts/06_run_b5_static_hypothesis.sh \
  --mode pilot --limit 1 --dry-run --run-id p5_b5_dry_001
```

Dry-run tạo plan có checksum dưới `results/baselines/<baseline>/<run-id>/` và
`STATUS=DRY_RUN`. Không dùng hay promote thư mục này thành scientific result.

## 3. Pilot thật

Chỉ B3/B4 cần xác nhận chi phí. Chạy tuần tự:

```bash
bash scripts/tools/validate_openrouter.sh
bash scripts/04_run_b3_raw_context_gptoss20b.sh \
  --mode pilot --limit 1 --budget-mode budget_matched \
  --confirm-api-spend --run-id p5_b3_pilot_001
bash scripts/05_run_b4_text_rag_gptoss20b.sh \
  --mode pilot --limit 1 --budget-mode budget_matched \
  --confirm-api-spend --run-id p5_b4_pilot_001
bash scripts/06_run_b5_static_hypothesis.sh \
  --mode pilot --limit 1 --budget-mode budget_matched \
  --run-id p5_b5_pilot_001
```

Không thêm `--confirm-api-spend` thì B3/B4 dừng trước request đầu tiên. Nếu tiến
trình bị ngắt khi còn thư mục `.run-id.inprogress`, chạy lại đúng lệnh với
`--resume`. Nếu run đã atomic-finalize nhưng có project fail, tạo run ID mới và
ghi `--parent-run-id`; không overwrite.

`validate_openrouter.sh` thực hiện một request nhỏ và vì vậy có phát sinh chi
phí rất nhỏ. Cả validator kết nối và runner đều từ chối chạy nếu
`MAXVERA_OPENROUTER_PROVIDER` không đúng `akashml`.

## 4. Evaluate và validate pilot

Evaluator là bước riêng có quyền đọc labels:

```bash
export MAXVERA_DATA_ROLE=evaluator
bash scripts/tools/evaluate_runs.sh \
  --run-root results/baselines/raw_context_gptoss20b/p5_b3_pilot_001
bash scripts/tools/validate_results.sh \
  --run-root results/baselines/raw_context_gptoss20b/p5_b3_pilot_001 \
  --require-metrics
```

Lặp lại với `text_rag_gptoss20b/p5_b4_pilot_001` và
`static_hypothesis/p5_b5_pilot_001`. Sau đó có thể `unset MAXVERA_DATA_ROLE` để
tránh vô tình chạy analyzer trong evaluator role.

Leaderboard chỉ nhận những run đã pass validator:

```bash
bash scripts/tools/generate_baseline_leaderboard.sh \
  --run-root results/baselines/raw_context_gptoss20b/p5_b3_pilot_001 \
  --run-root results/baselines/text_rag_gptoss20b/p5_b4_pilot_001 \
  --run-root results/baselines/static_hypothesis/p5_b5_pilot_001
```

## 5. Full budget-matched

Chỉ chạy khi pilot pass và số dư/hạn mức OpenRouter đủ:

```bash
bash scripts/tools/run_phase5_suite.sh \
  --mode full --budget-mode budget_matched \
  --confirm-api-spend --run-prefix p5_bm_full_001
```

Suite chạy B3, rồi B4, rồi B5; không song song. Evaluate và validate từng thư
mục như mục 4. Một baseline có project failure không chặn các baseline còn lại;
suite tiếp tục và cuối cùng trả exit khác 0 để buộc người chạy xem status. Nếu
suite trước đây đã dừng sau B3, tiếp tục cùng immutable prefix mà không gọi lại
B3 bằng:

```bash
bash scripts/tools/run_phase5_suite.sh \
  --mode full --budget-mode budget_matched \
  --confirm-api-spend --skip-existing \
  --run-prefix p5_bm_full_001
```

`best_effort` chỉ chạy sau budget-matched và phải dùng run ID mới:

```bash
bash scripts/tools/run_phase5_suite.sh \
  --mode full --budget-mode best_effort \
  --confirm-api-spend --run-prefix p5_be_full_001
```

## 6. Gate cần kiểm tra

- Mỗi project selected có final status. `STATUS=SUCCESS` khi tất cả thành công;
  nếu có failure thì giữ `STATUS=FAILED`, evaluator tính failure là miss và
  validator trả `PASS_WITH_ANALYSIS_FAILURES` khi accounting hợp lệ.
- Validator pass sau evaluator; project statuses và metrics đều đủ 120 dòng;
  tuyệt đối không drop, đổi status hoặc chạy lại riêng project thất bại để làm
  đẹp kết quả.
- B3/B4 manifest chỉ có returned model `openai/gpt-oss-20b`, provider route
  `akashml`,
  fallback tắt và prompt hash giống nhau.
- `resource_usage.csv` không vượt call/input cap; `llm_calls.jsonl` có request ID,
  usage, reasoning token, retry, latency và cost nếu provider trả về.
- Không dùng B1/B2 làm fair zero-hint comparator.
- Không diễn giải chênh lệch với B2/Groq Phase 4 là tác động của retrieval vì
  provider route khác nhau.
- Không chạy B6-B9 cho tới khi các phase dependency được hoàn thành.
