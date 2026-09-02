# Reproduction Report

**Mục đích:** báo cáo **IRIS pipeline reproduction with GPT-OSS 20B via OpenRouter** và variance.

## Điều kiện thực thi đã khóa

- Tái sử dụng 104 database có status `SUCCESS` từ Phase 2.
- Giữ nguyên 11 `BUILD_FAILED` và 5 `CODEQL_DB_FAILED` trong output 120/120;
  không bỏ qua im lặng.
- Dùng CodeQL 2.26.2, `codeql/java-queries` 1.11.7 và `codeql/java-all`
  9.2.2. Đây là toolchain substitution được người dùng chấp thuận vì CodeQL
  patched của IRIS không đọc được database mới.
- Chạy B0 CodeQL zero-hint, B1 CodeQL oracle-CWE và B2 IRIS + GPT-OSS 20B.
- `openai/gpt-oss-20b` chạy qua OpenRouter/provider `groq`, tuần tự, seed 1234,
  temperature 0, reasoning effort `low` và tối đa 2,048 output tokens.
- Tắt model/provider fallback, yêu cầu parameter support, ZDR và
  `data_collection=deny`.
- README context chỉ được đọc từ source checkout đã pin; B2 không tải README
  mutable từ mạng trong lúc phân tích.

## Sai khác bắt buộc báo cáo

GPT-OSS 20B qua hosted API thay model 32B của paper. Cấu hình hiện tại dùng
2,048 completion tokens như paper công bố; đây là thay đổi có chủ đích so với
giá trị 1,024 trong `src/models/config.py` của artifact vì reasoning tokens của
GPT-OSS được tính chung vào giới hạn completion. Public result có 121 rows do
CVE-2021-21345 được đánh giá ở cả CWE-078 và CWE-094, trong khi canonical
dataset có 120 project rows. Full runner tạo riêng row CWE-094 này và xuất cả
`metrics_dataset_canonical.json` lẫn `metrics_artifact_compatible.json`.

## Output và cách kiểm tra

Mỗi baseline/run có `manifest.json`, `project_status.jsonl`, raw SARIF/log,
metrics project, aggregate độc lập, `reproduction_variance.md` và
`checksums.sha256`. Bảng đối chiếu chung nằm ở
`results/paper/table_reproduction.csv`.

Chạy full trong tmux từ repository root:

```bash
tmux new-session -d -s maxvera-phase4 -c "$PWD" \
  'bash scripts/tools/run_phase4_reproduction.sh --mode full --run-id phase4_gptoss20b_full_001; exec bash'
tmux attach -t maxvera-phase4
```

Nếu tiến trình thật sự bị dừng (không chỉ SSH disconnect), tạo lại session với
cùng run ID và thêm `--resume`; runner bỏ qua project thành công, tiếp tục
`PENDING` và thử lại `ANALYSIS_FAILED`.

```bash
bash scripts/tools/validate_phase4.sh --run-id phase4_gptoss20b_full_001 --require-full
```

Không claim exact/numerical reproduction và không diễn giải chênh lệch số học
như bằng chứng về ưu/nhược điểm của model nếu chưa có phân tích bổ sung.
