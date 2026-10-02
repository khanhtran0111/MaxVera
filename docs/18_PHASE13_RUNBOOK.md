# Phase 13 Runbook

## Trạng thái và ranh giới dữ liệu

Phase 13 là workload dài và được chia thành hai process boundary:

1. **Analyzer pass** mở danh sách 24 opaque `test_locked` IDs, source và CodeQL
   database, nhưng không được đọc evaluator labels. Pass này chạy B0, B3-B9 và
   materialize Program Graph/USEG/specifications thành immutable run roots.
2. **Evaluator pass** chỉ bắt đầu sau khi analyzer snapshot hoàn tất. Pass này
   chạy B1/B2 oracle, fixed-version verification, áp dụng nguyên model/threshold
   Phase 12, metrics/bootstrap và robustness. Không được tune lại model,
   threshold, prompt, retrieval hoặc budget sau khi test đã mở.

Config ma trận đã khóa tại `configs/experiments/phase13.yaml` và
`configs/experiments/ablation.yaml`. Canonical run dùng temperature `0`, seed
`1234`, `budget_matched`; robustness dùng năm seed `1234, 2345, 3456, 4567,
5678` cho Full và baseline mạnh nhất được chọn chỉ từ development.

## Preflight ngắn

```bash
bash scripts/tools/preflight_phase13.sh
```

Kết quả hợp lệ phải là `READY_FOR_LONG_ANALYZER_RUN`, 24 test projects, 24
source aliases, CodeQL/OpenRouter configured, và đúng hash model/threshold của
`p12_calibration_dev_full_001`. Preflight không mở evaluator labels và không
gọi API.

## Chạy analyzer pass trong tmux

Chỉ chạy từ clean commit. Job chạy tuần tự vì máy 32 GB RAM và có thể kéo dài
nhiều giờ (ba database có thể cần build; B0 và B6-B9 gọi CodeQL; B3/B4/B6-B9
gọi OpenRouter):

```bash
tmux new -s maxvera-p13
cd ~/Documents/MaxVera
bash scripts/tools/run_phase13_analyzer.sh p13_test_analysis_001 all \
  2>&1 | tee logs/p13_test_analysis_001.log
```

Detach bằng `Ctrl-b`, rồi `d`. Gắn lại:

```bash
tmux attach -t maxvera-p13
```

Xem log mà không attach:

```bash
tail -f logs/p13_test_analysis_001.log
```

Pipeline có thể resume theo immutable stage. Nếu dừng giữa chừng, chạy lại cùng
command/run ID; stage đã hoàn tất sẽ được bỏ qua. Nếu một runner còn thư mục
`.inprogress`, dùng chính runner đó với `--resume` theo lỗi được in trong log,
không xóa output hoặc đổi run ID trước khi audit nguyên nhân.

Có thể chạy tách stage để dễ theo dõi:

```bash
bash scripts/tools/run_phase13_analyzer.sh p13_test_analysis_001 foundations
bash scripts/tools/run_phase13_analyzer.sh p13_test_analysis_001 specifications
bash scripts/tools/run_phase13_analyzer.sh p13_test_analysis_001 baselines
```

`foundations` không gọi LLM; `specifications` chạy B6-B9; `baselines` chạy B0,
B5 rồi B3/B4. Wrapper truyền xác nhận mở locked test và API spend một cách
explicit. Mọi stage vẫn fail-closed nếu role không phải `analyzer`.

B3/B4/B5 chấp nhận source đã chuẩn bị trong `project_sources` hoặc
`phase6_project_sources`; source alias phải resolve vào một trong hai thư mục
này. Stage `baselines` kiểm tra output cuối của từng baseline, nên lỗi cấu hình
không còn bị bỏ qua như một project analysis failure. Project thất bại đã ghi
nhận trong output cuối vẫn được giữ và tính là miss theo protocol. Chạy lại
stage chỉ xử lý baseline chưa có output cuối, không retry immutable run.

## Sau analyzer pass

Không tự mở/chấm evaluator labels ngay. Gửi lại cuối log và file
`results/phase13/p13_test_analysis_001/analyzer_status.json` để kiểm tra run
IDs/checksums và khóa analyzer snapshot trước khi khởi động evaluator pass.
Phase 13 chỉ hoàn tất sau evaluator pass, toàn bộ B0-B9, A0-A5/Full, năm seed
robustness và project-level bootstrap đều trỏ đến immutable run IDs.

## Audit, khóa snapshot và chạy verification trên test

Từ clean commit, audit đủ 11 analyzer outputs (Phase 6/7/9, B0, B3-B9),
giữ analysis failures làm miss và khóa checksum trước khi mở evaluator labels:

```bash
uv run --frozen python -m src.experiments.phase13_snapshot \
  --run-id p13_test_analysis_001
bash scripts/tools/run_phase13_evaluator.sh p13_test_analysis_001 all
```

Evaluator wrapper bắt buộc role `evaluator` và xác minh toàn bộ snapshot.
Nó ghi metrics proxy riêng cho 24 test projects, chuẩn bị fixed database
chỉ cho B9 `SUCCESS`, chạy differential verification theo nguyên policy Phase 11,
rồi áp dụng model/threshold Phase 12 mà không fit/tune lại. Source, labels,
config và database của development giữ scope riêng; không đổi tên test thành
development. Output nằm trong `results/phase13/<run_id>/evaluation`; không thêm
metrics hay thay checksum trong analyzer run roots đã chốt.

`analyzer_snapshot.json` là immutable. `evaluator_status.json` theo dõi tiến độ;
chạy lại wrapper bỏ qua output cuối đã kiểm tra và resume verification còn
`.inprogress`. Fixed preparation giữ database thành công và checkpoint từng
project. Nếu lỗi hạ tầng ngăn tạo output cuối, evaluator dừng với status `FAILED`.

Pass này thực hiện metrics proxy, A5 differential verification, frozen routing
và metrics của từng routing cohort. Cohort `VERIFY` không tự trở thành final
Full verdict. B1/B2 oracle, năm seed robustness, paired bootstrap và báo cáo
ablation cuối là workload riêng; `evaluator_status.json` liệt kê phần còn chờ
và không đánh dấu toàn bộ Phase 13 hoàn tất.

## Follow-up sau evaluator pass

Chạy audit, bootstrap/report hiện có và B1/B2 oracle tuần tự:

```bash
bash scripts/tools/run_phase13_followup.sh p13_test_analysis_001
```

Wrapper yêu cầu clean Git worktree trước khi tạo canonical oracle output;
ghi log có timestamp và exit sidecar trong `logs/`. Trạng thái tiến độ nằm tại
`results/phase13/<run_id>/evaluation/followup_status.json`. B1 rồi B2 chạy một
project/lần. Khi resume, chỉ project chưa có trạng thái cuối được xử lý; một
analysis failure đã chốt vẫn tính là miss, không được retry để cải thiện metric.
Output oracle hoàn tất có checksum, đủ 24 project, SARIF, per-project metrics,
resource usage và validator tái tính metrics từ raw output.

B1 dùng CodeQL per-CWE. B2 dùng pinned IRIS, GPT-OSS 20B/`akashml`, seed 1234,
temperature 0 và budget-matched. IRIS chỉ nhận CWE oracle cùng source/database
opaque; không nhận advisory hay fix-location hints. Internal IRIS evaluation và
module filtering từ patch đều tắt; parent evaluator chấm SARIF sau analysis.
Adapter CodeQL chính là toolchain substitution được ghi explicit, không claim
exact numerical reproduction. Request bị chặn trước API nếu vượt context/call/
project budget; actual usage cũng được kiểm tra và ghi failure nếu vượt cap.

Audit đọc source archives trong vulnerable/fixed database và ánh xạ chỉ những
dòng thuộc diff block giữ nguyên. `--check-fixed` chạy query đã remap trong
artifact diagnostic riêng để kiểm tra line-shift confounding; không sửa query,
verdict, model hay checksum canonical:

```bash
MAXVERA_DATA_ROLE=evaluator uv run --frozen python -m src.experiments.phase13_audit \
  --run-id p13_test_analysis_001 --audit-id verification_audit_001 --check-fixed
```

Audit ngày 02/10 xác nhận cả 4 canonical differential specifications còn path
trong fixed database sau remap dòng 306→307 và 308→309. Có 2 nhóm endpoint;
đây không phải số vulnerability độc lập. `verification_audit_001` giữ query,
endpoint CSV, SARIF và evidence. Vì vậy canonical validator PASS chỉ xác nhận
artifact hợp lệ theo verifier cũ, chưa xác nhận scientific correctness.

Report A0–A5 hiện tại giữ nguyên canonical numbers và ghi caveat audit. Bootstrap
10.000 draws resample cả repository group, giữ toàn bộ project rows và paired
method alignment; có failures-as-miss và common-success sensitivity. Chỉ so
sánh Recall giữa method cùng operational positive definition, không trộn
fix-location proxy với CWE-and-endpoint proxy hay differential verdict. Exact
McNemar có Holm correction riêng cho từng family/sensitivity. Precision/FDR
proxy không thay thế adjudication các `UNKNOWN_UNREVIEWED` findings.

`evaluation/robustness_plan.json` liệt kê năm seed cho Full và strongest baseline.
Robustness chưa chạy khi verifier audit còn confounded hoặc chưa có immutable
development-only baseline-selection lock. Selection phải có đầy đủ B0/B3–B8
candidate coverage trên đúng development split; không chọn từ test results.
Runner `phase13_robustness` hiện là prerequisite/seed-config preparer, chưa phải
executor Full end-to-end. Full verdict policy, verifier review và các workload
phụ thuộc được ghi pending; không đánh dấu `phase13_complete=true`.
