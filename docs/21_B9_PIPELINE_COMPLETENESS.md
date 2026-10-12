# B9: kiểm tra completeness trước lượt chạy 120 case mới

Ngày kiểm tra: 2026-10-12. **Chưa chứng minh được lượt chạy mới sẽ hoàn tất
120/120 case không có lỗi vận hành.** Không dùng việc đủ 120 dòng metric để thay
cho điều kiện 120 project xử lý thành công.

Run `b9_benchmark_120_v2_003` vẫn là kết quả lịch sử: 120 case được tính vào mẫu số,
97 analysis success, 23 analysis failure, không bị ghi đè bởi đợt sửa này. Đối chiếu
nguyên nhân và giới hạn detected trong [audit](20_B9_BENCHMARK_FAILURE_AUDIT.md).

## Những điều đã sửa trong mã chạy

- Phản hồi HTTP có JSON envelope hỏng được retry hữu hạn. Retry vẫn cách nhau
  90 giây và giữ checkpoint/budget; sai model/provider và lỗi authentication
  tiếp tục dừng. Không coi JSON nội dung do model sinh ra sai schema là lỗi mạng.
- Discovery thành công với 0 hypothesis được đi tiếp qua graph, USEG, synthesis,
  verification và routing dưới trạng thái `NO_CANDIDATES`. Case vẫn có trong
  cohort và mẫu số, không gọi API và không có finding giả.
- Thiếu file hypothesis khác với một file hypothesis rỗng. Dependency thiếu,
  trùng hoặc còn `PENDING` project status bị từ chối dù checksum hợp lệ.
- Cấu hình strict không finalize một stage có project lỗi. Truy vấn lỗi, thiếu
  fixed-side execution và endpoint resolution lỗi không được che bằng project
  `SUCCESS`. Ambiguous fixed mapping, flow còn tồn tại sau vá và không có flow
  là những kết quả phân tích riêng, không được tự chuyển thành verified.
- Explicit resume giữ project đã thành công, retry project thất bại, lưu lịch sử
  và giữ nguyên API/query reservations. Hết budget vẫn bị chặn; không tự tăng
  ngân sách hay xóa terminal synthesis decisions.
- Kiểm tra coverage mã ứng dụng khi nhận/reuse database ở cả hai phía. Database
  chỉ có `buildSrc` không vượt gate. Bản dựng bổ sung dùng checkout riêng, toolchain
  đã pin và không sửa source/DB của lượt benchmark cũ.
- Giữ typed endpoint inventory/provenance nếu discovery flow query thất bại để
  có bằng chứng debug. Tmux launcher hiển thị log qua `tee`.

## Cấu hình mới và bằng chứng còn thiếu

Entry point benchmark mặc định dùng
[`b9_benchmark_120_complete.yaml`](../configs/experiments/b9_benchmark_120_complete.yaml).
Đây là **lượt chạy diagnostic mới**, không phải resume mang kết quả cũ sang cấu
hình đã thay đổi. Nó giữ model/provider/privacy, budget LLM, scoring/mapping và
metric gốc, dùng fresh discovery và không inherit synthesis cũ.

Chính sách mới có `require_all_projects_success`, `empty_discovery_is_success`,
explicit resume, kiểm tra coverage và query timeout/resource mới. CodeQL queries
dùng 4 threads/12288 MiB/7200 giây; extraction bảo trì dùng 2 threads/4096 MiB.
**Tăng timeout/resource chưa phải bằng chứng hai truy vấn HL7 đã chạy thành công.**

Coverage gate hiện yêu cầu 100% tập Java ứng dụng theo quy tắc đã công bố trong
`coverage.py`; bỏ qua test/example/template/build helpers/package metadata.
Đây là kiểm tra sự có mặt của file trong archive, không phải chứng minh mọi
method đều được mô hình hóa đúng. Không dùng CVE, annotation hoặc CWE thật để
chọn file cho analyzer. Bản fixed chỉ được kiểm tra trong evaluator process.

Scan đầy đủ đầu tiên ở
[`b9_full_pipeline_readiness_003`](../results/diagnostics/b9_full_pipeline_readiness_003/summary.json)
có 57/120 case đạt coverage ở cả hai phía và 63 case cần xem xét/bổ sung theo
policy tại thời điểm scan. Đây không phải 63 analysis failure mới: một số gap
là compiler variant hoặc duplicate class giữa module. DSpace có hai file cùng
`org.dspace.utils.DSpaceWebapp`; không được âm thầm giả định tất cả file đã extract.
Policy hash được ghi ở các scan mới để phân biệt khi quy tắc coverage thay đổi.

Scan cập nhật theo policy hiện tại
[`b9_full_pipeline_readiness_005`](../results/diagnostics/b9_full_pipeline_readiness_005/summary.json)
đã ghi đủ 120 case: **64 READY, 56 BLOCKED**, 0 API call, chưa validate queries.
Đây là checkpoint trong khi bảo trì đang dựng bổ sung, không phải kết quả phân
tích mới và không phải chứng nhận toàn bộ pipeline đã chạy.

Scan vulnerable toàn tập phát hiện ba database coverage thấp rõ rệt:
Spring4Shell (0/3983 Java ứng dụng), xwiki-commons (~19.6%), spring-security-oauth
(~94.9%). Tập file/ratio cụ thể phải đọc từ report tương ứng vì quy tắc phân loại
application files được cải thiện trong audit.

Đợt dựng bổ sung không gọi LLM đang ghi vào
[`b9_full_pipeline_readiness_004`](../results/diagnostics/b9_full_pipeline_readiness_004/projects.json)
và `data/interim/b9_coverage_repairs_001`. Nó chưa phải certificate sẵn sàng:
scan cuối phải dùng code hiện tại, đủ 120 records, `PASS`, cùng config/policy hash,
và archive/metadata checksum không đổi. Không hạ coverage threshold hoặc đổi
metric để làm số project thành công tăng lên.

Pilot đã dựng lại vulnerable xwiki-commons đạt 1168/1168 file và
spring-security-oauth đạt 372/372 file. Truy vấn endpoint CodeQL thật PASS, lần
lượt có 254 và 71 endpoint. Flow discovery thật cũng PASS: xwiki có 81 relation
và 10 hypothesis; oauth có 0 relation/0 hypothesis, là outcome không ứng viên.
Pilot dùng 2 threads/4096 MiB/600 giây và 0 API calls, ghi riêng trong
[`b9_application_db_pilot_001`](../results/diagnostics/b9_application_db_pilot_001/summary.json).
Bản dựng Spring4Shell đạt 3982/3983 file, còn thiếu
`spring-test/src/main/java/org/springframework/mock/env/MockEnvironment.java` và
vẫn bị gate chặn. Không gọi bản dựng này là đã hoàn toàn sửa xong.

Theo dõi job bảo trì: `tmux attach -t maxvera-b9-readiness-120`. Window `progress`
hiển thị log; window `audit` đợi lượt repair hiện tại kết thúc, rồi tự scan lại
bằng code mới vào `_006`. Chỉ khi scan PASS mới chạy `--validate-only`; cả nhánh
này không gọi LLM. Phiên benchmark cũ không bị khởi động lại.

## Kiểm tra không gọi API

Chọn output mới nếu inputs/config/policy đã thay đổi. Chỉ chạy một job bảo trì
cho cùng cache tại một thời điểm; kiểm tra job đang chạy trước khi lặp lệnh.

```bash
MAXVERA_DATA_ROLE=evaluator uv run --frozen python -m src.pipeline_v2.readiness \
  --config configs/experiments/b9_benchmark_120_complete.yaml \
  --output results/diagnostics/b9_full_pipeline_readiness_NEW \
  --repair --workers 3
```

Đầu ra phải là `PASS`, `projects=120`, `ready=120`, `blocked=0`, `api_calls=0`.
CLI trả exit 1 nếu còn input bị chặn. Report ghi từng side/database, checksum,
coverage, revision và lỗi; không loại project khỏi selection khi extraction lỗi.

Sau khi freeze implementation sạch và input readiness PASS, chạy các bước CodeQL
và grounding thật, vẫn không gọi LLM:

```bash
uv run --frozen python -m src.pipeline_v2.benchmark \
  --config configs/experiments/b9_benchmark_120_complete.yaml \
  --run-id b9_benchmark_120_complete_001 --validate-only
```

Lệnh này chạy input preparation, P6, P7, P9 và P10 dry-run cho đủ 120 case.
Nó không chạy paid synthesis hay chứng nhận P11 với đặc tả chưa sinh. Nếu lỗi,
đọc stage log/`strict_gate.json`, sửa đúng nguyên nhân rồi explicit `--resume`;
không đánh dấu thành công thủ công. Giữ snapshot sạch, không thay code/config/DB
khi một stage đang chạy hoặc khi muốn tái sử dụng stage đã freeze.

Khi các gate đã PASS, cùng run ID cho phép controller reuse các stage đã hoàn
tất của cùng snapshot; paid pilot vẫn kiểm tra fixed preparation và verifier
trước full synthesis:

```bash
uv run --frozen python -m src.pipeline_v2.benchmark \
  --config configs/experiments/b9_benchmark_120_complete.yaml \
  --run-id b9_benchmark_120_complete_001 --confirm-api-spend
```

Không có paid benchmark mới được khởi động trong đợt audit này. Điều kiện thành
công cuối cùng là mọi stage có đúng tập 120 ID, 120 `SUCCESS`, không lỗi vận hành
ẩn trong verifier, mỗi spec có đúng một verification và routing record, cùng
snapshot/provenance, calibration chỉ fit 96 dev, evaluator giữ mẫu số 120.
Không yêu cầu mọi case phải detected hoặc verified để được coi đã xử lý hoàn tất.

## Kiểm thử

230 tests PASS; Ruff và mypy toàn bộ source PASS; launcher qua `bash -n`.
Validator độc lập trên run003 vẫn trả `PASS_WITH_ANALYSIS_FAILURES` với đúng
97 success/23 failure. Thử `--dry-run` với default mới bị chặn đúng ở input
readiness trước khi tạo controller hoặc gọi API.

Kiểm thử hồi quy bao gồm HTTP envelope hỏng phục hồi với pacing 90 giây,
route drift vẫn fatal, database chỉ có buildSrc, thiếu application module,
production package tên `resources/tests`, dependency mất project, strict resume
giữ budget, pipeline 120 case rỗng tới routing, validator bắt query failure bị
che bởi `SUCCESS`, no-API controller không vào paid branch, readiness vẫn ghi
đủ 120 case khi một archive lỗi và hủy subprocess khi dừng job bảo trì.

Các kiểm thử dùng provider/CodeQL giả ở biên để kiểm tra luồng điều khiển; không
thay cho truy vấn trên 120 database thật hoặc cho pilot có đặc tả LLM thực tế.
