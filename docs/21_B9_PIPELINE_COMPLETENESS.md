# B9: kiểm tra completeness trước lượt chạy 120 case mới

Ngày kiểm tra: 2026-10-13. **Đầu vào đã đạt 120/120 READY, 0 BLOCKED: unblock
35/35 case bị chặn ở lượt 008.** Cả 240 record vulnerable/fixed đạt 100% độ phủ mã
Java ứng dụng; giữ đúng 120 ID, không bỏ/thay case. Xem
[acceptance004](../results/diagnostics/b9_unblock_acceptance_004/summary.json) và
[final scan015](../results/diagnostics/b9_full_pipeline_readiness_015_final/summary.json).

Benchmark input preflight PASS, 240 tests PASS, Ruff/mypy PASS, 0 API LLM. Đây là
bảo trì đầu vào; chưa chạy lại full end-to-end và chưa có số liệu detection mới.
Input preflight không thay cho full query validation hoặc một lượt benchmark
thực tế thành công 120/120. Entry point thật vẫn yêu cầu snapshot Git sạch.

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
dùng 4 threads/12288 MiB/7200 giây; extraction bảo trì dùng 2 threads/4096 MiB,
repository có từ 50.000 file Java ứng dụng dùng 12288 MiB.
**Tăng timeout/resource chưa phải bằng chứng hai truy vấn HL7 đã chạy thành công.**

Coverage gate hiện yêu cầu 100% tập Java ứng dụng theo quy tắc đã công bố trong
`coverage.py`; bỏ qua test/example/template/build helpers/package metadata.
File rỗng/comment-only được miễn theo blob của đúng revision, có danh sách và
lý do trong report. File trích xuất bổ sung phải có type trong mô hình CodeQL;
pilot kiểm tra cả method và local flow. Đây chưa phải chứng minh mọi method đều
được mô hình hóa đúng. Không dùng CVE, annotation hoặc CWE thật để
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

### Tiếp tục bảo trì ngày 12/10

Lượt repair `_004` đã bị ngắt khi mới ghi 46 case. Log không có traceback cuối
hoặc mã thoát và kernel log còn lưu không có bằng chứng OOM, nên chưa xác định
được nguyên nhân hệ điều hành; không quy lỗi này cho API. Scan `_006` sau đó đã
kiểm tra đủ 120 case, **68 READY/52 BLOCKED**, không bắt đầu validation/LLM.

Đã bổ sung launcher tmux riêng và khóa độc quyền cache. `lifecycle.json` ghi PID,
thời điểm bắt đầu/kết thúc, `RUNNING/PASS/BLOCKED/INTERRUPTED/FAILED`.
`launcher_status.json` ghi thêm exit code và kết quả validation. CLI xử lý
SIGTERM để hủy tác vụ đang xếp hàng và dừng process group CodeQL. Lượt `_007`
được chủ động dừng bằng SIGTERM khi chuyển sang quy trình mới; đây là interruption
có ghi nhận, không phải một lượt repair hoàn tất.

Quy trình hiện tại **scan đủ 120 case trước khi sửa**, giữ các dòng READY/BLOCKED
trong report trong suốt thời gian dựng DB, ưu tiên repository nhỏ trước. DB hợp
lệ trong cache được reuse; DB cache không đạt được giữ riêng để chẩn đoán. Không
đụng source/DB của benchmark cũ. Coverage kiểm tra thêm Git revision trong
`creationMetadata` và từ chối DB chưa finalize hoặc metadata hỏng. 152 side READY
trong snapshot `_006` đều có metadata SHA trùng revision cần phân tích.

Quy tắc path loại thêm `src/testFixtures`, `src/test-*`, `src/it` và demo.
Java package tên `tests/resources/testFixtures/it` dưới `src/main/java` vẫn được
giữ. Extraction của profile mới dùng
`-Ojava.exclude=**/src/{test,testFixtures,test-*,it}/**` để bản test không che
bản production trùng tên. Pilot CodeQL thật
`b9_extraction_collision_pilot_001` cho thấy archive chỉ chứa bản production.
Chưa dùng pilot nhỏ này để khẳng định Spring thật đã sửa xong.

Thử nghiệm `b9_multimodule_extraction_pilot_001` dùng `index-files` để bổ sung
một lớp production trùng FQN trước finalize: archive chứa cả hai file nhưng
query chỉ thấy method của một bản. **Không áp dụng workaround này cho repair**
và không thêm file vào archive bằng tay để vượt gate. Duplicate production
variants và AspectJ/template cần giải quyết theo build/source scope có bằng
chứng; hints trong gap audit không miễn coverage cho bất kỳ file nào.

Lượt repair đang dùng quy trình mới:
[`b9_full_pipeline_readiness_008`](../results/diagnostics/b9_full_pipeline_readiness_008/summary.json).
Scan đầu của lượt này có đủ 120 case, **69 READY/51 BLOCKED**; các số này là
checkpoint trước repair, không phải kết quả cuối. Xem `projects.json` và
`progress.log` để biết tiến độ mới nhất. Báo cáo phân loại đầu vào được freeze
riêng trong `results/diagnostics/b9_input_gap_audit_002`, có CSV đủ 120 case,
module thiếu và sample bằng chứng source; không dùng evaluator report làm prompt.
Snapshot audit lúc 19:23 ngày 12/10 có **73 READY/47 BLOCKED**, 79 side cần xử lý,
0 API call/0 CodeQL query/0 coverage waiver; đọc blob bằng `git --no-lazy-fetch`.
Đây vẫn là checkpoint trong lúc repair chạy, không phải certificate hoàn tất.

Theo dõi: `tmux attach -t maxvera-b9-readiness-120`, window **`repair`** mới.
Window `progress` cũ vẫn tail các log lịch sử và có thể đứng yên. Launcher tự scan
lại vào `_008_final` sau khi repair trả kết quả bình thường; chỉ khi input PASS
mới chạy `--validate-only`, tuyệt đối không bắt đầu paid synthesis. Phiên benchmark
cũ không bị khởi động lại.
Cửa sổ repair giữ lại màn hình khi tiến trình thoát để thấy mã thoát và trạng thái.

```bash
bash scripts/tools/run_b9_readiness_120_tmux.sh NEW_OUTPUT_NAME
```

Launcher từ chối output đã tồn tại; khóa cache ngăn hai lượt bảo trì chạy trùng.
Lượt mới vẫn kiểm tra đủ cohort và reuse DB đã đạt; không phải restart benchmark.

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

238 tests PASS; Ruff và mypy toàn bộ source PASS; launcher qua `bash -n`.
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

Hồi quy bổ sung kiểm tra khóa cache khi có writer khác, lifecycle khi bị ngắt,
scan đủ 120 dòng trước extraction đầu tiên, giữ cohort khi repair lỗi, revision
mismatch/in-progress database và các source set test mới được phân biệt đúng.

## 2026-10-13 — Mở rộng extraction cho 35 case còn bị chặn

Lượt `_008_final` đã hoàn tất đủ 120 case: **85 READY/35 BLOCKED**, 0 API call.
34 case còn source archive gap; AWS fixed có lỗi Java heap thật ở 4096 MiB.
Đây là input readiness, chưa phải kết quả detection hoặc query validation.

Đã thêm kiểm tra nội dung blob tại đúng Git revision để miễn yêu cầu extraction
cho file rỗng/comment-only, ghi rõ từng file trong coverage report. Strings/text
blocks được giữ khi nhận diện comment; blob không đọc được vẫn bị chặn. Giới hạn
512 blob/lần chỉ giới hạn miễn trừ: mọi file chưa kiểm tra vẫn là missing.
Không hạ threshold 1.0, không miễn trừ theo CVE, fix location hoặc kết quả mong muốn.
Hai HL7 đã qua input gate nhờ bốn file generator/configuration đều không có mã.
Chưa khẳng định các truy vấn HL7 trước đây timeout đã được sửa.

`src/pipeline_v2/extraction.py` dựng DB qua init/trace/finalize và bổ sung từng
source root còn thiếu, bật `ODASA_JAVA_CLASS_ORIGIN_TRACKING=true` và dùng compiler
output riêng cho mỗi nhóm. Không sửa Java source, TRAP hoặc ZIP thủ công.
Pilot `_003`/`_004` vẫn chỉ query thấy một biến thể lớp; pilot `_005` bật origin
tracking query thấy cả hai method `a`/`b` tại đúng hai file; query local data flow
từ parameter tới return cũng PASS cho cả hai biến thể. DSpace thật ở
`b9_module_repair_real_pilot_001` đạt 1445/1445 và query xác nhận type của file
trước đây thiếu, nhưng pilot này đã bị supersede vì wrapper của supplement dùng
JDK bundled thay vì JDK project đã pin. Không dùng pilot001 làm certificate cuối.

Mọi supplement cần qua query `RefType.fromSource()` ở đúng file. Record PENDING,
BLOCKED, query failure hoặc missing modeled type không được reuse chỉ vì ZIP đủ
file. Coverage report pin SHA của model check; readiness/preflight pin thêm hash
extraction policy. Cơ chế được dùng chung ở bảo trì và fallback vulnerable/fixed
preparation của profile strict, không sửa cấu hình benchmark lịch sử.

Extraction giữ 4096 MiB cho repository thường; repository có từ 50.000 file Java
ứng dụng dùng 12288 MiB/2 threads. Đây là thay đổi resource theo kích thước đầu
vào, không theo annotation. Lượt `_009` chạy 2 worker, scan đầu **87 READY/33
BLOCKED**, giữ đủ 120 record rồi sửa các case còn thiếu; số cuối cần đọc report.

```bash
bash scripts/tools/run_b9_readiness_120_tmux.sh b9_full_pipeline_readiness_010 --inputs-only
tmux attach -t maxvera-b9-readiness-120
```

Window `repair-009` giữ log lịch sử; lượt009 đã được chủ động dừng bằng SIGTERM
lúc 03:36:41Z để sửa pinned-driver provenance, lifecycle ghi INTERRUPTED. Không
phải API limit hoặc interruption không rõ nguyên nhân. Các checkpoint READY của
009 thuộc policy cũ và không phải certificate theo policy sau sửa.
`--inputs-only` dừng sau final input scan, không tự chạy các stage benchmark hay
LLM. Không chạy hai job dùng chung cache. Chỉ gọi 120/120 input READY khi report
`_010_final` PASS với cùng config/policy hash; vẫn cần validation pipeline riêng.

### Sửa pinned extraction driver và tiếp tục bằng policy mới

Wrapper supplement hiện chạy bằng `$JAVA_HOME/bin/java` từ toolchain đã pin.
CodeQL vẫn tự dùng JVM extractor đi kèm, nhưng wrapper truyền đúng language level
và boot classes của project. Model-check record pin SHA extraction policy, driver
binary và JAVA_HOME; record từ wrapper cũ thiếu provenance bị từ chối reuse.
Toy006 dùng chính helper production với JDK8: coverage2/2, methods `a`/`b` và
local flows qua cả hai file PASS.238testsPASS,Ruff/mypyPASS.

Readiness hỗ trợ reuse DB giữa các case có cùng Git commit, cùng side và cùng
JDK/Maven/Gradle. Vẫn recheck revision/coverage/model provenance; không dùng
fixed-side DB làm analyzer input. Các DB cần sửa theo provenance mới sẽ được dựng
lại; không đổi marker cũ thành PASS thủ công. Lượt010 sẽ giữ config/policy mới
trong suốt quá trình chạy và ghi final scan riêng; không có paid benchmark.
Real DSpace pilot002 dùng pinned driver PASS1445/1445 và modeled-type check; DB
đã được copy vào cache sau khi giữ lại bản pilot001 dưới rejected. Lượt010 khởi
động lúc 03:44Z, trong tmux window repair mới, input-only và 2 worker.
Scan đầu010 có **88 READY/32 BLOCKED** theo policy pinned-driver mới; toàn bộ
120 case đã được kiểm tra trước repair. Không so checkpoint009 với010 như metric
detection vì provenance policy đã thay đổi.

Sau full input PASS, tool `scripts/tools/promote_b9_readiness_inputs.py` có thể
đưa DB vulnerable đã kiểm tra vào đường dẫn cache opaque bằng symlink, dưới khóa
cache và recheck archive/metadata/model SHA. Không sửa nội dung DB/historical
inputs; analyzer chỉ đọc DB vulnerable, không đọc report có fixed revision. Scan
lại sau promotion để pin đường dẫn cache mà bước input preparation sẽ reuse.
Tool đã được kiểm tra từ chối lượt IN_PROGRESS trước mọi mutation.

### Bảo toàn DB khi gate ném exception và lượt xác nhận cuối

Trong lúc010 chạy, `extraction.py` bị thay đổi xuống dòng (không đổi logic), làm
hash không còn khớp policy chốt. Gate từ chối các side Keycloak trùng thời điểm
này dù model query PASS; đã khôi phục chính xác file của snapshot002. Không sửa
model-check record để ép PASS. Lỗi được giữ trong report010; lượt recovery011
sẽ reuse các DB hợp lệ và dựng lại side vẫn bị chặn sau final scan010.

Đã sửa `readiness.extract` để cả exception từ coverage/model gate sau extraction
cũng giữ DB dưới `rejected`, thay vì bị cleanup cùng scratch.239testsPASS,
RuffPASS và mypy126filesPASS; extraction/coverage policy và config không đổi.

Tmux có window `finish-inputs` chạy `results/diagnostics/b9_finish_inputs_001.py`:
chờ launcher010 kết thúc, nếu BLOCKED thì recovery011 và scan012; chỉ sau full
input PASS mới promotion, scan013 và benchmark `--dry-run` không dùng LLM.
Acceptance002 đối chiếu 35 ID bị chặn của008 với đủ120 READY ở scan013. Nếu một
bước lỗi thì dừng, không tạo summary INPUTS_READY. Các đường dẫn dưới đây là kế
hoạch chạy tự động, chưa phải chứng nhận đã PASS:

- `results/diagnostics/b9_full_pipeline_readiness_011_recovery`
- `results/diagnostics/b9_full_pipeline_readiness_012_final`
- `results/diagnostics/b9_full_pipeline_readiness_013_final`
- `results/diagnostics/b9_unblock_acceptance_002/summary.json`

### Điều phối phục hồi ngoài cache và checkpoint 06:16Z

Lượt010 hiện **116 READY/4 BLOCKED**. Cả NiFi, Payara, Flink và Camel đã đạt.
AWS extraction ở heap12288 MiB đã hoàn tất; archive tạm có109920 file Java ứng
dụng, đang finalize. Chưa dùng số file tạm để chứng nhận READY.

Khi chỉ còn AWS, một worker phục hồi Keycloak ngoài cache đang khóa. Ba DB riêng
đủ cho bốn side bị ảnh hưởng: hai vulnerable có cùng SHA và cùng toolchain nên
reuse được. `b9_keycloak_recovery_pilot_002.py` dùng helper production, kiểm tra
revision/coverage/model SHA; checkpoint hiện2/3 DB PASS. Pilot001 bị chủ động
ngắt để thay điều phối; DB đầu đã PASS được002 reuse sau recheck checksum.

Điều phối hiện dùng cổng chờ trạng thái, thay cho việc dừng process finalizer.
Pilot002 chỉ cài DB sau khi launcher010 **và final scan010** kết thúc, dưới khóa
cache. `b9_finish_inputs_002.py` chờ pilot cài xong rồi mới recovery/full scan,
promotion và benchmark dry-run. Window `finish-inputs` cũ đã dừng có kiểm soát;
window đang dùng là `finish-inputs-002`, cạnh `recovery-pilot-002`.

Acceptance hiện chuyển sang `results/diagnostics/b9_unblock_acceptance_003`;
full scan sau promotion vẫn là `_013_final`. Các output002 là lịch sử điều phối,
không phải kết quả cuối. Vẫn0 API LLM; chưa có full end-to-end rerun.

### Kết quả cuối: 35/35 unblock, 120/120 input READY

AWS fixed đã hoàn tất extraction/finalize ở 12288 MiB, coverage 109920/109920.
Ba DB phục hồi Keycloak PASS và được cài dưới khóa cache. Lượt 011 có 120 READY
nhưng scan 012 chỉ 118: DSpace và một Keycloak phụ thuộc pool trong RAM, chưa lưu
đường dẫn peer. Đã sửa readiness để persist alias chỉ cho cache thiếu/không đạt,
đồng thời giữ nguyên DB vật lý còn hợp lệ để worker khác có thể đọc an toàn.
Kiểm thử mới chứng minh repair reuse mà không extraction, giữ DB cũ bị loại và
quét lại bằng process mới vẫn 120 PASS. 240 tests PASS; Ruff/mypy 126 files PASS.

Lượt 014 repair và 014_final đều PASS 120/120. Promotion001 kiểm tra lại từng DB
dưới khóa, cập nhật 73 đường dẫn vulnerable vào cache mà analyzer sẽ đọc; không
sửa nội dung database hoặc đưa report evaluator vào prompt. Scan015 sau promotion
tiếp tục PASS 120/120, 0 BLOCKED, 0 PENDING. Preflight entry point B9 PASS 120 cases,
96 development + 24 diagnostic, request interval 90 giây, 0 API LLM.

Acceptance004 đối chiếu toàn bộ 120 ID với 008_final, xác nhận 35 case từng BLOCKED
đều READY và kiểm tra lại archive/metadata/model SHA cho 240 side. Snapshot mã đã
kiểm thử ở `results/diagnostics/b9_unblock_implementation_004`. Output011/012 và
acceptance003 là lịch sử phát hiện lỗi cache, không phải certificate cuối.
Không hạ threshold 1.0, không sửa ZIP/TRAP/source thủ công, không đổi marker cũ
thành PASS. Chưa chạy full query validation hoặc benchmark end-to-end mới.

```bash
MAXVERA_DATA_ROLE=evaluator uv run --frozen python -m scripts.tools.promote_b9_readiness_inputs \
  --readiness results/diagnostics/b9_full_pipeline_readiness_010_final \
  --output results/diagnostics/b9_readiness_promotion_001
```
