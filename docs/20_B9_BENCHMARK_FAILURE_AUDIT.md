# Audit B9 full120 — 2026-10-12

Lượt chạy `b9_benchmark_120_v2_003` hoàn tất end-to-end, nhưng chưa chứng minh lợi ích
phát hiện của B9: 24/120 case trùng phương thức vá trước kiểm chứng, 1/120 sau kiểm chứng,
97 case phân tích thành công và 23 case lỗi. Audit đã truy nguyên 17 case development
được detected trước kiểm chứng, phân loại đủ 23 case lỗi và đối chiếu đặc tả với truy vấn.
Điểm cần xử lý nằm ở cả discovery, khả năng biểu đạt của đặc tả và verifier.

## Phạm vi và bằng chứng

- Run gốc giữ nguyên; không thay config, ngân sách, nhãn, split, mã verifier hay kết quả.
- Audit offline ở vai trò evaluator; 0 API call, 0 truy vấn CodeQL mới.
- Chỉ 17 case development được đọc sâu đường đi và diff từ source archive đã phân tích.
  Ba case lỗi thuộc test24 chỉ được kiểm kê lỗi vận hành; không dùng để thiết kế sửa đổi.
- Test24 vốn có disposition diagnostic; audit không tạo holdout mới.
- Tái dựng toàn bộ 120 hàng metrics cho cả `vulnerable_paths` và
  `differential_verified`: cả 240 hàng khớp evaluator gốc, gồm deduplication và mẫu số.
- Manifest audit pin SHA256 đầu vào và kiểm tra lại sau khi đọc; các source archive,
  manifest, kết quả và code được tham chiếu không thay đổi trong audit.

Artifact chính:

- [Summary](../results/diagnostics/b9_benchmark_120_v2_003_audit_005/summary.json)
- [17 case development CSV](../results/diagnostics/b9_benchmark_120_v2_003_audit_005/development_cases.csv)
- [62 đặc tả liên quan](../results/diagnostics/b9_benchmark_120_v2_003_audit_005/development_spec_evidence.jsonl)
- [23 case lỗi CSV](../results/diagnostics/b9_benchmark_120_v2_003_audit_005/analysis_failures.csv)
- [Counterfactual mapping](../results/diagnostics/b9_benchmark_120_v2_003_audit_005/mapping_diagnostics.jsonl)
- [Manifest và SHA256 đầu vào](../results/diagnostics/b9_benchmark_120_v2_003_audit_005/manifest.json)

Mỗi thư mục `development/<project_id>/evidence.md` chứa diff đầy đủ của các file
được annotation và descriptor/mapping của đặc tả liên quan. Diff là giữa hai snapshot
thực sự được phân tích; có thể chứa thay đổi ngoài security patch. File không có trong
source archive được ghi rõ `SOURCE_DIFF_UNAVAILABLE`, không đoán nội dung.

## 17 case development mất ở đâu?

Các đường đi trùng phương thức vá đến từ **62 đặc tả**: 46 có trạng thái
`UNVERIFIED_PERSISTS_FIXED`, 16 có `UNVERIFIED_FIXED_ENDPOINT_MAPPING`. Đây là số đặc tả,
không phải số case hay số đường đi đã deduplicate. Theo case: 10 chỉ persistence,
2 chỉ mapping, 5 có cả hai. Không case development nào vượt differential verification.

Trong bảng, P/M là số đặc tả có đường đi trùng phương thức vá bị chặn bởi persistence/mapping.
Cột cuối mô tả bằng chứng hoặc việc cần kiểm tra, không khẳng định exploitability.

| CVE / repository | P | M | Kết quả audit |
|---|---:|---:|---|
| CVE-2018-17297 / hutool | 6 | 0 | Diff thêm `checkSlip` và kiểm tra canonical path; flow vẫn tồn tại. Cần kiểm tra guard theo nhánh và các đường đi qua helper. |
| CVE-2018-11762 / tika | 1 | 0 | Diff normalize/basename tên file; đặc tả liên quan đi từ socket input đến `Files.newInputStream`. Cần đối chiếu đúng luồng khai thác thay vì chỉ overlap phương thức. |
| CVE-2019-0207 / tapestry-5 | 10 | 0 | Vá chuyển backslash thành slash; thao tác này vẫn truyền dữ liệu. Nhiều source là System property/env. Taint persistence không đủ phân biệt điều kiện traversal đã được sửa. |
| CVE-2020-5410 / spring-cloud-config | 7 | 2 | Diff thêm `PathUtils.checkResource`; hai mapping sink `svnPath` bị lặp ngữ nghĩa. Cần kiểm tra guard và vị trí sink thực sự liên quan đến patch. |
| CVE-2020-5405 / spring-cloud-config | 2 | 2 | Các flow còn tồn tại và hai sink `svnPath` lặp ngữ nghĩa. Diff snapshot có nhiều thay đổi ngoài patch; cần thu hẹp đường đi liên quan. |
| CVE-2018-1002202 / zip4j | 3 | 0 | Diff thêm canonical-path containment và throw trước giải nén; cần mô hình hóa điều kiện an toàn trên đường đi liên quan. |
| CVE-2011-4367 / myfaces | 0 | 5 | Toàn bộ đặc tả tạo overlap bị chặn do lặp biểu thức `getResource` trong cùng callable; diff có thêm validation tên resource/library. |
| CVE-2018-1002201 / zt-zip | 0 | 4 | Mapping chặn các `getName`/`isDirectory` lặp; diff thêm containment/throw. Sửa mapping chưa đồng nghĩa sẽ vượt verifier. |
| CVE-2022-31194 / DSpace | 2 | 1 | Diff thêm canonical-path containment; một source `FileItem#getName` bị lặp ngữ nghĩa. Có hai nhóm nguyên nhân độc lập. |
| CVE-2022-4065 / testng | 1 | 1 | Diff thay helper copy bằng kiểm tra normalized path và `Files.copy`; một endpoint cũ không còn ứng viên. Không được tự coi endpoint mất là đã verified. |
| CVE-2022-32287 / uima-uimaj | 2 | 0 | Diff có canonical-path handling và nhiều thay đổi khác; cần kiểm tra guard trên đúng đường đi còn tồn tại. |
| CVE-2023-35887 / mina-sshd | 2 | 0 | Diff liên quan rooted filesystem và safe relative symlink; đây là điều kiện filesystem, không chỉ có/không taint. Cần review từng flow. |
| CVE-2022-4244 / plexus-utils | 2 | 0 | Diff thêm containment/throw trong `extractFile`; flow vẫn tới thao tác filesystem. Cần kiểm tra guard-sensitive modeling. |
| CVE-2019-10078 / jspwiki | 1 | 0 | Nhãn CWE-79, nhưng đặc tả tạo overlap là CWE-22; patch escape HTML bằng `TextUtil.replaceEntities`. Chỉ chứng minh overlap vị trí. |
| CVE-2022-4137 / keycloak | 2 | 0 | Nhãn CWE-79, đặc tả tạo overlap là CWE-22 đến `File#isDirectory`; patch liên quan decode/sanitize HTML. Chưa chứng minh phát hiện XSS. |
| CVE-2022-46907 / jspwiki | 4 | 1 | Nhãn CWE-79, đặc tả tạo overlap đều CWE-22; patch escape form fields. Một sink lặp ngữ nghĩa bị chặn mapping. |
| CVE-2022-44262 / ff4j | 1 | 0 | Nhãn CWE-94, đặc tả tạo overlap CWE-22; patch thêm kiểm tra type trước reflective construction. Chưa chứng minh phát hiện code injection. |

**Cả 62 đặc tả tạo overlap đều thuộc CWE-22.** Vì evaluator chính thức đo overlap
phương thức và không yêu cầu candidate CWE khớp nhãn, 4/17 case vẫn được counted
detected dù các đặc tả liên quan khác CWE. Đây là giới hạn của location proxy;
không sửa âm thầm công thức hay số 24/120 đã công bố. Có 13/17 case development có
ít nhất một đặc tả tạo overlap đúng CWE; con số này chỉ là kiểm tra consistency bổ sung,
không phải số lỗ hổng đã được xác nhận.

## Mapping: chính sách bảo thủ đang bỏ qua một số bằng chứng vị trí

16 đặc tả mapping-failed tạo overlap có 18 lần endpoint chưa resolve: 17 lần có
2 hoặc 3 ứng viên tương đương ngữ nghĩa, 1 lần không có ứng viên. Đếm theo lần sử dụng
endpoint trong đặc tả; có endpoint được sử dụng ở nhiều đặc tả.

Counterfactual offline giữ nguyên callable, expression, fingerprint, role/model,
file và kiểm tra toàn bộ span trong block mã không đổi: **17/18 lần có đúng một
ứng viên khớp span**. Tuy vậy, `map_endpoint` yêu cầu duy nhất trên toàn bộ pool
same-path, nên vẫn từ chối nếu có biểu thức tương tự ở nơi khác trong callable.
Hành vi này được test hiện tại khóa rõ ràng; đây là chính sách cần nghiên cứu lại,
không phải một lỗi cú pháp có thể sửa mà giữ nguyên semantics của run.

Counterfactual chưa thực thi fixed-side queries và **không thay verdict**. Không
được cộng 16 đặc tả hoặc 2 case mapping-only vào detected. Một mapping mới phải
có chứng cứ ngữ cảnh đủ mạnh để phân biệt occurrence lặp, rồi resolve lại bằng
CodeQL trên bản vá. Endpoint bị xóa/thay thế vẫn phải giữ trạng thái chưa kiểm chứng
trừ khi có cơ chế riêng chứng minh tương đương hoặc loại bỏ hành vi nguy hiểm.

## 23 case lỗi: 20 development, 3 test diagnostic

| Nguyên nhân đầu tiên quan sát được | Development | Test diagnostic | Tổng |
|---|---:|---:|---:|
| Có source và sink nhưng không có candidate relation trong discovery | 11 | 2 | 13 |
| Không có modeled endpoint | 2 | 0 | 2 |
| Có sink nhưng không có modeled source | 2 | 1 | 3 |
| Có source nhưng không có modeled sink | 2 | 0 | 2 |
| Truy vấn flow Phase 6 timeout 1800 giây | 2 | 0 | 2 |
| Phản hồi API không parse được, bị đánh dấu fatal | 1 | 0 | 1 |
| **Tổng** | **20** | **3** | **23** |

20 case không có hypothesis đều có 0 dòng discovery relation; chưa có bằng chứng
chúng bị mất do JSON/schema LLM hoặc pruning ở Phase 10. Trong hai case timeout,
typed endpoint inventory không được lưu hoàn chỉnh; các cột count là null/unknown,
không diễn giải là repository không có endpoint.

Hai timeout đều ở `org.hl7.fhir.core` (CVE-2023-24057, CVE-2023-28465).
CVE-2022-25842 / `one-java-agent` có một `JSONDecodeError` sau các retry HTTP429,
bị provider client phân loại không retryable. Một hypothesis lỗi khiến toàn case
`ANALYSIS_FAILED`; chín đặc tả đã sinh bị Phase 11 giữ ở
`UNVERIFIED_UPSTREAM_ANALYSIS_FAILURE`. Không phải chín truy vấn đã chạy và thất bại.

Các case zero-endpoint có nguyên nhân coverage khác nhau:

- **spring-framework/CVE-2022-22965:** archive database chỉ chứa 3 file Java, đều
  nằm trong `buildSrc`; file ứng dụng được annotation không có trong archive. Đây
  là bằng chứng extraction chỉ bắt build helpers. Database được đánh dấu build
  thành công chưa bảo đảm application coverage; cần sửa gate nhận database và
  cách build/extract project này.
- retrofit/CVE-2018-1000850 có 219 file Java trong archive; một trong hai file
  annotation có mặt. Vì có mã ứng dụng, chưa thể quy zero-endpoint cho cùng lỗi
  buildSrc; cần review model/coverage chi tiết.
- Hai case HL7 timeout có 7496/7514 file Java; các file được annotation đều có
  trong archive. Lỗi quan sát được là flow-query evaluation vượt 1800 giây.

Source coverage chỉ đếm file archive, không chứng minh mỗi callable trong file đã
được extract đầy đủ. Có endpoint mà không có relation cũng chỉ xác định điểm mất
tại discovery; chưa chứng minh repository không có luồng nguy hiểm.

## Phần LLM/đồ thị hiện có ảnh hưởng gì đến truy vấn?

Đối chiếu từng `hypothesis_id` với Phase 6:

- **892/892 đặc tả giữ nguyên tập source/sink đã freeze từ hypothesis Phase 6.**
  Một số output có nhiều alias, nhưng sau binding vẫn là cùng physical endpoints.
- **0/892** có sanitizer hoặc propagator do LLM chọn. Metadata của các plan API-eligible
  cũng không cho phép chọn endpoint thuộc hai vai trò này.
- `bindings`/`path_query` dùng frozen sources, sinks, candidate CWE và
  `v2Barrier` từ CodeQL; preconditions được lưu trong JSON nhưng không được biên dịch
  thành điều kiện trong truy vấn.
- Discovery giới hạn trước vào các model source/sink và relation đã định nghĩa trong
  `Grounding.qll`, rồi top-k. Các case không có hypothesis bị loại trước khi LLM chạy.

Vì vậy, lượt chạy này chưa cho thấy LLM/USEG mở rộng các endpoint dùng để phát hiện,
hoặc bổ sung guard đặc thù repository vào truy vấn. Có thể ảnh hưởng tới biểu diễn
và metadata, nhưng cần ablation cùng điều kiện để đo lợi ích. Chưa thể quy toàn bộ
thất bại cho model GPT-OSS20B, API limit, hay riêng pruning.

Các diff thêm kiểm tra path, encoding hoặc type cho thấy cần audit semantics của
verifier. Chúng **không tự chứng minh** rằng mọi flow `PERSISTS_FIXED` là false positive
hoặc rằng bỏ bước kiểm chứng sẽ cải thiện chất lượng.

## Kế hoạch sửa và pilot tiếp theo

| Ưu tiên | Công việc cụ thể | Tiêu chí kiểm tra trước khi chạy full |
|---|---|---|
| P0 | Thêm gate application coverage khi nhận database; sửa build/extraction Spring4Shell đang chỉ chứa buildSrc. Gate analyzer dùng population/source manifest hoặc mã ứng dụng, không dùng file annotation của evaluator. | Database chỉ có build helpers bị từ chối dù command exit0; bản build mới thực sự extract mã ứng dụng. Evaluator kiểm tra riêng coverage file annotation và provenance. |
| P0 | Sửa phân loại phản hồi transport JSON lỗi thành retry hữu hạn khi có bằng chứng response hỏng; giữ request/budget/checkpoint, tránh retry lỗi config/auth. | Response JSON hỏng phục hồi được; retry vẫn bị chặn bởi giới hạn stage/call/token; HTTP401/403 không retry. Dùng case one-java-agent ở development để pilot. |
| P0 | Ghi nhận lỗi theo hypothesis/spec, tách partial synthesis và project coverage để chín spec hợp lệ không bị mất âm thầm khi một hypothesis lỗi. | Trạng thái thiếu vẫn được báo; metric không đổi mẫu số; không tính spec chưa kiểm chứng thành verified. Semantics mới cần config/run mới. |
| P1 | Thiết kế mapping dùng unchanged block + toàn span + context/occurrence proof; giữ nguyên kiểm tra semantic fingerprint, role/model và fixed-side resolution. | Phân biệt được biểu thức lặp có bằng chứng duy nhất; trường hợp lặp không đủ chứng cứ, đổi slot/symbol, rename không rõ và endpoint mất vẫn chưa verified. Pilot myfaces/zt-zip; không suy ra detected từ mapping counterfactual. |
| P1 | Đối chiếu và mô hình hóa guard/sanitizer trên mã bản lỗi, có grounding; evaluator dùng diff bản vá để kiểm chứng hiệu lực. | Guard trên đúng branch và đúng biến mới được áp dụng; guard không liên quan không cắt flow. Pilot hutool/zip4j/tapestry với cả control dương và âm, chưa dùng test24. |
| P1 | Kiểm tra build/extractor coverage và khoảng trống source/sink/relation trong development. | Tách rõ DB thiếu mã với model miss. Dùng retrofit/spring-framework cho zero-endpoint, CureKit/json-sanitizer cho thiếu một vai trò và vertx-web cho relation miss. Không đưa CVE/CWE thật vào analyzer. |
| P1 | Profile hai truy vấn HL7 timeout; thử phân rã relation theo batch/family hoặc tối ưu join trước khi tăng timeout toàn tập. | Lưu query plan/log và kết quả so với truy vấn chuẩn; không thay đổi tập relation khi tối ưu, có timeout/resource cap rõ ràng. |
| P2 | Tạo ablation từ cùng hypothesis/context/budget: trực tiếp từ Phase 6, B6/B7/B8 và B9; mở rộng vai trò LLM chỉ với endpoint có grounding. | Đo thay đổi endpoint/guard có hiệu lực trong query, detected và chi phí. Đặc tả khác nhau nhưng truy vấn tương đương phải được nhận diện. |
| P2 | Giữ metric paper-proxy gốc; bổ sung riêng consistency CWE, manual adjudication và coverage theo lỗi. | Báo cả raw/differential/routed; giữ all120 và 96/24, không đổi annotation hoặc công thức để tăng detected. |
| P3 | Fit calibration sau khi có đủ verified records đa lớp và repository groups trên development. | Giữ điều kiện eligibility; ACCEPT tiếp tục tắt khi chưa đủ dữ liệu, không hạ ngưỡng để tạo số đẹp. |

Mỗi thay đổi semantic cần phiên bản/config/run mới. Pilot vận hành không được dùng
nhãn hay patch làm hint cho analyzer. Thành công của pilot là điều kiện correctness
và coverage, không phải yêu cầu các case đã xem phải trở thành true positive.
Chỉ chạy full lại sau khi đã có bằng chứng từ các pilot độc lập và ngân sách được ghi nhận.
Audit lịch sử hoàn tất. Các sửa đổi vận hành và gate cho lượt chạy mới đang được
thực hiện, ghi riêng trong [pipeline completeness](21_B9_PIPELINE_COMPLETENESS.md).
Mapping/guard/ablation ở bảng này vẫn là công việc nghiên cứu chưa được thực hiện;
không thay verdict hay metric của run gốc.

## Tái lập audit

Chọn output mới vì audit không overwrite:

```bash
MAXVERA_DATA_ROLE=evaluator uv run --frozen python -m src.experiments.b9_failure_audit \
  --run-root results/pipeline_v2/benchmark/b9_benchmark_120_v2_003 \
  --output results/diagnostics/b9_benchmark_120_v2_003_audit_NEW
```

Các lượt audit `_001`–`_004` là extraction/counterfactual/coverage trung gian; `_005`
là bản đầy đủ được tham chiếu ở tài liệu này. Tất cả tách khỏi run benchmark gốc.

Validation: Ruff và mypy cho công cụ audit PASS; 46 unit tests liên quan đến evaluator,
grounding và verifier PASS. Validator độc lập của benchmark vẫn trả
`PASS_WITH_ANALYSIS_FAILURES`; các số liệu gốc không thay đổi.
