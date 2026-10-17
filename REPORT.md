# Báo cáo tổng hợp MaxVera / B9 — ngày 17/10/2026

**Ngày lập báo cáo: 17/10/2026 (17/10).**

**Lượt chạy chính:** `b9_benchmark_120_complete_001`.
**Phạm vi:** tổng hợp kết quả, vấn đề, nguyên nhân, khó khăn và hướng xử lý sau
benchmark 120 case; gồm 96 development và 24 test dùng cho chẩn đoán.
**Trạng thái:** benchmark đã hoàn tất vận hành; chưa chứng minh được hiệu quả
của phương pháp B9 hoặc khả năng tổng quát trên holdout mới.

## Nhận định chính

Kết luận: implementation hiện tại có vấn đề ở cơ chế phát hiện và kiểm chứng,
không chỉ ở vận hành. Kết quả chưa bác bỏ ý tưởng phối hợp LLM, đồ thị và static
analysis nói chung, nhưng chưa cung cấp bằng chứng cho lợi ích của kiến trúc B9.
Ưu tiên tiếp theo nên là pilot kiểm tra từng cơ chế và baseline cùng điều kiện;
chưa nên chạy lại full120 với cùng semantics hoặc chỉ đổi model lớn hơn.

Phạm vi: đọc đúng run `b9_benchmark_120_complete_001`, tái dựng metrics offline,
đối chiếu source hiện tại được audit pin, kiểm tra inventory/flows trước top-k,
so sánh query sinh từ đặc tả LLM với query trực tiếp từ Phase 6. Không có API call
hay CodeQL query mới. Benchmark, cấu hình và mã pipeline giữ nguyên.

Nguồn định lượng:

- [Audit độc lập mới](results/diagnostics/b9_benchmark_120_complete_001_audit_001/summary.json),
  có checksum đầu vào và diff của 17 development case.
- [Phân tích bổ sung](results/diagnostics/b9_benchmark_120_complete_001_analysis_001/summary.json), [script tái lập](results/diagnostics/b9_benchmark_120_complete_001_analysis_001/recompute.py),
  [checksum đầu vào](results/diagnostics/b9_benchmark_120_complete_001_analysis_001/inputs_sha256.json), [20 case không có hypothesis](results/diagnostics/b9_benchmark_120_complete_001_analysis_001/empty_cases.json).
- [Metrics gốc](results/pipeline_v2/benchmark_evaluation/b9_benchmark_120_complete_001_evaluate/metrics_paper_proxy.json).
- [Verification](results/verification/v3/b9_benchmark_120_complete_001_verify/summary.json).
- [Calibration eligibility](results/calibration/v2/b9_benchmark_120_complete_001_route/eligibility.json).

## 1. Kết quả thực nghiệm

Cấu hình chính: zero-hint, GPT-OSS20B, CodeQL 2.26.2, Java pack 9.2.2,
Top-k=10. Calibration chỉ fit trên development. Test24 đã được dùng cho phân
tích chẩn đoán, không còn là bằng chứng confirmatory độc lập.

Nguồn: [báo cáo benchmark gốc](results/pipeline_v2/benchmark/b9_benchmark_120_complete_001/report.md)
và [cấu hình lượt chạy](configs/experiments/b9_benchmark_120_complete.yaml).

### 1.1. Chất lượng đầu ra

| Đầu ra | Phạm vi | Detected/cases | Avg FDR | Avg F1 |
|---|---|---:|---:|---:|
| Vulnerable paths | all120 | 24/120 | 0,8903 | 0,1065 |
| Vulnerable paths | development96 | 17/96 | 0,9063 | 0,0911 |
| Vulnerable paths | test24 diagnostic | 7/24 | 0,8354 | 0,1682 |
| Differential verified | all120 | 1/120 | 0,5000 | 0,0083 |
| Differential verified | development96 | 0/96 | 1,0000 | 0,0000 |
| Differential verified | test24 diagnostic | 1/24 | 0,0000 | 0,0417 |
| Routed VERIFY hoặc ACCEPT | all120 | 1/120 | 0,5000 | 0,0083 |
| ACCEPT only | all120 | 0/120 | Không có paths | 0,0000 |

Các dòng routed giống differential ở cả ba phạm vi. ACCEPT không có output ở
cả ba phạm vi. AvgFDR của differential all120 chỉ dựa trên **hai case có paths**;
không nên diễn giải 0,5000 là bằng chứng cải thiện precision đáng tin cậy.

### 1.2. Độ hoàn tất và khối lượng xử lý

Run mới: 120/120 analysis SUCCESS, 0 analysis failures, 913 hypotheses/specifications,
916 LLM call records trong synthesis summary, 1.703 verification query invocations.
20 case SUCCESS không có hypothesis; empty discovery được coi là hoàn thành hợp lệ.

| Bước | Kết quả |
|---|---:|
| Có ít nhất một hypothesis | 100/120 case |
| Có vulnerable paths | 93/120 case |
| Tổng đường đi đã deduplicate | 1.842 |
| Đường đi overlap phương thức vá | 223 |
| Raw detected | 24/120 case |
| Differential verified | 2 đặc tả thuộc 2 case |
| Differential detected theo patch overlap | 1/120 case |
| ACCEPT | 0 |

So với run003, analysis failures giảm 23 xuống 0; raw detected vẫn 24 và
differential detected vẫn 1. Tập detected không hoàn toàn giống nhau: thêm
CVE-2023-28465 (HL7), mất CVE-2022-44262 (ff4j). Các số này không chứng minh sửa
coverage vô ích; chúng cho thấy độ phủ vận hành chưa đủ để cải thiện tổng detected.

## 2. Discovery đóng mất phần lớn cơ hội trước khi LLM chạy

| CWE thật của case | Số case | Có modeled sink đúng CWE | Có relation đúng CWE trước top-k | Có hypothesis đúng CWE sau top-k | Raw overlap |
|---|---:|---:|---:|---:|---:|
| CWE-22 | 55 | 54 | 51 | 51 | 20 |
| CWE-78 | 13 | 6 | 3 | 3 | 0 |
| CWE-79 | 31 | 0 | 0 | 0 | 3 |
| CWE-94 | 21 | 9 | 2 | 2 | 1 |

Đây là thống kê evaluator sau chạy, không đưa CWE thật vào analyzer. Raw overlap
không yêu cầu đúng CWE, nên ba case XSS overlap không phải bằng chứng phát hiện XSS.
Không có modeled sink trong inventory không đồng nghĩa source repository không có
sink thật: có thể thiếu model, loại node không được hỗ trợ, hoặc thiếu semantic
extraction. File archive đủ không chứng minh đầy đủ mọi semantic node.

913 hypothesis phân bố: 714 CWE-22, 146 CWE-78, 16 CWE-79, 37 CWE-94.
16 hypothesis XSS tồn tại ở các case có nhãn CVE thuộc CWE khác; cả 31 case XSS
không có hypothesis XSS. 20 case rỗng gồm 12 không có relation, 2 không endpoint,
4 không source, 2 không sink.

`Grounding.qll` chỉ lấy một tập source/sink có sẵn, rồi ràng buộc relation.
Đặc biệt, `v2Sink` dùng external `sinkNode` cho XSS, trong khi thư viện CodeQL
Java 9.2.2 `XSS.qll` còn có logic nhận biết output writer theo flow qua
`XssVulnerableWriterSourceToWritingMethodFlow`. Đây là khoảng thiếu cụ thể của
adapter so với query chuẩn, chưa phải bằng chứng rằng thêm nó sẽ cứu được 31 case.

Ở cấp có/không hypothesis đúng CWE, số trước/sau top-k giống nhau. Tăng k không
giải quyết được các family đang mất từ inventory/relation. Tuy nhiên top-k vẫn
có thể bỏ đúng endpoint pair trong một family; chưa đo được pair-level recall.
Ranking hiện dùng điểm 0,9/0,7/0,6 theo loại relation, trừ điểm non-application,
rồi tie-break bằng hypothesis ID. Đây không phải ranking theo exploitability.

## 3. LLM chưa thay đổi query phát hiện

Audit mới xác nhận:

- 913/913 specs giữ nguyên physical endpoint pair Phase 6.
- Không spec nào có sanitizer hay propagator do LLM chọn.
- `path_query` dùng endpoint, candidate CWE và `v2Barrier`; không đọc preconditions.
- Dựng spec trực tiếp từ Phase 6, giữ ID để loại khác biệt tên/comment, tạo ra
  query text giống hệt query từ spec LLM ở **913/913 trường hợp**.

Đây là kiểm tra tương đương query offline, chưa phải một ablation runtime mới.
Tuy vậy, nó xác lập rõ rằng với các spec được giữ ở run này, phần synthesis
không bổ sung logic phát hiện. LLM có thể thay đổi diễn giải/metadata nhưng chưa
thay đổi predicate source, sink, guard hoặc propagation. Không thể lấy số layer
đồ thị, số spec hay việc JSON hợp lệ làm bằng chứng đóng góp khoa học.

Điểm khác với IRIS: IRIS cho LLM suy ra source/sink cho candidate APIs rồi
thêm chúng vào static analysis. B9 hiện giới hạn lựa chọn vào endpoint đã được
model hóa trước. Nguồn: [IRIS, mục 3.2–3.4](https://arxiv.org/html/2405.17238v3#S3.SS2).

## 4. Differential verifier vừa quá hẹp vừa chưa đủ để chứng minh đúng lỗ hổng

| Verdict | Số specs | Tỷ lệ |
|---|---:|---:|
| PERSISTS_FIXED | 509 | 55,75% |
| FIXED_ENDPOINT_MAPPING | 246 | 26,94% |
| NO_VULNERABLE_PATH | 156 | 17,09% |
| VERIFIED_DIFFERENTIAL | 2 | 0,22% |

Trong 17 development case raw-detected, 68 specs tạo overlap: 44 persistence,
24 mapping. Theo case: 8 chỉ persistence, 3 chỉ mapping, 6 cả hai. Không case
development nào còn detected sau verifier.

Verifier yêu cầu có path ở vulnerable, mapping/resolve đầy đủ, rồi fixed có
zero path. Nhưng bản vá thường thêm điều kiện chặn input nguy hiểm trong khi
vẫn giữ việc truyền dữ liệu hợp lệ. Query hiện dùng external barrier models;
không dùng đầy đủ `PathInjectionSanitizer`/guard semantics của query chuẩn.
CodeQL 9.2.2 `PathSanitizer.qll` có `BarrierGuard` cho prefix/normalization và
những phép kiểm tra liên quan; B9 không kết nối lớp này vào `v2Barrier`.

Diff hutool và zip4j ở audit mới có canonical-path/containment checks. Điều này
ủng hộ việc kiểm tra guard modeling, nhưng **không đủ để kết luận cả 509 specs
là true positive bị verifier loại nhầm**. Có specs sai threat model hoặc chỉ
vô tình đi qua phương thức vá. Ví dụ một path zip4j bắt đầu ở `System.getProperty`
và kết thúc ở `File.exists`; nó không tự chứng minh luồng khai thác Zip Slip.

Mapping bảo thủ từ chối lặp expression trong cùng callable ngay cả khi có một
vị trí unchanged hợp lý. Với 26 unresolved endpoint occurrences của các specs
overlap development, 18 có một ứng viên khớp toàn span unchanged trong kiểm tra
counterfactual. Không cộng 18 vào số detected: chưa chạy fixed-side query cho
mapping thay thế, các trường hợp ấy vẫn có thể persistence hoặc false positive.

Chiều ngược lại, mất path trên fixed cũng không đủ chứng minh phát hiện đúng CVE:
run có 2 differential specs nhưng chỉ 1 case overlap đúng phương thức vá.

Ở cấp thiết kế, yêu cầu fixed revision để có finding cuối giới hạn hệ thống khi
đi tìm lỗi chưa biết: khi đó chưa có bản vá. Nên tách findings trên một snapshot
khỏi chứng cứ differential dùng cho đánh giá hồi cứu. Đây là thay đổi protocol,
không phải đổi tên metric hiện tại hay coi mọi path là vulnerability.

## 5. Đọc đúng metrics và calibration

AvgFDR 0,8903 là macro trung bình trên **93 case có paths**, theo proxy overlap
phương thức vá; không phải đánh giá thủ công rằng 89% cảnh báo là sai. 8/120 case
không có method annotation hợp lệ nên không thể detected theo scorer này. Ngay
cả khi chỉ xét 112 case có annotation, raw detected là 24/112, chưa giải thích
được phần lớn khoảng thiếu.

Ba trong 17 development case overlap không có spec overlap đúng CWE. Vì thế
24/120 cũng chưa đồng nghĩa xác nhận 24 CVE. Không sửa âm thầm công thức gốc.

Calibration development có đúng 1 verified record, target=0 và chỉ 1 repository
group. Điều kiện train đa lớp không đạt; ACCEPT tắt là hành vi phù hợp. Routing
chỉ lặp lại verifier ở run này. Hơn nữa target hiện là candidate-CWE correctness,
không phải correctness của vulnerability finding; ngay cả đủ dữ liệu cũng không
được diễn giải xác suất này thành precision/FDR lỗ hổng.

Raw B9 24/120, FDR 0,8903, F1 0,1065 so với published CodeQL 27/120, 0,9003,
0,0760 không cho thấy B9 thua trên mọi cột. Nhưng không phải controlled comparison:
snapshots/toolchain/model/hints khác. Alignment ghi 10 buggy commit refs và 5 fix
refs khác reproduction. IRIS có CWE được cung cấp, còn B9 phải tự tìm family.
Không so 1 differential-detected với 55 IRIS-detected như hai đầu ra cùng tiêu chuẩn.

## 6. Khó khăn và giới hạn còn tồn tại

| Nhóm | Khó khăn cụ thể | Tác động và cách xử lý cần kiểm chứng |
|---|---|---|
| Dữ liệu và extraction | Đủ file Java trong archive chưa bảo đảm mọi callable, API model và dataflow node đều được trích xuất đúng. | Kiểm tra semantic coverage theo family; không dùng trạng thái database SUCCESS làm bằng chứng phát hiện đầy đủ. |
| Discovery | Source/sink model còn hẹp; 20 case không có hypothesis, toàn bộ 31 case XSS thiếu sink đúng CWE trong inventory. | Ưu tiên kiểm tra adapter và semantics CodeQL chuẩn, sau đó mới mở rộng model bằng LLM. |
| Ranking | Top-k=10; nhiều candidate cùng điểm, phân hạng cuối bằng ID. | Chưa biết đúng endpoint pair bị mất bao nhiêu; cần đo pair-level recall riêng. |
| Biểu đạt đặc tả | Precondition chưa có hiệu lực trong query, LLM không bổ sung endpoint hoặc guard trong lượt này. | Cần compiler biến phần suy luận có grounding thành logic thực thi và kiểm tra được. |
| Guard và context | Một check chỉ bảo vệ đúng biến, đúng nhánh, đúng quan hệ với sink. | Áp dụng barrier quá rộng có thể che lỗi thật; không áp dụng thì flow trên fixed vẫn tồn tại. Cần control dương/âm. |
| Mapping hai phiên bản | Expression lặp, đổi tên, thay API, xóa endpoint và diff nhiều thay đổi gây ambiguity. | Chứng minh correspondence bằng context/span/semantics; endpoint biến mất không tự động là verified. |
| Đánh giá correctness | Overlap phương thức vá có thể khác CWE hoặc khác luồng khai thác; tám case thiếu method annotation hợp lệ. | Giữ proxy gốc, bổ sung consistency và manual adjudication riêng; không sửa metric để tăng số. |
| Calibration | Chỉ một verified record development, không có lớp dương; target còn là đúng CWE. | Chưa đủ dữ liệu để fit/routing có ý nghĩa; cần target phù hợp trước khi claim confidence của finding. |
| Chi phí và thời gian | Synthesis ghi 916 call records; verification thực hiện 1.703 query invocations; request pacing 90 giây. | Chạy lại full có chi phí đáng kể nhưng chưa tạo bằng chứng mới nếu semantics không đổi; ưu tiên ablation và pilot nhỏ. |
| Tổng quát hóa | Test24 đã dùng cho diagnostic, baseline công bằng cùng điều kiện chưa được thiết lập cho claim B9. | Khóa phương pháp sau development rồi đánh giá trên holdout mới. |

Các khó khăn lịch sử về coverage, timeout và API được ghi ở
[audit lượt cũ](docs/20_B9_BENCHMARK_FAILURE_AUDIT.md) và
[tài liệu hoàn thiện pipeline](docs/21_B9_PIPELINE_COMPLETENESS.md).
Lượt complete_001 có 0 analysis failures; không dùng nguyên nhân lỗi của lượt cũ
để giải thích trực tiếp toàn bộ kết quả hiện tại.

## 7. Đánh giá hướng nghiên cứu

**Hướng kết hợp LLM, đồ thị và static analysis vẫn có cơ sở để thử nghiệm, nhưng
cách kết nối các thành phần trong B9 hiện chưa chứng minh được đóng góp.**
Phần discovery giới hạn tập có thể phát hiện; synthesis chưa đổi query; verifier
đòi hỏi biến mất flow trên fixed; calibration không đủ dữ liệu. Những điểm này
có quan hệ nhân quả: lỗi hoặc giới hạn ở bước đầu không thể được xử lý chỉ bằng
thêm lớp quyết định ở cuối.

Không có bằng chứng hiện tại để kết luận model GPT-OSS20B là nguyên nhân chính,
đổi model lớn sẽ giải quyết vấn đề, bỏ verifier sẽ tạo ra finding đúng, hoặc sửa
mapping chắc chắn tăng detected. Những giả thuyết đó cần thí nghiệm riêng.

Ưu tiên khoa học là chứng minh **một thay đổi LLM/graph tạo thêm năng lực phát hiện
hoặc giảm chi phí có thể đo được** so với baseline trực tiếp. Nếu chưa đạt điều
này, số graph layer hay số đặc tả không đủ làm cơ sở claim novelty/effectiveness.

## 8. Hướng điều chỉnh và thí nghiệm có giá trị tiếp theo

1. Tạo baseline cùng snapshot/database/toolchain/evaluator: query CodeQL chuẩn
   cho đủ bốn family, và Phase6-to-query trực tiếp. Tách chi phí vulnerable scan
   khỏi retrospective fixed verification. Đây là mốc để đo LLM/USEG có thêm gì.
2. Ưu tiên sink/source coverage, đặc biệt XSS và code injection. Tái sử dụng
   semantics query chuẩn và kiểm tra node adapter, rồi mới xét suy luận model mới.
   LLM cần được đề xuất API source/sink/summary có grounding để mở rộng analyzer.
3. Làm compiler cho phần spec thực sự có ảnh hưởng: source/sink model,
   propagation summary, guard có điều kiện. Giữ kiểm chứng symbol/slot/branch;
   không biến một câu precondition thành barrier vô điều kiện.
4. Pilot guard và mapping riêng trên development, có control dương/âm và test
   cho ambiguity/rename/removed endpoint. Dùng patch ở evaluator, không đưa patch
   vào analyzer để tạo câu trả lời. Mục tiêu là semantics đúng, không ép case tăng điểm.
5. Đo ablation: direct P6, thêm mở rộng model bằng LLM, thêm USEG/retrieval,
   thêm guard reasoning. Ghi query nào thực sự đổi, path nào mới, correctness
   qua review, tokens/calls/runtime. Giữ raw, differential và adjudicated metrics riêng.
6. Hoãn calibration đến khi có đủ dữ liệu đúng target. Giữ test24 là diagnostic;
   kết luận tổng quát cần holdout mới sau khi đã khóa phương pháp.

Điều kiện để tiếp tục đầu tư vào kiến trúc đầy đủ: chứng minh ít nhất một cơ chế
LLM/graph tạo khác biệt có ích so với deterministic baseline dưới cùng điều kiện.
Nếu sau các pilot cơ chế riêng vẫn không tạo được cải thiện, nên thu hẹp hướng
sang model inference cho một family hoặc guard verification, thay vì tiếp tục
thêm layer cho hệ thống đa mục tiêu.

### 8.1. Thứ tự ưu tiên và điều kiện qua bước

| Ưu tiên | Công việc | Bằng chứng cần có trước khi mở rộng |
|---|---|---|
| P0 | Baseline CodeQL chuẩn và Phase6 → query trực tiếp cùng điều kiện. | Cùng cohort, snapshot, database, evaluator; phân biệt proxy, failure, runtime và chi phí. |
| P0 | Pilot coverage XSS/code injection và node adapter. | Truy nguyên sink/source bị thiếu; model mới resolve đúng symbol/slot và có control để tránh mở rộng tùy tiện. |
| P1 | Spec có hiệu lực và ablation LLM/USEG. | Query thực sự thay đổi; thay đổi tạo path hoặc lọc path có căn cứ, không chỉ đổi mô tả JSON. |
| P1 | Pilot guard và mapping trên development. | Guard đúng nhánh/biến; mapping xử lý ambiguity đúng; giữ unresolved khi bằng chứng không đủ. |
| P1 | Tách output phát hiện khỏi differential audit. | Hệ thống có thể tạo candidate finding trên một snapshot; không đánh đồng candidate với vulnerability đã xác nhận. |
| P2 | Review correctness, target calibration và holdout mới. | Có dữ liệu đa lớp/nhóm phù hợp, protocol và phương pháp được khóa trước đánh giá mới. |

Đây là đề xuất tiếp theo, **chưa phải các sửa đổi đã được triển khai hoặc kết quả
cải thiện đã được xác nhận**. Chưa có cơ sở khuyến nghị chạy lại full120 chỉ với
model lớn hơn hoặc nới threshold. Thay đổi semantics cần version/config/run mới,
giữ nguyên artifacts và scoring lịch sử.

## 9. Công việc chẩn đoán đã hoàn thành ngày 17/10/2026

- Audit đúng run complete_001 và tái dựng khớp cả 240 dòng raw/verified metrics.
- Kiểm kê discovery theo CWE, inventory, relation và top-k cho toàn bộ 120 case.
- Đọc sâu bằng chứng và diff của 17 development case raw-detected.
- So sánh query trực tiếp từ Phase 6 với query từ 913 đặc tả LLM.
- Lưu summary, bằng chứng case-level, script và checksum đầu vào trong các
  thư mục diagnostics được dẫn ở đầu báo cáo.
- Không gọi API LLM mới, không chạy query CodeQL mới trong audit; không thay
  mã pipeline, cấu hình hay kết quả benchmark gốc.

Tái lập phân tích bổ sung từ repository root:

```bash
PYTHONPATH=. .venv/bin/python results/diagnostics/b9_benchmark_120_complete_001_analysis_001/recompute.py
```
