# Kết quả pilot10 và quyết định GO — 25/10/2026

**NO-GO cho toàn bộ pipeline research/full120 theo tiêu chí acceptance hiện tại.**
Pilot đã chạy thật qua CLI MaxVera, đủ mười case cố định ở mỗi variant. Hai run
đều kết thúc `COMPLETED_WITH_CASE_FAILURES`; evaluate và compare đều exit 0.
Workflow hoàn tất lúc **11:10 ngày 25/10/2026, giờ Việt Nam**, sau khoảng 3 giờ
51 phút. Trạng thái supervisor `COMPLETED` chỉ xác nhận chuỗi lệnh kết thúc;
nó không phải engineering pass hoặc scientific approval.

## Kết quả đo thực tế

| Chỉ tiêu | `static_only` | `graph_only` |
| --- | --- | --- |
| Selected/final case records | 10/10 | 10/10 |
| Case hoàn tất có candidates | 7/10 | 6/10 |
| Build failures | 3 | 3 |
| Analysis failures | 0 | 1 |
| Engineering acceptance | Fail | Fail |
| Truth evaluable | 6/10 | 6/10 |
| Strong discovery Recall@5 trên **subset sáu case** | 2/6 = 33,3% | 1/6 = 16,7% |
| Strong discovery Recall@10, @20 trên subset | 3/6 = 50,0% | 2/6 = 33,3% |
| Recall toàn cohort | `null` | `null` |
| Raw / retained candidates | 634 / 107 | 2.782 / 120 |
| Model calls / usage rows | 0 / 0 | 0 / 0 |

Cả hai evaluation có cùng condition hash
`5e710215d075b6ee7cb325ae3afa7f6a4a686ac7f7c2d8bbe06ea04b41b87473`.
So sánh paired hợp lệ, giữ đủ case lỗi trong denominator. Root đã kiểm lại
checksum toàn bộ hai run, hai evaluation và comparison: **5/5 hợp lệ**.
Implementation hash và receipt của label/truth/tool inputs vẫn khớp lúc chạy.
Không chạy lại benchmark, sửa frozen artifact hoặc loại case trong đợt kiểm này.

Graph không tạo case strong-match Top-5 mới so với static. Case
`proj_10459fcd88fe353fe011` được cả hai phát hiện; các strong matches xuất phát
từ static alerts. Static còn có Top-5 match ở FF4J, nhưng graph fail ở bước dựng
graph của case này. Đây là regression quan sát được trong pilot có case failure;
chưa phải kết luận tổng quát về chất lượng thuật toán xếp hạng.

65 retained candidates ngoài default alerts không chứng minh có phát hiện đúng
mới. Không suy ra precision/FDR từ các candidates chưa được adjudicate. Các graph
discovery reports đã ghi không chạm traversal cap; lỗi FF4J là lỗi định danh node.

## Các blocker có bằng chứng

| Project / case | Blocker trực tiếp |
| --- | --- |
| AntiSamy — `proj_fbcf5031d7f72ba603b6` | Spotless `apply` cần Git repository/ratchet, trong khi workspace được tạo từ archive. |
| Spring Security — `proj_5d26b10d499ec06333c3` | Không resolve được Bundlor `1.0.0.M6`; các options gặp DNS failure hoặc Maven HTTP blocker. |
| NiFi — `proj_3de018c0418e4985f97a` | npm kết thúc với `Exit handler never called!`; các fallback gặp lỗi tương thích Maven/JDK. Nguyên nhân sâu hơn của npm chưa được chứng minh. |
| FF4J — `proj_b1a4d30ba5b93c784823` | `build_graph` báo `ambiguous graph node key`; CSV gán cùng key cho các source locations khác nhau. |

Ba build failures lặp lại ở cả hai variant. FF4J chỉ lỗi trong graph variant,
sau khi static extraction thành công. Báo cáo điều tra có exact log/line và phân
biệt nguyên nhân đã chứng minh với giả thuyết ở
[failure diagnosis](../logs/research_pilot_20261025/failure_diagnosis.md).

## Đối chiếu acceptance và phạm vi được phép kết luận

Theo [pilot acceptance](research_pilot_acceptance_2026-10-24.md):

- Engineering chưa đạt trên toàn selection: static 7/10, graph 6/10.
- Truth chưa đủ: pilot 6/10 aligned, bốn case `GT_UNALIGNED`; whole-cohort recall
  bắt buộc giữ `null`. Case truth hợp lệ nhưng build/analysis lỗi vẫn thuộc
  denominator sáu case và không được loại khỏi phép đo.
- Graph Recall@5 thấp hơn static và không có case strong-match Top-5 mới ngoài
  default alerts. Điều kiện graph signal chưa đạt; approval giữ false.
- Hai variant này tắt LLM và targeted verification. Chưa có actual pilot
  `graph_llm_verify` chứng minh assessment/citation/verification coverage 100%,
  chất lượng sau LLM hoặc same-identity resume của paid pilot.

Nhánh prospective exploratory trong runbook cho phép review kết quả âm rồi đăng
ký protocol riêng; đó là phạm vi thực thi khác, giữ scientific approval false.
Đợt kiểm này không đăng ký protocol, bật approval hoặc launch full120/LLM.

Preflight full120 `graph_only` được chạy lại sau pilot với `--require execution`
và **exit 0**: source/provenance/recipe **120/120 ready**, `execution_ready=true`,
`evaluation_ready=false`, `scientific_approved=false`. Có truth records cho
113/120 case nhưng chỉ **6/120 aligned**. Preflight không build hoặc chạy model
(`network_requests=0`, `tool_invocations=0`), vì vậy kết quả này chỉ xác nhận
đầu vào đủ để chạy static/graph. Nó không chứng minh full120 build thành công,
hoặc full LLM/verification đã đủ điều kiện. Xem
[full120 postpilot preflight](../logs/research_pilot_20261025/full120_postpilot_preflight.json).

Thứ tự công việc cần làm tiếp: xử lý ba build mechanisms và tính nhất quán
key/location graph, kiểm regression tương ứng; đóng băng identity mới và chạy
lại fixed pilot10 như một vòng development mới; giải quyết truth alignment và
review graph signal trước pilot LLM/verification theo tiêu chí đã công bố.
Giữ đủ cohort và mọi failure; không sửa kết quả cũ để làm gate pass.

## Bằng chứng

- [Workflow và exact commands](../logs/research_pilot_20261025/workflow.json).
- [Compact postrun summary](../logs/research_pilot_20261025/postrun_summary.json).
- [Fresh checksum verification](../logs/research_pilot_20261025/postrun_integrity_receipt.json).
- [Independent scientific gate review](../logs/research_pilot_20261025/scientific_gate_review.md).
- [Static run](../results/research/research_pilot10_20261025_static01/quality_report.json),
  [graph run](../results/research/research_pilot10_20261025_graph01/quality_report.json).
- [Static aggregate](../results/evaluations/research_pilot10_20261025_static01/zero_hint_aligned_v1/5e710215d075b6ee7cb325ae3afa7f6a4a686ac7f7c2d8bbe06ea04b41b87473/metrics_aggregate.json),
  [graph aggregate](../results/evaluations/research_pilot10_20261025_graph01/zero_hint_aligned_v1/5e710215d075b6ee7cb325ae3afa7f6a4a686ac7f7c2d8bbe06ea04b41b87473/metrics_aggregate.json).
- [Comparison](../results/comparisons/research_pilot10_20261025_graph01_vs_static/comparison.json).
