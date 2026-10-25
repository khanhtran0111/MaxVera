# Tiêu chí pilot trước khi quyết định chạy full120

Ghi nhận ngày 24/10/2026, trước khi thực thi scientific pilot10. Các engineering
smoke trên hai case đã xem trước không được dùng làm kết quả pilot hoặc bằng chứng
blind. Đây là tiêu chí tối thiểu để mở rộng thí nghiệm, không phải ngưỡng chứng
minh hệ thống phát hiện lỗ hổng tốt hoặc một kết luận có ý nghĩa thống kê.

## Cohort và đầu vào

- Giữ đúng mười IDs trong `configs/pipelines/research_pilot10.csv`, không đổi hoặc
  bỏ case theo kết quả. Giữ nguyên development/test_locked 96/24.
- Cả mười source/provenance/build recipes phải qua preflight; cả mười case phải
  có truth đã xác minh ở vulnerable snapshot. Không dùng evaluable subset để
  phê duyệt full khi một case của pilot còn unknown.
- Freeze input inventories, mapping revision, code/query versions, model/provider,
  Top-K, budgets và resolved config trước lần pilot được dùng để quyết định.

## Static và graph

- Chạy `static_only` và `graph_only` với cùng profile pilot đã chuẩn bị, nguồn,
  generic suite, cutoffs và ngân sách tương ứng. Primary cutoff là **Top-5**;
  Top-10/20 chỉ là secondary diagnostics, không đổi primary sau khi xem kết quả.
- Mọi case phải hoàn tất engineering acceptance: stage/candidate accounting đầy
  đủ, không empty pool, không traversal truncation hoặc integrity failure.
- Điều kiện tín hiệu tối thiểu: graph strong Recall@5 không thấp hơn static,
  đồng thời có **ít nhất một case** strong match ở graph Top-5 mà static Top-5
  không có, với matching graph candidate có `default_alert_overlap: false`.
  Ghi rõ số case và candidate/span bằng chứng, không chỉ báo phần trăm.
- Phân biệt raw-pool miss, Top-K miss và default-query overlap. Không lấy graph
  candidate trùng endpoint static làm bằng chứng discovery mới. Không suy ra
  precision/FDR từ cohort chỉ có positive labels hoặc coi unmatched là false positive.
- Nếu điều kiện không đạt, giữ NO-GO và phân tích development evidence. Một lần
  chỉnh sửa sau khi xem pilot tạo một vòng development mới, không được mô tả là
  xác nhận blind cho giả thuyết cũ.

## LLM và verification

Chỉ mở pilot `graph_llm_verify` sau khi có review bằng chứng static/graph và quyết
định graph-signal riêng. Không tự bật `graph_signal_approved` để chạy qua guard.

- Giữ cùng retained candidate pool và cutoffs đã freeze cho phép so sánh paired.
- Assessment hợp lệ/citation/evidence completeness phải đủ 100% retained candidates;
  verification supported phải đủ 100% theo engineering gate hiện tại.
- Whole-cohort ranked Recall@5 không thấp hơn graph pre-LLM Recall@5. Báo cáo
  cả improvement, regression và unchanged cases; không bỏ uncertain candidates.
- Không còn PENDING/UNCERTAIN charge chưa giải quyết hoặc unknown-cost attempt;
  mọi call nằm trong resolved budget/deadline. Resume cùng identity không có
  paid call mới hoặc thay frozen artifacts.
- `FLOW_FOUND` chỉ là modeled reachability, `NO_FLOW_FOUND` không là safety;
  schema/citation valid không thay thế review rationale và security evidence.

## Full120

Full120 chỉ đủ điều kiện khi các gate trên đạt, đủ 120 source/build/provenance
và 120 case truth aligned, cấu hình đã freeze và graph-signal được review thực
chất. Trước execution vẫn chạy full preflight. Không dùng locked24 để sửa discovery,
ranking hoặc chọn ngưỡng. Mọi full120 inference phải ghi giới hạn nguồn nhãn và
model; vượt gate chỉ cho phép thực hiện thí nghiệm đầy đủ.

Hiện chưa thực thi scientific pilot theo tiêu chí này. Mapping pilot v2 mới có
6/10 case aligned; `graph_signal_approved` vẫn false.

## Amendment vận hành exploratory

[Full enablement](research_full_enablement_2026-10-24.md) bổ sung protocol
prospective exploratory sau actual paired development measurement, theo mục tiêu
gốc cho phép kết quả âm. Đây là scope execution riêng, giữ approval false và
không được báo là đã đạt các tiêu chí confirmatory ở trên. Unknown truth giữ
nguyên cohort và whole-cohort recall null. Mapping v3 chỉ rebind inventory mới,
giữ nguyên 55 mapped/12 unresolved rows và 6/10 aligned cases.
