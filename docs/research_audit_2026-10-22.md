# Audit tiếp theo review và dọn output — 22/10/2026

Hồ sơ lịch sử của lượt audit. Các lỗi phía dưới đã được sửa trong [lượt 23/10](research_smoke_2026-10-23.md). Theo yêu cầu xóa toàn bộ output cũ, artifact/reproducer/biên bản machine-readable được nhắc trong lượt audit này đã xóa; regression hiện hành nằm trong bộ test.

## Kết luận

**Chưa sẵn sàng chạy full.** Kiểm tra trực tiếp source và tái lập offline xác nhận thêm bốn lỗi có thể làm mất candidate/path. Lượt này kiểm tra và dọn dung lượng theo yêu cầu; không thay thuật toán, không sửa upstream IRIS, không gọi provider hoặc chạy thêm benchmark.

Bản đính kèm mới có SHA256 giống bản review trước (`30e11e8e…369c5987`). Vì vậy audit tập trung vào phần checklist chưa được chứng minh ở cấp source, thay vì coi những khuyến nghị cũ là tính năng đã triển khai.

## Lỗi đã tái lập

| Phạm vi | Vị trí | Tái lập / ảnh hưởng | Hướng sửa cần kiểm chứng |
|---|---|---|---|
| Research discovery | `maxvera/candidates.py:83`, `:98`; `ProgramCore.qll:3` | Graph có một node mang cả `source` và `sink` sinh hai candidate `SOURCE_ONLY`/`SINK_ONLY`, không có cặp endpoint đầy đủ. Điều kiện `current != start` loại đường identity tại cùng biểu thức. | Giữ một complete candidate có source=sink, không cần edge; gộp attribution của hai generator. Kiểm thử biểu thức input lồng trực tiếp trong sink và targeted verifier. |
| Reproduction validation | `maxvera/llm.py:21–34` | `[{}]`, `{}` và `{"is_vulnerable":"not a boolean"}` đều vượt validation hiện tại. Kiểm tra chỉ bảo đảm hình dạng JSON; upstream có thể bỏ entry/path thiếu trường thay vì báo lỗi adapter. | Validation field/type theo từng stage trước khi lưu SUCCESS; phân biệt invalid response với verdict âm hợp lệ. |
| Reproduction parsing | `third_party/iris/src/modules/contextual_analysis_pipeline.py:294–297` | JSON hợp lệ có `is_vulnerable=true` nhưng explanation chứa URL `http://…` hoặc chuỗi rỗng bị parser upstream biến thành `{}`. Adapter đã chấp nhận JSON trước đó không ngăn lần parse phá dữ liệu này. | Chuyển parsed result nghiêm ngặt tới consumer, hoặc override parser riêng trong workspace của run. Ghi rõ deviation so với artifact IRIS pin. |
| Reproduction batching | Cùng module upstream, `:699–705` | Hai input path: path đầu đang chờ, path cuối bị ignore hoặc dùng cache. Không batch nào được gửi; output chỉ có path cuối nhưng `num_failure=0`. Tail batch chưa được flush. | Flush sau vòng lặp và kiểm tra accounting của toàn bộ path. Ghi rõ sửa behavior upstream; không âm thầm coi run đã sửa là reproduction nguyên bản. |

Các lỗi trên được tái lập trên fixture offline; **chưa có bằng chứng chúng giải thích từng CVE bị bỏ lỡ trong smoke r4 hoặc số failures của run cũ**. Không dùng ground truth để thêm luật cho analyzer.

## Những điểm review vẫn chưa hoàn tất

- **Recovery batch:** chưa có bisection và missing-ID recovery. IRIS gốc yêu cầu chỉ trả các API dương tính; omission chưa phân biệt được với nhãn âm. Không được áp completeness bằng phép trừ ID một cách máy móc. Muốn accounting đầy đủ phải khai báo protocol có nhãn `NONE` hoặc nêu giới hạn faithful mode.
- **Coverage generator:** giới hạn hop/4.096 node chưa có artifact ghi lý do cutoff/visited count; partial candidate chưa phân biệt được bounded search với graph không nối. Việc mỗi candidate quét lại toàn bộ edges cũng gây nguy cơ timeout khi graph lớn.
- **Coverage extraction:** stage lưu hash workspace nhưng chưa tự so expected Java inventory của build recipe với extraction/source archive. `partial_build_rate` vẫn null; kiểm tra 3/3 và 118/118 của smoke là audit riêng, chưa phải gate tự động dùng lại được.
- **Gate thí nghiệm:** frozen graph-only development signal, ablation, adjudicated negatives và đánh giá thống kê vẫn chưa có; r4 giữ Recall@5=0/2. Sai khác CodeQL reproduction 2.15.5 với paper 2.15.3 chưa được chứng minh tương đương.

## Những invariant đã có trong code

Research giữ raw/pre-LLM output và kiểm tra ID/score/rank khi final; LLM âm/no-flow không xóa candidate và không dùng endpoint-global negative cache. Retrieval giới hạn context, kiểm tra source hash, evidence bundle và citation ID. Worker lọc environment và dùng Landlock; runtime CodeQL tách riêng. Provider được pin, fallback tắt và returned route/model/usage được kiểm tra.

Evaluator tách `legacy_artifact` với `paper_formula_path`, đếm alert/path theo protocol, loại project không có path khỏi FDR trung bình và giữ failure trong mẫu số recall. Không thấy blocker mới ở các phần này trong lượt audit.

## Bằng chứng mới

Lệnh kiểm tra có phạm vi liên quan, chạy lại sau audit:

```bash
.venv/bin/python -m pytest -q \
  tests/pipeline/test_evaluation_protocols.py \
  tests/pipeline/test_llm_response_recovery.py \
  tests/pipeline/test_reproduction.py \
  tests/pipeline/test_llm_journal.py
```

**117 passed, 7.04 giây.** Các reproducer ngoài bộ test xác nhận hành vi sai nêu trên, cho thấy test pass chưa bao phủ hết invariant. Không trình bày những reproducer này như test regression đã sửa RED→GREEN.

- JSON bằng chứng/hash source, reproducer offline và biên bản dọn dung lượng được tạo ở thời điểm audit; đã xóa ngày 23/10 theo yêu cầu không giữ output cũ. Các reproducer dùng class upstream qua AST, thay provider bằng fixture và không gọi mạng.

## Phạm vi dọn dung lượng

Xóa các run reproduction cũ, smoke research trước r4, evaluator r3, log cũ và cache research của các run đã xóa. Giữ r4 và evaluator r4, log chẩn đoán gọn đang dùng, export legacy được Git theo dõi, source/config/test, dataset, `.env`, `.venv`, toolchains và third-party checkouts. Script lấy lock run, từ chối target chứa tracked files và kiểm tra hash tracked files/r4 trước và sau.

Cleanup **COMPLETED**: đã xóa 25 target, gồm 9 run; thực thu hồi **240,515 GiB**. Dung lượng trống tăng từ khoảng 61,36 lên **301,87 GiB**; filesystem dùng 32% sau cleanup. Tất cả target đã biến mất; hash tracked files và checksum index r4 không đổi tại thời điểm hoàn tất cleanup. Các cập nhật tài liệu audit/index sau đó là thay đổi có chủ đích của lượt này.

Raw artifacts của run đã xóa không còn để resume hoặc đánh giá lại. Các con số reproduction cũ chỉ còn là bằng chứng lịch sử trong báo cáo và biên bản tóm tắt; không coi chúng là run còn nguyên artifact.

Ưu tiên sửa tiếp theo: candidate identity flow trong research; sau đó validation/parser/accounting của reproduction với deviation được khai báo. Full LLM research tiếp tục giữ gate đóng.
