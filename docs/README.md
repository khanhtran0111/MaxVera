# Tài liệu hiện hành

Bắt đầu với tài liệu tương ứng công việc đang làm:

| Nội dung | Tài liệu |
| --- | --- |
| Phiên full reproduction đang chạy, tmux và nơi lưu log | [Lượt full ngày 21/10/2026](reproduction_full_2026-10-21.md) |
| Cách chạy và giới hạn reproduction | [Reproduction protocol v2](reproduction_protocol.md) |
| Pipeline research zero-hint và các bước chưa triển khai | [Research protocol v2](research_protocol.md) |
| Cách đánh giá, mẫu số và so sánh kết quả | [Evaluation protocol v2](evaluation_protocol.md) |
| Trạng thái triển khai từng capability | [Implementation status](IMPLEMENTATION_STATUS.md) |

Bằng chứng kiểm tra code: [validation report](validation_report.md). Chi tiết bản sửa phản hồi LLM và API thật: [LLM response repair](llm_response_repair_2026-10-21.md).

Thiết kế tổng thể có thẩm quyền: [kế hoạch triển khai v2](../ke_hoach_trien_khai_zero_hint_repository_vulnerability_research.md). Trạng thái `RUNNING` không phải kết quả full thành công.

## Hồ sơ nguồn và lịch sử

Các file sau được giữ để truy xuất nguồn gốc; không dùng làm hướng dẫn chạy hiện tại:

| Hồ sơ | Mục đích |
| --- | --- |
| [Migration inventory](migration_inventory.md) | Mapping và hạn chế của mã trước migration |
| [Migration decisions](migration_decisions.md) | Quyết định và review tại thời điểm migration |
| [Migration source index](migration_source_index.json) | SHA và đích đến của các file nguồn đã kiểm kê |
| [Legacy reproduction index](legacy_reproduction_index.json) | Chỉ mục/checksum kết quả lịch sử, không phải kết quả mới |
| [Storage cleanup](storage_cleanup.json) | Ghi nhận lần dọn dữ liệu cũ đã hoàn tất |

Tài liệu Phase/B0–B9 cũ, runbook trùng, hướng dẫn smoke đã dừng và hai plan sửa lỗi đã hoàn tất đã được bỏ khỏi `docs`. Bản gốc và danh sách xoá nằm trong thư mục được ghi ở `logs/docs_cleanup_latest.json`; bằng chứng chạy vẫn giữ tại các log/run gốc.
