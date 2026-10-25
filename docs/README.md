# Tài liệu hiện hành

Bắt đầu với tài liệu tương ứng công việc đang làm:

| Nội dung | Tài liệu |
| --- | --- |
| Kết quả pilot10 thực tế, lỗi build/graph và quyết định NO-GO | [Pilot results ngày 25/10/2026](research_pilot_result_2026-10-25.md) |
| Cách chạy full research, chuẩn bị/resume và protocol exploratory | [Full research runbook ngày 24/10/2026](research_full_runbook_2026-10-24.md) |
| Nâng cấp full pipeline, source120 và bằng chứng kiểm tra mới | [Full enablement ngày 24/10/2026](research_full_enablement_2026-10-24.md) |
| Thực thi các bước GO, smoke pass và coverage còn thiếu | [Research GO execution ngày 24/10/2026](research_go_execution_2026-10-24.md) |
| Tiêu chí ghi nhận trước scientific pilot10 | [Pilot acceptance](research_pilot_acceptance_2026-10-24.md) |
| Sửa blocker, preflight và quyết định chạy 120 case | [Research readiness ngày 24/10/2026](research_readiness_2026-10-24.md) |
| Smoke mới trên hai case ngẫu nhiên và kiểm tra pipeline MaxVera | [Research smoke ngày 23/10/2026](research_smoke_2026-10-23.md) |
| Audit tiếp theo review, lỗi mới tái lập và dọn output | [Research audit ngày 22/10/2026](research_audit_2026-10-22.md) |
| Sửa research pipeline, smoke 2 case và gate còn thiếu | [Research smoke ngày 22/10/2026](research_smoke_2026-10-22.md) |
| Hồ sơ lịch sử reproduction; raw run/log đã được dọn | [Lượt full ngày 21/10/2026](reproduction_full_2026-10-21.md) |
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

Tài liệu Phase/B0–B9 cũ, runbook trùng, hướng dẫn smoke đã dừng và hai plan sửa lỗi đã hoàn tất đã được bỏ khỏi `docs`. Theo yêu cầu mới ngày 23/10/2026, mọi run/log cũ, cả r4, export kết quả legacy và tóm tắt machine-readable từng giữ lại, đều đã xóa. Các báo cáo cũ chỉ là tài liệu lịch sử; raw artifacts đó không còn để resume/đánh giá lại. Chỉ giữ output/bằng chứng của tác vụ smoke mới.
