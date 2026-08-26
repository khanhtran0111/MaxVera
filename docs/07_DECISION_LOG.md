# Decision Log

**Mục đích:** ghi quyết định làm thay đổi khả năng tái lập hoặc diễn giải kết quả.

## D-001 — Freeze protocol 1.0.0 (2026-08-26)

Khóa Java + CodeQL, RQ1-RQ6, evaluation units, B0-B9 classification, label
firewall, budget, metrics, statistics và publishability gates theo
`00_RESEARCH_SCOPE.md` và `01_EXPERIMENT_PROTOCOL.md`.

## D-002 — Hai CodeQL toolchain độc lập (2026-08-26)

Reproduction dùng IRIS `codeql-0.8.3-patched`; main study dùng CodeQL bundle
2.26.2 với `codeql/java-queries@1.11.7`. Kết quả giữa toolchain không trộn. SHA
của legacy ZIP không có trong release API nên đã được tính trực tiếp:
`e61633fa05ee291ba01cdaa36bbe96acfe83ca3e6aa6b77b06406abb24cec094`
(807,846,025 bytes); archive listing đã được kiểm tra trước khi khóa.

## D-003 — Canonical CPU inference (2026-08-26)

Qwen3B Q4_K_M qua llama.cpp, context 8K, one request/project-at-a-time và
`n_gpu_layers=0` là canonical. Partial GPU offload chỉ là technical benchmark
trước khi có decision mới.

## D-004 — License chưa được chủ sở hữu chọn (2026-08-26)

Không tự cấp open-source license. Root `LICENSE` giữ all-rights-reserved cho đến
khi copyright holder chọn license; third-party giữ nguyên terms riêng.

## Quy trình thay đổi

Decision mới phải ghi ngày, lý do, alternatives, impact, protocol version và
config/result bị ảnh hưởng. Không sửa ngầm RQ, split, budget, model, tool, metric
hoặc threshold.
