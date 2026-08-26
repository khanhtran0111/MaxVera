# Reproduction Report

**Mục đích:** báo cáo IRIS pipeline reproduction with Qwen3B và variance.

Execution thuộc Phase 4. Ba variance đã biết phải được giữ nguyên trong báo cáo:
model Qwen3B Q4_K_M thay model paper; paper dùng max tokens 2,048 trong khi
artifact config có 1,024; artifact result có 121 rows do CVE-2021-21345 được
đánh giá ở CWE-078 và CWE-094 trong khi canonical dataset có 120 CVE rows.

Không claim exact/numerical reproduction. Phải xuất song song artifact-compatible
metrics, dataset-canonical metrics và `reproduction_variance.md`.
