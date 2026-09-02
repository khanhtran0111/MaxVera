# Experiment Log

**Mục đích:** index các run và thay đổi vận hành; không lưu secret hoặc số liệu
chép tay.

| Date | Run/phase | Status | Pointer |
|---|---|---|---|
| 2026-08-26 | Phase 0 protocol 1.0.0 | frozen | `docs/00_*`, `docs/01_*` |
| 2026-08-26 | Phase 1 scaffold | implemented | repository commit/working tree |
| 2026-08-29 | Phase 2 data/build gate | passed | 104 DB success, 16 recorded failures |
| 2026-08-29 | Phase 3 smoke pass | passed/cleaned | endpoint through evaluator; 0 artifact |
| 2026-08-29 | Phase 3 injected failure | passed/cleaned | failed after analysis; 0 artifact |
| 2026-08-29 | Phase 4 one-project technical pilot | passed | B0/B1/B2, 120 statuses, all IRIS stages |
| 2026-09-01 | Protocol/model migration | implemented | GPT-OSS 20B/OpenRouter, protocol 1.1.0, D-009 |
| 2026-09-01 | Legacy Phase 4 full run | stopped/removed | tmux stopped; B2 full/pilot outputs moved to trash |
| 2026-09-01 | GPT-OSS pilot 001 | failed/diagnosed | filesystem-unsafe model ID and truncated 1,024-token JSON; D-010 |
| 2026-09-01 | GPT-OSS pilot 002 | passed | B0/B1/B2 validated; 4/4 LLM calls stopped normally; D-010 |
| 2026-09-02 | GPT-OSS full 001 | metrics generated; strict gate failed | 99 B2 successes, 5 analysis failures; run ID `phase4_gptoss20b_full_001` |

Các smoke run đã bị cleanup theo protocol. Pilot dùng backend trước protocol
1.1.0 chỉ là kiểm tra kỹ thuật và đã bị xóa cùng partial full run; không số liệu
legacy nào được dùng.
Pilot 002 là kiểm tra kỹ thuật một database, không phải scientific result. Full
GPT-OSS 20B run 001 đã có metrics intention-to-analyze trên đủ 120 status; 5/104
B2 analysis failures được tính là miss nên strict all-success gate chưa pass.
