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
| 2026-09-03 | Phase 5 B3-B5 implementation | ready/offline-tested | controlled runner, budget estimator, evaluator and validator; no API run |
| 2026-09-03 | Phase 5 provider migration | configured/not run | AkashML route pinned, protocol 1.2.0, D-012; no API call |
| 2026-09-13 | Phase 5 pilot 1 project | passed | B3/B4/B5 analysis, evaluator và validator đều pass |
| 2026-09-13 | Phase 5 gate20 attempt 001 | B3 pass; B4 19/20 | B4 lặp hallucinated file path qua generic repair; B5 chưa chạy |
| 2026-09-13 | Phase 5 repair feedback | implemented | prompt v2, protocol 1.2.1, D-013; rerun bằng ID mới |
| 2026-09-13 | Phase 5 gate20 attempt 002 | B3 pass; B4 19/20 | validation feedback vẫn bị bỏ qua ở cùng path; B5 chưa chạy |
| 2026-09-13 | Phase 5 strict structured output | implemented | dynamic file enum, prompt v3, protocol 1.2.2, D-014 |
| 2026-09-13 | Phase 5 gate20 attempt 003 | B3 19/20 | one project exhausted four rapid HTTP 429 attempts; B4/B5 chưa chạy |
| 2026-09-13 | Phase 5 429 backoff | implemented | Retry-After/bounded 5–60s backoff, protocol 1.2.3, D-015 |
| 2026-09-13 | Phase 5 gate20 attempt 004 | passed | B3/B4/B5 20/20 success; evaluator/validator pass; API cost `$0.00791760` |
| 2026-09-13 | Phase 5 full budget-matched B3 | scientifically complete with one miss | run `p5_akashml_bm_full_001_b3`: 119 success, 1 `ANALYSIS_FAILED` after six HTTP 429 attempts; evaluator covers 120/120; API cost `$0.02110620` |
| 2026-09-13 | Phase 5 failure-accounting alignment | implemented | validator accepts fully recorded final failures as intention-to-analyze misses; suite continues B4/B5; D-016 |

Các smoke run đã bị cleanup theo protocol. Pilot dùng backend trước protocol
1.1.0 chỉ là kiểm tra kỹ thuật và đã bị xóa cùng partial full run; không số liệu
legacy nào được dùng.
Pilot 002 là kiểm tra kỹ thuật một database, không phải scientific result. Full
GPT-OSS 20B run 001 đã có metrics intention-to-analyze trên đủ 120 status; 5/104
B2 analysis failures được tính là miss nên strict all-success gate chưa pass.
