# Qwen Model Card

**Mục đích:** khóa model/backend và điều kiện tài nguyên dùng chung.

- Model: `Qwen/Qwen2.5-Coder-3B-Instruct-GGUF`
- Revision: `f74adce6aa16316c625447af059dbebe4983757c`
- File: `qwen2.5-coder-3b-instruct-q4_k_m.gguf`
- SHA256: `724fb256bec1ff062b2f65e4569e871ad2e95ab2a3989723d1769c54294730b7`
- Backend: llama.cpp `v0.3.0`, commit
  `c1d0e7a004015f23bc0233470b747b596f29b264`
- Canonical context/output: 8,192/1,024 tokens; temperature 0; top-p 1;
  seed 1234; parallel 1; CPU-only.

Chat template lấy từ model metadata và phải được kiểm thử trước full run. GPU
offload không phải canonical; chỉ khóa sau benchmark theo protocol. Mỗi run phải
ghi model/file SHA, llama.cpp commit, template, context, GPU layers, thread/batch,
sampling, stop sequences và JSON repair policy. Full validation thuộc Phase 5.
