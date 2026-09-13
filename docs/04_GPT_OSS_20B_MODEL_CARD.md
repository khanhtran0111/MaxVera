# GPT-OSS 20B / OpenRouter Model Card

**Mục đích:** khóa model, hosted backend, provider route và privacy policy dùng chung.

- Model ID: `openai/gpt-oss-20b`.
- Backend: OpenRouter Chat Completions, `https://openrouter.ai/api/v1`.
- Provider route canonical từ Phase 5: `akashml` tại snapshot ngày 03/09/2026.
- Snapshot Phase 4 protocol 1.1.1 đã chạy bằng `groq` được giữ nguyên như kết
  quả lịch sử, không đổi metadata và không trộn vào so sánh provider-controlled.
- Config Phase 4/Groq nằm riêng tại
  `configs/models/gpt_oss_20b_openrouter_groq.yaml`; config mặc định cho Phase 5
  và các phase sau pin AkashML.
- Canonical context/output budget: 8,192/2,048 tokens; temperature 0; top-p 1;
  seed 1234; reasoning effort `low`; parallel requests 1.
- Routing: `allow_fallbacks=false`, `require_parameters=true`, `zdr=true`,
  `data_collection=deny`.
- API key: chỉ đọc từ `OPENROUTER_API_KEY` trong `.env`, không ghi vào output.

Hosted model không có weight SHA do dự án kiểm soát. Mỗi run phải ghi requested
và returned model, provider route, request ID, system fingerprint nếu có,
input/output/reasoning token usage, cost, latency, retry và resolved routing.
Provider/model mismatch hoặc route unavailable phải làm request/run fail closed.

Mọi output LLM mới từ Phase 5 phải đến từ GPT-OSS 20B qua `akashml`. Output của
smoke kỹ thuật Phase 3 luôn bị xóa và không được dùng trong bảng thực nghiệm.
