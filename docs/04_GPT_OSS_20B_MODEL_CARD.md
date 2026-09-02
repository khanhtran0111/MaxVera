# GPT-OSS 20B / OpenRouter Model Card

**Mục đích:** khóa model, hosted backend, provider route và privacy policy dùng chung.

- Model ID: `openai/gpt-oss-20b`.
- Backend: OpenRouter Chat Completions, `https://openrouter.ai/api/v1`.
- Provider route canonical: `groq` tại snapshot ngày 01/09/2026.
- Canonical context/output budget: 8,192/2,048 tokens; temperature 0; top-p 1;
  seed 1234; reasoning effort `low`; parallel requests 1.
- Routing: `allow_fallbacks=false`, `require_parameters=true`, `zdr=true`,
  `data_collection=deny`.
- API key: chỉ đọc từ `OPENROUTER_API_KEY` trong `.env`, không ghi vào output.

Hosted model không có weight SHA do dự án kiểm soát. Mỗi run phải ghi requested
và returned model, provider route, request ID, system fingerprint nếu có,
input/output/reasoning token usage, cost, latency, retry và resolved routing.
Provider/model mismatch hoặc route unavailable phải làm request/run fail closed.

Mọi output LLM được giữ lại từ Phase 4 trở đi phải đến từ GPT-OSS 20B qua route
canonical ở trên. Output của smoke kỹ thuật Phase 3 luôn bị xóa và không được dùng
trong bảng thực nghiệm.
