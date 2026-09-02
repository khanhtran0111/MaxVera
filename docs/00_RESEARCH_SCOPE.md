# Phạm vi nghiên cứu

**Mục đích:** khóa câu hỏi khoa học, điều kiện đầu vào và tiêu chí thành công trước khi phát triển phương pháp.

**Protocol:** `1.1.1` — cập nhật và frozen ngày 01/09/2026.

**Phạm vi:** Java, CodeQL, CWE-Bench-Java và `openai/gpt-oss-20b` qua OpenRouter.

## Bài toán và ranh giới

Đầu vào của hệ thống chính là một source repository Java. Trong điều kiện
zero-hint, analyzer không nhận CWE, CVE, advisory, patch, vị trí fix hay kết quả
đã công bố của chính project. Đầu ra là tập finding có repository, location,
candidate CWE, hypothesis, source, sink, guard/sanitizer, preconditions,
evidence path, provenance, confidence và quyết định `ACCEPT`, `VERIFY` hoặc
`ABSTAIN`.

Ba track được tách biệt:

1. **Reproduction:** IRIS v1 với dataset/toolchain đã khóa và GPT-OSS 20B thay model.
2. **Controlled baselines:** B0-B9 dùng cùng data, evaluator và budget khi có LLM.
3. **Proposed method:** Program Graph + Security KG + Evidence Graph (USEG),
   minimal retrieval, spec synthesis, static verification và selective routing.

Không thuộc scope chính: ngôn ngữ ngoài Java; nhận CVE/advisory như input; dùng
LLM verdict làm verifier cuối; hoặc so trực tiếp với phương pháp chỉ chạy trên
native setting khác. QLCoder, SemTaint, LLMxCPG, VulReaD, VulnAgent-R2, Argus,
AgenticSCR và EntailLLM là related-work/native-setting references trừ khi về sau
có adapter đáp ứng cùng input, firewall và budget.

## Research Questions đã khóa

- **RQ1 — Zero-hint discovery:** độ chính xác và thứ hạng hypothesis/CWE ở cấp
  repository so với CodeQL zero-hint và IRIS oracle-CWE.
- **RQ2 — Graph vs context:** USEG so với raw context và text-RAG dưới cùng token
  budget về Precision, Recall và F1.
- **RQ3 — Resource efficiency:** mức giảm token, calls, latency và peak memory do
  graph pruning, cùng delta recall.
- **RQ4 — Knowledge grounding:** ảnh hưởng của Security KG lên source, sink,
  sanitizer, propagator và verified path.
- **RQ5 — Calibration:** ảnh hưởng của `VERIFY/ABSTAIN` lên FDR, ECE, Brier Score
  và selective risk.
- **RQ6 — Generalization:** khả năng tổng quát sang repository family và CWE
  family chưa thấy ở development.

Thay đổi nội dung hoặc cách đo RQ yêu cầu protocol version mới và ghi quyết định
trong [`07_DECISION_LOG.md`](07_DECISION_LOG.md).

## Claim được phép kiểm tra

Claim chỉ được chốt sau locked test. Novelty dự kiến nằm ở zero-hint
repository-only setting, USEG, minimal-context retrieval và static-semantics-
grounded selective verification. Không claim “first SAST + LLM + KG”. Với IRIS,
chỉ dùng cụm **“IRIS pipeline reproduction with GPT-OSS 20B via OpenRouter”**;
cấm dùng “exact reproduction” hoặc “numerically reproduced”.

## Publishability gates

Một claim mạnh chỉ được dùng khi đồng thời có:

- reproduction report và B0-B9 trên cùng locked test;
- firewall không leakage, project status đầy đủ, raw results có checksum;
- full method tốt hơn baseline công bằng mạnh nhất có ý nghĩa thống kê, hoặc
  recall non-inferior trong biên 2 điểm phần trăm và giảm ít nhất khoảng 30%
  token/call/latency; ngưỡng cuối phải khóa trước test;
- ablation, calibration/risk-coverage nếu claim abstention, fixed-version hoặc
  blind manual audit, CI/test ở cấp project và error analysis ít nhất 50 case;
- mọi bảng/hình sinh từ immutable run IDs bằng script.

Nếu chỉ cải thiện recall nhưng FDR/chi phí tăng, narrative phải là discovery
thiên recall. Nếu chất lượng tương đương nhưng chi phí giảm, narrative phải là
resource-efficient retrieval. Không kết hợp hai claim khi dữ liệu không hỗ trợ.

## Upstream đã pin

Nguồn machine-readable duy nhất là [`configs/upstreams.yaml`](../configs/upstreams.yaml).
IRIS v1, CWE-Bench reproduction, CWE-Bench extended, CodeQL reproduction/main,
GPT-OSS 20B/OpenRouter model/provider route và Docker base đều được khóa. Phase 3
chỉ dùng một endpoint dùng một lần để kiểm tra kỹ thuật và không giữ lại output LLM. Vì
API release cũ không công bố digest, legacy IRIS CodeQL ZIP đã được tải trực tiếp,
kiểm tra cấu trúc archive và khóa SHA256 trong upstream config.
