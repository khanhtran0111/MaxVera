# Baseline Cards

**Mục đích:** mô tả đầu vào, information advantage, model, budget và giới hạn
của từng baseline.

Baseline matrix `1.2.3` đã được khóa tại
[`configs/baselines/matrix.yaml`](../configs/baselines/matrix.yaml). B0/B3-B9 là
zero-hint; B1/B2 là oracle-CWE và luôn được ghi nhãn riêng. B8 là ablation gần
nhất, B9 là proposed method chứ không phải external baseline.

| ID | Input/context | LLM | Trạng thái | Giới hạn diễn giải |
|---|---|---|---|---|
| B0 | CodeQL security-extended, không hint | Không | Phase 4 đã chạy | SAST zero-hint reference |
| B1 | CodeQL query chọn bằng CWE thật | Không | Phase 4 đã chạy | Oracle-CWE, không phải fair comparator |
| B2 | IRIS stages, CWE thật | GPT-OSS 20B | Phase 4 đã chạy | Model/toolchain substitution reproduction |
| B3 | Java chunks breadth-first | GPT-OSS 20B | Phase 5 runnable | Không security-aware retrieval |
| B4 | Java chunks xếp hạng bằng security terms | GPT-OSS 20B | Phase 5 runnable | Text retrieval, không program graph |
| B5 | Regex/static API signals trên toàn source Java | Không | Phase 5 runnable | Hypothesis, chưa static verification |
| B6 | Program Graph | GPT-OSS 20B | Blocked đến Phase 7/10 | Chưa có graph extractor/retriever |
| B7 | Security KG | GPT-OSS 20B | Blocked đến Phase 8/10 | Chưa có versioned knowledge graph |
| B8 | USEG không pruning | GPT-OSS 20B | Blocked đến Phase 9/10 | Nearest ablation |
| B9 | USEG pruned + verification/calibration | GPT-OSS 20B | Blocked đến Phase 6-12 | Proposed method |

## Hợp đồng công bằng B3/B4

B3 và B4 cùng dùng prompt `phase5-zero-hint-v3`, output schema Top-10, model
`openai/gpt-oss-20b`, provider route `akashml`, temperature 0, top-p 1,
seed 1234, output cap 2.048 và context cap 8.192 token/call. Cả hai chạy tuần
tự. Khác biệt duy nhất có chủ đích là B3 chọn chunks breadth-first theo file,
còn B4 xếp hạng chunks bằng vocabulary bảo mật chung đã khóa trong code.
Runner đối chiếu `.env`, baseline config, model config và experiment config;
route khác `akashml` làm run dừng trước khi tạo request.
Nếu response sai schema/path/line, repair prompt nêu lỗi validation cụ thể và
bắt buộc sao chép path/line từ evidence; không đổi nhiệm vụ phát hiện.
Request dùng Structured Outputs strict với enum động chỉ gồm các file xuất hiện
trong context; local validator tiếp tục kiểm tra file và line sau response.

Token input trước request được giới hạn bằng ước lượng UTF-8 bảo thủ và safety
margin. Gate sau response dùng usage do provider trả về. Nếu actual usage vượt
hard cap, project bị `ANALYSIS_FAILED`; không âm thầm tăng budget.

## Output và failure policy

Mỗi run ghi manifest, resolved config, environment, command, status đủ 120
project, hypotheses/findings, SARIF, call log, timing, resource/cost và checksum.
Output được tạo trong thư mục `.inprogress` rồi atomic rename. Một project lỗi
schema/API vẫn có status và khiến run không qua validator. Evaluator-only tạo
metric sau analysis; analyzer không import hay mở label view.

Run Phase 5 hiện là implementation-validation trên `D_repro_v1`, không phải
main locked-test claim. B0-B9 trên `D_extended/test_locked` chỉ được chạy sau
khi B6-B9 và calibration của Phase 6-12 hoàn tất.
