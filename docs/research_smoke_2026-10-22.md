# Sửa research pipeline và smoke — 22/10/2026

Hồ sơ lịch sử. Ngày 23/10, mọi run/log cũ trong báo cáo này, gồm cả r4 và evaluator, đã xóa theo yêu cầu mới. Xem [lượt smoke mới](research_smoke_2026-10-23.md) để biết trạng thái hiện hành.

## Phạm vi và trạng thái

Theo yêu cầu của người dùng: sửa theo bản research review, kiểm tra kỹ, chỉ smoke 1–2 trường hợp, chưa chạy full. Chỉ hai project development thuộc D_extended được dùng qua các lần sửa lỗi; không mở rộng dataset. Đây là kiểm tra kỹ thuật, **SMOKE_NOT_BENCHMARK**.

Lượt cuối **`research_smoke_20261022_r4` COMPLETED, 2/2 case terminal**. LLM thật có 5/5 assessment hợp lệ và verifier chạy query thật. Tuy nhiên **Recall@5 = 0/2** với ground truth hai case này; chưa đủ điều kiện chạy full. Đây là kết quả kỹ thuật và chẩn đoán discovery, không phải kết luận benchmark hoặc chất lượng model.

| Case | Raw pool → Top-5 → final | LLM | CodeQL verifier |
|---|---|---|---|
| json-sanitizer | 0 → 0 → 0 | Không có candidate để gọi | Không có endpoint để kiểm tra |
| Commons IO | 261 → 5 → 5 | 5/5 VALID | 2 FLOW_FOUND, 3 UNSUPPORTED_SPEC; 4 query invocations |

Việc 261 → 5 là cutoff **trước LLM**; toàn bộ 261 candidate raw vẫn được lưu. Sau reasoning, cả 5 candidate được giữ nguyên ID, score và rank ban đầu. Không candidate nào bị xóa vì NOT_SUPPORTED, UNCERTAIN hoặc endpoint chưa hỗ trợ.

Evaluator độc lập sau freeze: discovery Recall@5 **0%**, final ranked Recall@5 **0%**, ranking complete **2/2**, verified known-CVE detection **0/2**. Hai FLOW_FOUND không khớp vulnerability program point đã gán nhãn, nên không được tính là hai CVE tìm đúng. Không ước lượng FDR/F1 cho research khi chưa có adjudicated negatives. Không báo Recall@10/@20 từ smoke chỉ giữ Top-5.

Chẩn đoán riêng trên **toàn bộ raw pool đã freeze** cũng không có strong match hay location match với truth ở cả hai case. Vì vậy, trong smoke này lỗi không chỉ nằm ở cutoff/rerank: generator chưa sinh được ứng viên chạm đúng program point đã biết. Analyzer/rank không được chỉnh từ kết quả ground truth này.

## Thay đổi

1. **Research có reasoning thật:** retrieval lấy code/graph từ snapshot đã phân tích, kiểm tra hash, giới hạn context, khóa bundle/evidence ID. GPT-OSS-20B qua Groq chỉ cộng/trừ điểm; không xóa candidate và không có cache phán quyết âm dùng chung endpoint. Lỗi response giữ candidate ở UNCERTAIN. Citation validation kiểm tra ID tồn tại; không chứng minh rationale đúng về ngữ nghĩa.
2. **Verification có query thật:** kiểm kê endpoint chính xác rồi chạy CodeQL global taint reachability trên DB riêng. `FLOW_FOUND` là bằng chứng theo static model, không phải exploit. `NO_FLOW_FOUND`, endpoint thiếu, query lỗi hoặc timeout đều giữ candidate. Manifest DB gắn với snapshot, kiểm tra trước resume và từng query để chặn DB bị thay đổi.
3. **Evaluator khóa đơn vị đếm:** `legacy_artifact`/alias `iris_paper` đếm alert theo artifact cũ; `paper_formula_path` đếm path thực. Container rỗng không vào mẫu số path. Thiếu nhãn/truth gây lỗi nêu case ID. Research chỉ báo K đã cấu hình, kèm raw/retained/cutoff; aggregate recall sau reasoning là null nếu assessment chưa đầy đủ. Không suy FDR từ candidate chưa được thẩm định.
4. **Runtime được sửa qua smoke:** tạo thư mục classes trước javac; lưu script để CodeQL không tách sai shell quoting; cho sandbox đọc đúng file đích resolver DNS của hệ thống. Credentials chỉ truyền qua stdin, không vào resolved config; response thành công cũng được che exact API key trước cache/finding. Checksum verification đọc theo luồng và kiểm kê bằng SQLite tạm.

## Hai trường hợp smoke

| Project / opaque ID | Commit D_extended | Cách build |
|---|---|---|
| json-sanitizer / `proj_91e28208605dbd16dda6` | `bb41f80ad575cb90ea6535976d7c17accb4b4c87` | JDK 8u202, 3 main Java files; dependency jsr305 đã hash |
| Commons IO / `proj_47c10c379d379cebae55` | `2ae025fe5c4a7d2046c53072b0898e37a079fe62` | JDK 8u202, 118 main Java files |

Nguồn được sao chép từ checkout sạch đúng commit, chỉ lấy source và dependency generic; không lấy IRIS specs/cache/nhãn. D_repro và D_extended dùng opaque ID khác nhau nên membership và commit được kiểm tra riêng. Worker không đọc reproduction output. Build là **manual main-source javac phục vụ smoke**, chưa phải Maven lifecycle nguyên bản của benchmark.

Kiểm tra source archive r4: **3/3** và **118/118** main Java files dự kiến có trong DB, không có main source bị thiếu. Điều này kiểm tra coverage của recipe smoke; không chứng minh mọi dependency hoặc test source đã được trích xuất đầy đủ.

CodeQL research: **2.26.2**; reproduction giữ binary riêng đang báo **2.15.5**, chưa chứng minh tương đương paper 2.15.3. Model/profile được giữ cố định: `openai/gpt-oss-20b`, Groq, temperature 0, top-p 1, reasoning low, output cap 2048. Budget smoke: 12 attempts/case, ngưỡng dừng $0.10/case, tối đa 2 case. Ngưỡng dollar không phải prepaid cap phía provider.

Manifest local: `data/processed/analysis_input/smoke/research_smoke_20261022.csv`. Nguồn và manifest local không được đóng gói trong Git. Provenance chuẩn bị, amendment build và log tại `logs/research_smoke_20261022/`.

## Lịch sử smoke giữ nguyên

| Run | Kết quả / nguyên nhân |
|---|---|
| `research_smoke_20261022` | 2 BUILD_FAILED: javac JDK8 yêu cầu classes tồn tại; chưa gọi model |
| `research_smoke_20261022_r2` | Build thử pass, DB failed vì CodeQL tách sai lệnh shell có quoting; chưa gọi model |
| `research_smoke_20261022_r3` | 2 case terminal; json-sanitizer 0 candidate, Commons IO 261 raw → Top-5 → 5 findings. Query thật: 2 FLOW_FOUND, 3 UNSUPPORTED_SPEC. LLM dừng sau 1 lỗi DNS, không báo rerank hoàn chỉnh |
| `research_smoke_20261022_r4` | COMPLETED 2/2. LLM: 5/5 VALID, 0 failed; 1 SUPPORTED, 3 NOT_SUPPORTED, 1 UNCERTAIN. CodeQL: 2 FLOW_FOUND + 3 UNSUPPORTED_SPEC. Resume pass |

Journal UNCERTAIN của r3 được giữ nguyên. Chẩn đoán riêng tái lập HTTPS dưới allowlist cũ: URLError do gaierror trước kết nối; allowlist mới trả HTTP 200 cho GET models không dùng model/key. Có adjudication riêng cho phép smoke mới trên cùng hai case. Journal r3 không lưu nested exception; chẩn đoán DNS là suy luận từ tái lập cùng transport/sandbox, không phải kiểm tra hóa đơn provider.

Lượt r4 ghi đúng returned model `openai/gpt-oss-20b` và provider `Groq`; 5 HTTP completion SUCCESS, finish_reason `stop`, không retry. Chi phí provider trả về cho 5 completion là **$0.00119355**. Ba ý kiến âm và một uncertain vẫn có candidate tương ứng; chỉ ảnh hưởng điểm, không prune.

Usage r4: 9.666 prompt tokens, 1.562 completion tokens, trong đó 214 reasoning tokens được provider ghi nhận. Prompt lớn nhất 7.238 UTF-8 bytes, dưới bound 8.192 đã cấu hình.

Lệnh đã chạy cho r4:

```bash
MAXVERA_OPENROUTER_PROVIDER=groq .venv/bin/python -m maxvera pipeline research \
  --config configs/pipelines/research_smoke.yaml --mode smoke --limit 2 \
  --run-id research_smoke_20261022_r4 --execute
```

Dry-run riêng xác nhận smoke có tối đa 24 attempts và ngưỡng dừng tổng $0.20 theo cấu hình. Full LLM dry-run bị từ chối với `full LLM research requires a reviewed frozen development signal`; không tạo full run.

## Kiểm chứng code

| Kiểm tra | Kết quả |
|---|---|
| `.venv/bin/python -m pytest -q` | **460 passed, 2 skipped**, 27.38 giây; hai skip là fixture CodeQL opt-in |
| `.venv/bin/python -m ruff check .` | Pass |
| `.venv/bin/python -m mypy src` | Pass, 126 source files thuộc phạm vi cấu hình; không phải type-check toàn bộ module maxvera mới |
| `git diff --check` | Pass |
| Review độc lập | Ba blocker đã sửa: DB resume integrity, Recall@K vượt cutoff và API-key echo ở response thành công |

Resume thật cùng config/code/input: **exit 0 trong 2,476 giây**, không thay checksum index hoặc call journal; số calls trước/sau đều **5**. SHA256 checksum index: `210e9ddfd2aabc0ca885badfa27796de277c464d351cb570c5989c7d392d68cf`. Kiểm tra critical DB sau tất cả query vẫn khớp manifest cho cả hai case (150 và 154 critical files). Quét toàn bộ **4.781 run files** không thấy exact API key; không in hoặc lưu key vào bằng chứng.

Artifact chính:

- Run: `results/_smoke/research/research_smoke_20261022_r4/`.
- Evaluation: `results/evaluations/research_smoke_20261022_r4/zero_hint/`.
- Bằng chứng compact: `logs/research_smoke_20261022/smoke_r4_summary.json`, `resume_r4.json`, `integrity_r4.json`, `source_coverage_r4.json`, `raw_pool_diagnosis_r4.json`.

Regression quan sát RED → GREEN gồm empty-path counting, missing labels/truth, checksum tamper/duplicate/symlink, soft-negative/no-flow giữ candidate, citation giả, frozen score/rank, shell argv có quote/khoảng trắng/literal, resolver không mở rộng quyền đọc thư mục runtime, DB mutation/replacement/add/delete/parent symlink, và key echo trước cache. Query verifier cũng đã compile với CodeQL thật; r3 chạy query thật với endpoint unique và kết quả flow đã decode.

## Đối chiếu CodeQL reference với paper

Audit artifact hiện có, không chạy lại benchmark: paper 27 và reference hiện tại 20 chỉ trùng **17 CVE**. Vì vậy có **10 paper hits bị mất, đồng thời 3 hits mới**, không phải chỉ 7 case bị mất.

Trong 10 paper-only: 9 bị chặn bởi build/DB hoặc audit artifact/source; TestNG còn lại có DB SUCCESS nhưng recipe chỉ chạy `gradlew clean`, và file ground truth `JarFileUtils.java` không có trong source archive. Cả 13 checkout khác biệt khớp commit canonical. Không có DB/query/build hash tác giả để khẳng định parity hay quy nguyên nhân cho version/model. Bảng case-by-case: `logs/research_smoke_20261022/reference_gap.csv` và `.json`.

## Gate chưa đạt trước full

1. Chưa có frozen development graph-only signal đủ rộng hoặc matched ablation; hai case smoke chưa phát hiện đúng known CVE. Json-sanitizer không có source/sink role trong graph nên discovery rỗng; Commons IO có nhiều candidate nhưng toàn raw pool không chạm truth. Cần sửa coverage của generator theo thiết kế generic được chốt trước, rồi kiểm tra graph-only; reasoning không thể phục hồi candidate chưa sinh ra.
2. Reproduction vẫn còn 67/120 failures; IRIS batch bisection và missing-ID recovery chưa triển khai trong đợt này. Không sửa semantics hard filtering của bản reproduction để làm đẹp số.
3. Chưa có CWE-specific barrier templates, adjudicated negatives, bootstrap/McNemar hoặc benchmark hiệu năng đầy đủ. Ground truth cũ còn thiếu phải được bổ sung có nguồn gốc trước đánh giá chính thức toàn bộ run.

Full LLM research vẫn bị chặn khi `graph_signal_approved` chưa được duyệt. Code sửa chưa commit/push trong tác vụ này.

## Kiểm tra lại sau crash — 22/10/2026

**Chưa thể kết luận đã sửa hoàn toàn hoặc sẵn sàng chạy full.** Các bản sửa research trong phạm vi smoke vượt qua kiểm thử lại; điểm chưa đạt vẫn là coverage của candidate generator và các gate đã nêu trên. Lần kiểm tra này không thay đổi thuật toán, không chạy thêm benchmark case hoặc gọi completion mới.

Đã khôi phục yêu cầu cuối từ lịch sử local: sửa theo review phần research, giữ model/provider và chỉ smoke 1–2 case. Báo cáo này được đối chiếu với artifact thực tế, không chỉ đọc lại kết luận cũ.

| Kiểm tra mới | Kết quả |
|---|---|
| `.venv/bin/python -m pytest -q` | **460 passed, 2 skipped**, 28.07 giây; hai skip là fixture CodeQL opt-in |
| `MAXVERA_RUN_CODEQL_FIXTURE=1 .venv/bin/python -m pytest -q tests/integration/test_pipeline_codeql_fixture.py` | **2 passed**, 273.64 giây; extraction cross-file và CLI sandbox bảo toàn source snapshot. Tổng hai lượt là **462 test pass**, không còn test opt-in chưa được chạy trong bộ này |
| `.venv/bin/python -m ruff check .` | Pass |
| `.venv/bin/python -m mypy src` | Pass, 126 source files; phạm vi không bao gồm toàn bộ `maxvera` |
| `git diff --check` | Pass |
| `maxvera doctor` | Exit 0, Python 3.10.16, Landlock hoạt động; reproduction CodeQL 2.15.5 và research 2.26.2; không gọi mạng |
| Resume thật r4, cùng cấu hình và provider Groq | **Exit 0, 3.442 giây**; checksum index và call journal không đổi, calls vẫn là **5** |

Doctor không đặt provider override nên hiển thị default `akashml`; lệnh resume đặt `MAXVERA_OPENROUTER_PROVIDER=groq` đúng profile r4. Không dùng kết quả doctor để khẳng định route hiện đang live.

Kiểm tra artifact độc lập xác nhận toàn bộ checksum run và evaluator, hash nhãn/truth, DB inventory (150/154 critical files), source archive (3/3 và 118/118 main Java files) đều khớp. Cả 18 stage của hai case đều SUCCESS; error journal rỗng. Năm assessment hợp lệ và hai decoded flow có bằng chứng; ba verifier endpoint vẫn là `UNSUPPORTED_SPEC`. Candidate ID, score và rank trước LLM được giữ nguyên.

Đối chiếu lại **toàn bộ raw pool** với truth hiện tại vẫn cho 0 strong match và 0 location match ở cả hai case. Recall@5 và verified known-CVE detection vẫn là **0/2**. Vì vậy, hoàn tất các stage không đồng nghĩa đã tìm được vulnerability cần tìm; reasoning/rerank không thể khôi phục candidate chưa được sinh ra. Reproduction artifact cũ vẫn ghi 67/120 failures, chưa có run sửa recovery mới.

Review source độc lập trong phạm vi DB/resume, Recall@K cutoff, soft rerank/no-flow, DNS và redaction không tìm thấy blocker nghiêm trọng mới. Đây không phải chứng minh không còn lỗi trên mọi đầu vào. Exact API-key scan không chạy lại trong lượt này; bằng chứng 4.781 files là của lượt trước.

Bằng chứng resume mới: `logs/research_smoke_20261022/recheck_after_crash_resume.json`. Bước kỹ thuật tiếp theo là thiết kế coverage generator theo quy tắc generic, khóa thiết kế trước khi triển khai và kiểm tra graph-only; không dùng vị trí truth của hai smoke case làm luật trong analyzer.

Audit tiếp sau đó đã tái lập thêm lỗi ngoài phạm vi review ban đầu: [research audit](research_audit_2026-10-22.md). Ngày 22/10, cleanup từng giữ r4 và bản tóm tắt. Ngày 23/10, người dùng yêu cầu không giữ output nào của run cũ; r4, evaluator, log và các bản tóm tắt machine-readable cũng đã xóa. Các con số phía trên mô tả kết quả tại thời điểm chạy.
