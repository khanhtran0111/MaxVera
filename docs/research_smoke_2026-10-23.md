# Kiểm tra và smoke ngẫu nhiên MaxVera — 23/10/2026

**Kết luận: chưa fix hoàn toàn và chưa sẵn sàng chạy full.** Lượt cuối `research_smoke_20261023_r3` đã hoàn thành 18/18 stage trên đúng hai case ngẫu nhiên, trong **1.203,376 giây** (20 phút 3 giây), exit 0. Lỗi lấy evidence cuối path đã sửa. Vẫn còn lỗi tái lập Top-K giữa các lần build RocketMQ, một response LLM không hợp lệ và discovery Recall@5=0/2. Stage SUCCESS là trạng thái thực thi, không phải chứng nhận chất lượng phát hiện.

## Phạm vi

Theo yêu cầu mới: kiểm tra lại theo review, chọn thêm đúng hai case bất kỳ, xóa toàn bộ kết quả/log run cũ và nới giới hạn API khi cần. Pipeline được chạy là **MaxVera research `graph_llm_verify`**, gồm ingest → static extraction → graph → candidate generation → frozen Top-K → evidence retrieval → LLM → targeted CodeQL → final ranking. Không chạy lại full benchmark reproduction hoặc full 96-case research trong tác vụ này.

## Các lỗi đã sửa và kiểm chứng

1. Node mang cả source và sink nay giữ một complete candidate zero-edge, gộp attribution hai generator và vẫn tìm các endpoint khác. Regression fail trước sửa; CodeQL thật xác nhận inventory source=1/sink=1 và FLOW_FOUND tại cùng biểu thức.
2. Evaluator chấp nhận đúng singleton identity path này cho discovery/ranked recall; empty path thiếu hoặc sai endpoint vẫn chỉ là weak match. Một regression fail và năm negative case pass trước sửa, sau sửa cả sáu pass; matching policy tăng lên v2.2.
3. IRIS validation kiểm tra field/type theo đúng từng prompt; malformed semantic JSON không còn được coi SUCCESS chỉ vì parse được.
4. Parser IRIS trong worker không sửa nội dung string của JSON hợp lệ; URL, empty string và quoted text được giữ nguyên.
5. Context loop IRIS flush batch cuối ngay cả khi path cuối dùng cache hoặc bị heuristic ignore; negative endpoint pruning và positive-only label omission vẫn theo upstream.
6. Graph chỉ giữ node backed bởi file snapshot. Node Java ảo bên trong JAR có thật được loại ở ranh giới model trước candidate generation; archive hash và số node/file/edge bị loại được ghi rõ. Toàn bộ raw graph vẫn phải vượt validation; source dự án bị thiếu, path không an toàn/oracle và dangling endpoint vẫn gây lỗi.
7. Retrieval ưu tiên code ở endpoint graph và hai đầu static path trước context. Không còn lấy riêng 10 vị trí đầu rồi bỏ cuối path mà báo chưa truncation. Mọi cutoff theo số lượng, byte hoặc snippet đều ghi `retrieval_truncated`; graph metadata không chiếm hết chỗ của code. Hai regression đều fail trước sửa, pass sau sửa. Replay đọc output r2 chứng minh cả 10 candidate có code tại vị trí đầu/cuối và prompt dưới 8.192 byte; không sửa artifact đã freeze, không đọc nhãn hoặc gọi API trong replay.

Không sửa checkout `third_party` đã pin. Các thay đổi compatibility được ghi trong artifact riêng ở worker, là deviation có khai báo so với parser/loop gốc. Batch bisection và giao thức completeness có nhãn NONE chưa được triển khai; không coi omission trong prompt positive-only hiện tại là lỗi missing-ID.

Kiểm chứng cuối trước r3: **500 default tests pass, 3 opt-in CodeQL tests skipped**, 24,07 giây; Ruff pass; mypy pass 126 file thuộc phạm vi `src`; diff whitespace check pass. Riêng test CodeQL identity mới đã chạy opt-in và pass trong **201,22 giây**, không gọi model hoặc dùng benchmark case. Hai fixture CodeQL opt-in cũ không chạy lại ở lượt này; smoke trên hai repository thực hiện kiểm tra end-to-end riêng. Kết quả này không bao hàm mọi khả năng của full reproduction.

## Kết quả lượt cuối r3

| Kiểm tra | RocketMQ | Spring Security |
|---|---:|---:|
| Stage SUCCESS | 9/9 | 9/9 |
| Thời gian case | 808,410 giây | 388,315 giây |
| Raw → giữ Top-5 → final | 396 → 5 → 5 | 424 → 5 → 5 |
| Assessment hợp lệ về schema/citation | 4/5 | 5/5 |
| Verifier | 4 NO_FLOW_FOUND, 1 UNSUPPORTED_SPEC | 5 UNSUPPORTED_SPEC |
| Discovery khớp nhãn tại Top-5 | 0/1 | 0/1 |

API có **10 HTTP200**, đúng `openai/gpt-oss-20b` qua Groq, tất cả finish=`stop`, mỗi request chỉ một attempt; không có rate-limit, output truncation hoặc unknown cost. Tổng usage **19.555 input / 3.034 output tokens**, chi phí **$0,002376825**. Không có lý do tăng output cap hoặc đổi provider từ kết quả này; local headroom đã được tăng như mô tả bên dưới.

Một response RocketMQ trích ID không có trong bundle (`code-86f33b2d226da2903013b45e`); bundle có ba evidence ID, response chỉ trích một ID. Đây không phải giới hạn số citation hoặc quota. Validator từ chối, giữ candidate ở UNCERTAIN và không bỏ khỏi final. Chín assessment còn lại chỉ được xác nhận đúng schema/trích dẫn, không được coi là chín phán quyết đúng về bảo mật.

Bốn cặp endpoint thực thi resolve source=1/sink=1, chạy tổng tám query và đều không tìm thấy modeled flow. Sáu candidate còn lại thiếu endpoint graph tường minh; không đoán endpoint để làm query pass. Không có FLOW_FOUND; NO_FLOW_FOUND/UNSUPPORTED_SPEC đều không chứng minh code an toàn.

Evaluator chạy riêng sau khi r3 freeze: **discovery Recall@5=0/2**, **verified detection=0/2**, aggregate **ranked Recall@5=null**, một trong hai case có rerank đầy đủ. Không ước lượng precision/FDR/F1 khi chưa adjudicate negatives. Top-5 miss không phải kết luận về toàn bộ 820 raw candidates; đây là smoke trên development data, không phải held-out benchmark.

Resume với cùng code/config/input đã pass: **15.315 file không đổi**, checksum index và paid journal không đổi, tổng vẫn 10 API attempts. Scan 40.009 file thuộc run/evaluator/log chuẩn bị không thấy API key. Các con số này thuộc lúc xác minh trước khi xóa bản sao chuẩn bị tạm.

Audit độc lập xác nhận checksum toàn run, 174/170 DB critical files, 2.880 dependency hashes và mọi bất biến candidate/evidence/rank. Cả 10 bundle có code tại anchor đầu/cuối và endpoint graph tường minh khi có; mọi truncation được ghi đúng. Prompt lớn nhất **7.343/8.192 byte**. Archive compiler-scope vẫn đạt RocketMQ 1.061/1.062 (thiếu duy nhất package documentation), Spring 828/828. Checksum index SHA256: `67f8011f02c6903290dc9157e1fb75d0e58fa62b9efd8536660d8d6bb7cdbfb9`.

## Lỗi còn mở trước full

**P0 — thứ tự hòa điểm chưa tái lập giữa các build RocketMQ.** Hai lượt dùng cùng commit và Java source; inventory analyzed có cùng 3.402 path nhưng 40 hash khác: 14 `pom.properties` chứa timestamp và 26 compiler `inputFiles.lst` chứa đường dẫn r2/r3 tuyệt đối. Không có hash Java khác. `static_extract` lấy digest toàn bộ inventory này làm analyzed snapshot ID; node/candidate ID đổi theo snapshot; `rank()` dùng candidate ID để hòa điểm. Kết quả là static candidate đứng thứ năm đổi từ path BatchProducer sang path TLS, dù không đổi model hay score rule. Bất biến frozen trong từng run vẫn pass, nhưng điều đó không đảm bảo cùng Top-K giữa các run. **Lỗi này đã xác nhận, chưa sửa trong tác vụ kiểm tra này**; cần tách identity của source/model khỏi metadata build biến động hoặc dùng khóa hòa điểm semantic ổn định, có regression giữa hai workspace, trước khi so sánh variant/full.

Không suy ra tác động riêng của bản sửa retrieval bằng cách so trực tiếp r2/r3: Top-K RocketMQ đã đổi như trên. Bản sửa được kiểm chứng riêng bằng regression RED→GREEN, replay đọc r2 và kiểm tra endpoint trên output mới.

Các gate khác vẫn thiếu: LLM chưa đạt 100% schema/citation trên smoke; chất lượng candidate/flow còn yếu; 92/96 development source chưa chuẩn bị. Full reproduction cũng chưa được kiểm chứng lại sau adapter repair; batch bisection/completeness và fidelity CodeQL so với phiên bản paper vẫn là phần chưa hoàn tất. Giữ `graph_signal_approved: false`.

## Lượt đầu và lý do chạy lại

`research_smoke_20261023` kết thúc `COMPLETED_WITH_CASE_FAILURES` sau 960,154 giây; **0 LLM calls**. Cả hai DB/static extraction SUCCESS và DB integrity hợp lệ. RocketMQ có 251.758 node rows/131.537 edge rows, vượt bound 200.000; bound được tăng lên **500.000 node** trong profile smoke và profile research chính, không tăng edge bound 1.000.000. Spring có 165.462 node rows/83.245 edge rows nhưng 60.898 dòng thuộc 365 virtual Java source paths trong Mockito/OpenID JAR, không phải source file của workspace.

Fix boundary được tái lập trên artifact Spring: giữ 104.564 source nodes/50.401 edges; ghi nhận 60.898 raw node rows, 60.886 normalized nodes và 32.844 incident edges nằm ngoài model source-backed. Không dùng cutoff này để xóa candidate vì phán quyết âm. Source-backed filtering có thể bỏ flow qua implementation thư viện; đây là giới hạn được báo cáo, không phải khẳng định dependency an toàn.

R2 chạy lại toàn bộ stages trên cùng hai snapshot, chỉ warm CodeQL compilation cache theo content hash; không copy checkpoint, graph/finding hay paid journal của lượt đầu. Lượt đầu đã được dọn cùng raw log/cache, thu hồi thêm 1.088.516.096 byte.

R2 hoàn thành 18/18 stage trong 1.290,941 giây. Candidate RocketMQ 396→5→5; Spring 424→5→5. Có 10 HTTP200, đúng model/provider, không retry, chi phí $0,0021723. Chỉ 9/10 assessment hợp lệ về schema/trích dẫn: một response sửa sai một evidence ID nên bị giữ ở UNCERTAIN. Một response khác dùng SUPPORTED trong khi rationale nói code an toàn; validator schema không chứng minh đúng nghĩa. Không có căn cứ quy các lỗi này cho API quota.

Verifier r2 có 4 NO_FLOW_FOUND và 6 UNSUPPORTED_SPEC: bốn cặp endpoint đều resolve 1/1, chạy tổng tám query nhưng không có flow; sáu static-alert candidate không có endpoint graph tường minh. Đánh giá nhãn sau freeze: discovery Recall@5=0/2; verified detection=0/2; aggregate ranked recall=null do một assessment không hợp lệ. Top-5 miss không chứng minh toàn bộ raw pool miss. Resume r2 không đổi bất kỳ file nào trong 15.301 file, không phát sinh API call; scan key trong 39.987 artifact/log không thấy API key. Audit tiếp theo mới phát hiện lỗi evidence cutoff ở 4/6 static path, dẫn đến bản sửa và r3; không dùng kết quả r2 để tuyên bố full-ready.

## Chọn case trước khi xem truth

`random.Random(20261023).sample(sorted(eligible), 2)` trên **94** development IDs: tập 96 case hiện có trừ hai case smoke cũ. Không chọn lại nếu case build/phân tích thất bại. Lựa chọn được lưu trước khi đọc metadata chuẩn bị từng case. Labels/fix locations chỉ được mở để evaluate sau khi output tương ứng freeze; analyzer/LLM không đọc chúng. Người audit đã thấy evaluation r2 trước khi sửa retrieval và chạy r3: r3 là engineering recheck trên development cases đã xem, không phải một lần đánh giá blind mới. Bản sửa dựa trên cutoff mất endpoint độc lập với nhãn.

| Opaque ID | Repository / commit | Recipe |
|---|---|---|
| `proj_5c0d1e85426e676fb0fa` | RocketMQ, `db4ba459bec9392ac37647ff1a4d24d30466814d` | JDK 8u202, Maven 3.5.0, clean package theo default reactor, offline dependencies |
| `proj_5d26b10d499ec06333c3` | Spring Security, `beb0ec4ba95265a7e3481b3eb8d87f3b922733ae` | Cùng toolchain; bỏ Bundlor packaging plugin không tải được từ bảy POM, giữ nguyên Java source và reactor |

Mỗi snapshot qua hai lần clean package liên tiếp trong Landlock với HOME/TMP riêng, không đọc `.env` hoặc Maven cache người dùng. Dependency cache được hash-bound và kiểm tra SHA256 từng file trước khi sao chép vào repository Maven riêng của build. Cache chứa 2.129/751 file cho hai case.

Coverage build cần phân biệt: RocketMQ có 1.063 checked-in Java nhưng default reactor compile **778 main + 284 test = 1.062**; một file thuộc `src/main/test` không chuẩn không được compile. Spring có 998 Java nhưng compile **515 main + 313 test = 828**; 170 file thuộc samples/sandbox/adapters/itest và một `src/main/test` ngoài scope default. Tất cả các file ngoài scope vẫn ở snapshot, không bị loại để làm smoke pass. Audit r2 xác nhận archive RocketMQ có 1.061/1.062 compiler inputs; file thiếu duy nhất là package-info.java chỉ chứa package documentation. Spring đủ 828/828. Source đã archive khớp hash snapshot.

## Cấu hình và lệnh

Profile `configs/pipelines/research_smoke_random.yaml` dùng GPT-OSS-20B/Groq, temperature 0, top-p 1, reasoning low, output cap 2.048; giữ Top-5/case. Headroom mới: **60 attempts, 1.000.000 input reservation, 122.880 output reservation, ngưỡng dừng $1/case**; 7.200 giây/case và runtime, 900 giây/query. Smoke tối đa hai case, 120 attempts/$2 theo dry-run. Dollar threshold không phải prepaid cap phía provider; uncertain-charge attempt không được retry tự động.

```bash
MAXVERA_OPENROUTER_PROVIDER=groq .venv/bin/python -m maxvera pipeline research \
  --config configs/pipelines/research_smoke_random.yaml --mode smoke --limit 2 \
  --run-id research_smoke_20261023_r3 --execute --resume
```

Lệnh trên đã kiểm chứng resume, không gọi API thêm. Run ID là immutable; chỉ resume với cùng code/config/input. Muốn thực thi mới phải đặt run ID mới và bỏ `--resume`. Xem trạng thái bằng `.venv/bin/python -m maxvera status --run-id research_smoke_20261023_r3`; tmux đã kết thúc sau khi run hoàn thành. R3 chạy lại đủ DAG; chỉ CodeQL compilation cache được warm theo content hash. Đây là kiểm tra engineering sau sửa, không phải một thí nghiệm độc lập mới hoặc tune theo nhãn.

## Xóa output cũ và giới hạn full

Đã xóa toàn bộ output/log/cache run trước đó, gồm r4/evaluator cũ, 24 export result được Git theo dõi, lượt lỗi đầu và r2 đã bị thay thế. Xóa cả các bản sao source/dependency/build tạm dùng cho chuẩn bị smoke; giữ source snapshot và dependency cache hash-bound thật sự dùng để chạy lại. Chỉ còn run **r3**, evaluator r3 và log/audit của tác vụ hiện hành. `results/README.md` là tài liệu. Ba đợt cleanup của tác vụ này thu hồi khoảng **3,51 GiB**; ổ đĩa còn khoảng **300,30 GiB trống** sau khi giữ output mới. Không cộng lại 240,5 GiB đã thu hồi ở lượt trước.

Source/config/test, dataset inputs, secrets, Python environment và toolchains được giữ. Các báo cáo lịch sử trong docs chỉ ghi nhận sự kiện, không chứng minh raw run đó còn tồn tại. Bằng chứng của tác vụ mới nằm tại `logs/research_smoke_20261023/`.

Doctor với Groq override pass: Python 3.10.16, Landlock hoạt động, research CodeQL 2.26.2, reproduction binary thực báo 2.15.5. Full graph-only dry-run chọn đúng **96** development cases và không gọi model. Tuy nhiên hiện chỉ có source directory cho **4/96 case**, còn 92 thiếu; LLM full vẫn cần reviewed frozen graph signal. Chưa thể trình bày full research là đã sẵn sàng chỉ từ smoke hai case hoặc lệnh dry-run.

Artifact còn lại:

- Run: `results/_smoke/research/research_smoke_20261023_r3/`.
- Evaluation: `results/evaluations/research_smoke_20261023_r3/zero_hint/`.
- Audit: `logs/research_smoke_20261023/inspection_frozen_r3.json`, `evidence_endpoints_frozen_r3.json`, `resume_verification.json`, `secret_scan.json`, `validation_final.json`.
- Chuẩn bị/cleanup: selection, source/dependency inventories, packaging adaptation diff và ba cleanup ledger trong cùng thư mục log. Chẩn đoán metadata/tie-break mới được ghi tại `r2_r3_candidate_semantics_audit.json`; raw run/evaluator/log r2 đã xóa theo yêu cầu.
