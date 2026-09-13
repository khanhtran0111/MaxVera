# Decision Log

**Mục đích:** ghi quyết định làm thay đổi khả năng tái lập hoặc diễn giải kết quả.

## D-001 — Freeze protocol 1.0.0 (2026-08-26)

Khóa Java + CodeQL, RQ1-RQ6, evaluation units, B0-B9 classification, label
firewall, budget, metrics, statistics và publishability gates theo
`00_RESEARCH_SCOPE.md` và `01_EXPERIMENT_PROTOCOL.md`.

## D-002 — Hai CodeQL toolchain độc lập (2026-08-26)

Reproduction dùng IRIS `codeql-0.8.3-patched`; main study dùng CodeQL bundle
2.26.2 với `codeql/java-queries@1.11.7`. Kết quả giữa toolchain không trộn. SHA
của legacy ZIP không có trong release API nên đã được tính trực tiếp:
`e61633fa05ee291ba01cdaa36bbe96acfe83ca3e6aa6b77b06406abb24cec094`
(807,846,025 bytes); archive listing đã được kiểm tra trước khi khóa.

## D-003 — Inference profile ban đầu, đã superseded (2026-08-26)

Inference profile cục bộ ban đầu dùng context 8K và xử lý tuần tự từng project.
Quyết định này đã bị thay thế hoàn toàn bởi GPT-OSS 20B/OpenRouter ở D-009 và
D-010; không output nào từ profile cũ được giữ hoặc dùng làm kết quả khoa học.

## D-004 — License chưa được chủ sở hữu chọn (2026-08-26)

Không tự cấp open-source license. Root `LICENSE` giữ all-rights-reserved cho đến
khi copyright holder chọn license; third-party giữ nguyên terms riêng.

## D-005 — Group split 80/20 và opaque project ID (2026-08-27)

`D_extended` dùng 80% development và 20% test-locked, phân theo toàn bộ nhóm
`github_username/github_repository_name`. Thứ tự nhóm được khóa bằng SHA256 của
seed `1234` và group key, không phụ thuộc phiên bản Python hay thứ tự CSV.
Analyzer chỉ nhận `proj_<20 hex>` sinh từ dataset ID, revision và upstream slug;
mapping repository/CVE/CWE chỉ tồn tại trong evaluator-only view. Protocol vẫn
ở `1.0.0` vì tỷ lệ là tham số Phase 2 còn bỏ ngỏ đã được khóa, không thay đổi
evaluation unit hay data track.

## D-006 — Public exact-version JDK archives trên SSH host (2026-08-28)

Oracle JDK 7u80/8u202 archive yêu cầu interactive Oracle account nên không thể
tái tạo tự động trên SSH host. Phase 2 dùng Azul Zulu Community Availability
OpenJDK đúng update `7u80` và `8u202`, lấy qua Azul Metadata API/CDN với SHA256
pin; JDK 17 vẫn dùng Oracle GA archive với SHA256 chính thức. Đây là thay đổi
vendor có kiểm soát, không thay Java update level. Vendor, URL, archive hash và
`java -version` thực tế phải nằm trong toolchain manifest; reproduction report
phải nêu khác biệt với Oracle binaries mà upstream README đề xuất.

## D-007 — Chọn D_smoke theo build ổn định (2026-08-29)

`D_smoke` giữ một project thành công cho mỗi CWE có trong `D_repro_v1`. Trong
mỗi CWE, project có `codeql_seconds` nhỏ nhất trong status Phase 2 được chọn;
tie-break bằng opaque `project_id`. Manifest phân tích chỉ giữ bốn ID mờ và
đường dẫn source/database, không chứa CWE/CVE. Đây là test kỹ thuật, mọi output
pass/fail đều bị cleanup và tuyệt đối không được promote thành kết quả khoa học.
Protocol vẫn ở `1.0.0` vì quyết định này chỉ materialize track `D_smoke` đã định
nghĩa, không thay đổi dataset hoặc metric chính.

## D-008 — Phase 4 tái sử dụng 104 CodeQL DB của Phase 2 (2026-08-29)

Theo quyết định vận hành của chủ dự án, Phase 4 không build lại database bằng
IRIS CodeQL patched. Thử tương thích xác nhận CLI patched (báo phiên bản 2.15.5)
không đọc được database tạo bởi CodeQL 2.26.2. Adapter vì vậy chạy IRIS queries
với CodeQL 2.26.2 và `codeql/java-all@9.2.2` trên 104 database thành công của
Phase 2; 16 project còn lại giữ nguyên failure status. Đây là **toolchain
substitution**, nên B1 không còn paper-compatible và báo cáo cấm claim exact hay
numerical reproduction. Raw IRIS stages, evaluator độc lập và public CSV vẫn
được giữ để đối chiếu phương pháp/tham khảo. Protocol version vẫn 1.0.0 nhưng
manifest từng run phải ghi rõ substitution này.

## D-009 — Chuyển toàn bộ run LLM mới sang GPT-OSS 20B/OpenRouter (2026-09-01)

Theo quyết định của chủ dự án, Phase 4 trở đi dùng duy nhất model ID
`openai/gpt-oss-20b` qua OpenRouter. Provider route được
khóa là `groq` theo snapshot endpoint ngày 01/09/2026; fallback bị tắt,
`require_parameters=true`, `zdr=true` và `data_collection=deny`. API key chỉ nằm
trong `.env`. Model hosted không có weight SHA do dự án kiểm soát, vì vậy
manifest thay bằng requested/returned model, provider route, request IDs,
resolved config, usage/cost và metadata snapshot. Các partial/pilot Phase 4 từ
backend trước quyết định này bị dừng và xóa, không được resume hoặc trộn với run
GPT-OSS. CodeQL database Phase 2 được giữ vì độc lập LLM. Protocol và baseline
matrix tăng từ `1.0.0` lên `1.1.0`;
RQ, dataset, split và evaluator không đổi. Output-token budget ban đầu vẫn giữ
1.024 tại quyết định này và được điều chỉnh riêng ở D-010 sau pilot.

## D-010 — Alias filesystem-safe và 2.048 completion tokens cho GPT-OSS (2026-09-01)

Pilot `phase4_gptoss20b_pilot_001` xác nhận OpenRouter/Groq hoạt động nhưng B2
fail. IRIS dùng tên model làm một phần tên file cache, nên model ID chứa dấu `/`
tạo path lồng không tồn tại. Adapter từ đây truyền alias
`gpt-oss-20b-openrouter` cho IRIS, trong khi request API vẫn khóa đúng
`openai/gpt-oss-20b`. Hai response API đầu của pilot cũng kết thúc với
`finish_reason=length`; reasoning dùng 720/1.024 và 281/1.024 completion tokens,
làm JSON bị cắt. Budget output được tăng lên 2.048, trùng giá trị paper công bố
và lời gọi active `max_new_tokens=2048` của IRIS. Failed pilot 001 không được
resume do resolved config thay đổi; pilot xác nhận mới dùng run ID 002. Protocol
và baseline matrix tăng từ `1.1.0` lên `1.1.1`; input budget, call cap, model,
provider, dataset, evaluator và RQ không đổi.

## D-011 — Khóa context adapters và spend-confirmation cho Phase 5 (2026-09-03)

B3 chọn Java chunks theo breadth-first round-robin giữa các file, không dùng
security-aware ranking. B4 dùng cùng chunker nhưng xếp hạng bằng vocabulary bảo
mật chung được version trong `src/baselines/context.py`. B3/B4 dùng chung prompt
`phase5-zero-hint-v1`, schema, model route và budget. B5 dùng cùng source view,
phát static hypothesis và không gọi LLM. Mọi LLM execution yêu cầu cờ
`--confirm-api-spend`; dry-run và budget estimator tuyệt đối không gọi mạng.

B3-B5 trước mắt chạy trên `D_repro_v1` để cùng release với B0-B2 Phase 4 và chỉ
là implementation-validation. Không dùng chúng làm main locked-test claim.
B6-B9 tiếp tục fail-closed vì phụ thuộc Phase 6-12; không tạo stub result giả.
Quyết định không đổi RQ, metric, model, budget hoặc protocol version `1.1.1`.

## D-012 — Chuyển Phase 5 và các run LLM mới sang AkashML (2026-09-03)

Theo quyết định của chủ dự án, B3/B4 Phase 5 và các baseline LLM triển khai về
sau dùng route OpenRouter `akashml` cho `openai/gpt-oss-20b`. Route được khóa
đồng thời trong upstream, model, experiment và baseline config; `.env` phải
khớp, fallback tiếp tục tắt, `require_parameters=true`, `zdr=true` và
`data_collection=deny`. Snapshot giá dùng cho estimator là `$0.02/M` input và
`$0.10/M` billed output tại ngày 03/09/2026; actual `usage.cost` của từng request
vẫn là số liệu chi phí có thẩm quyền.

Alternative giữ Groq bị loại vì chi phí cao hơn cho Phase 5. Kết quả Phase 4
đã hoàn tất bằng Groq không bị sửa hoặc chạy lại ngầm; chúng giữ protocol
`1.1.1` và config Groq riêng để có thể tái lập snapshot lịch sử. Vì provider
khác nhau, không được quy chênh
lệch B2/Groq với B3-B4/AkashML cho retrieval/model trong một so sánh
provider-controlled. Model, prompt, token budget, dataset, evaluator và RQ
không đổi. Thay đổi provider làm protocol và baseline matrix tăng lên `1.2.0`.

## D-013 — Validation-aware schema repair cho Phase 5 (2026-09-13)

Gate 20 project đầu tiên cho B3 pass 20/20, nhưng B4 chỉ pass 19/20. Project
`proj_9473477120ad15346b26` trả một file path không tồn tại và lặp lại cùng lỗi
qua ba response vì repair prompt cũ chỉ báo chung rằng JSON không hợp lệ. API,
model và AkashML route đều trả response thành công; đây là lỗi repair contract.

Prompt `phase5-zero-hint-v2` từ đây đưa thông báo validation đã giới hạn độ dài
vào repair turn, yêu cầu sao chép chính xác file/line từ evidence và cho phép
trả mảng rỗng nếu không còn hypothesis được hỗ trợ. Nhiệm vụ zero-hint, system
prompt, model, provider, context selection và budget không đổi. Prompt hash nay
bao phủ system, user và repair templates. Artifact attempt 001 được giữ nguyên;
mọi gate mới dùng run ID mới và không trộn prompt version. Protocol/matrix tăng
từ `1.2.0` lên `1.2.1`.

## D-014 — Structured Outputs khóa file path theo context (2026-09-13)

Targeted repair check v2 đã sửa được path ở lượt thứ hai, nhưng gate20 attempt
002 vẫn lặp cùng path sai qua ba response cho cùng project. Vì hành vi sampling
của hosted route không hoàn toàn deterministic, prompt-only repair không đủ làm
gate tái lập được. File thật có mặt trong context, nhưng model đổi `src/test`
thành `src/main`.

Phase 5 từ đây dùng OpenRouter Structured Outputs với `strict=true` và JSON
Schema động: `file` là enum chính xác của các path có trong context, các field
còn lại bị khóa type/range/cardinality, và local parser vẫn validate file/line
lần hai. `require_parameters=true` giữ fail-closed nếu provider không hỗ trợ
schema. Không bật response healing và không tự động sửa đường dẫn model trả về.
Prompt/request contract tăng thành `phase5-zero-hint-v3`; protocol/matrix tăng
từ `1.2.1` lên `1.2.2`. Các attempt v1/v2 được giữ làm failed diagnostics và
không trộn với run v3.

## D-015 — Bounded rate-limit backoff cho AkashML (2026-09-13)

Gate20 attempt 003 dùng Structured Outputs nhưng B3 dừng ở 19/20 vì một project
nhận bốn HTTP 429 liên tiếp trong khoảng 14 giây. Không có response model hoặc
API cost cho project đó; lỗi do transport retry 1/2/4 giây quá ngắn, không phải
schema hay analysis. Các project trước và sau đều thành công.

Client từ đây ưu tiên header `Retry-After` với trần 60 giây; nếu provider không
trả header, 429 dùng backoff 5/10/20/40/60 giây. `max_retries` tăng từ 3 lên 5,
mọi delay được ghi vào call log. Retry vẫn bounded và không làm tăng successful
call/token budget; model, prompt v3, schema, provider và scientific task không
đổi. Protocol/matrix tăng từ `1.2.2` lên `1.2.3`; attempt 003 giữ làm failed
diagnostic và gate mới phải dùng run ID mới.

## D-016 — Final analysis failures được tính là miss (2026-09-13)

Full B3 `p5_akashml_bm_full_001_b3` hoàn tất status cho 120/120 project: 119
`SUCCESS` và một `ANALYSIS_FAILED` sau sáu HTTP 429 có bounded backoff. Runner
đã giữ đúng `STATUS=FAILED`, nhưng validator cũ yêu cầu all-success và suite
fail-fast trước B4/B5. Hành vi đó mâu thuẫn với protocol đã khóa: primary
intention-to-analyze phải tính build/analysis failure là miss và Phase 5 gate
chỉ yêu cầu 100% project có final status.

Từ đây validator chấp nhận `STATUS=FAILED` chỉ khi mọi selected project có final
status, ít nhất một selected project thực sự failed, resolved config khóa
`failures_count_as_miss: true`, evaluator giữ failure là zero-alert miss, và
aggregate khớp project statuses. Kết quả được ghi rõ
`PASS_WITH_ANALYSIS_FAILURES`, không đổi failure thành success. Leaderboard công
bố run status cùng số selected success/failure. Suite tiếp tục baseline kế tiếp
sau exit khác 0 và hỗ trợ `--skip-existing` để tiếp tục immutable prefix.

Alternative chạy lại riêng project 429 bị loại vì sẽ condition kết quả trên
thành công và làm sai intention-to-analyze; alternative loại cả run bị loại vì
drop một project đã được protocol yêu cầu giữ. Đây là sửa implementation để
khớp policy có sẵn, không đổi RQ, dataset, model, budget, metric hay protocol
version `1.2.3`.

## Quy trình thay đổi

Decision mới phải ghi ngày, lý do, alternatives, impact, protocol version và
config/result bị ảnh hưởng. Không sửa ngầm RQ, split, budget, model, tool, metric
hoặc threshold.
