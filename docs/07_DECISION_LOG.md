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

## D-017 — Phase 6 development-only static-first hypothesis contract (2026-09-14)

Phase 6 dùng `D_extended/development` gồm 96 opaque project; 24 project
`test_locked` bị runner và validator cấm. Generator static v1 trích external
input, public boundary, source/sink và sanitizer bằng versioned Java patterns,
sau đó tạo Top-10 hypothesis có source/sink candidates, precondition, grounded
location, score và rule/source provenance. Evidence literal dạng CVE/CWE trong
source bị redacted và không tham gia matching/ranking.

Hai frozen data releases dùng opaque ID khác nhau; 110 row có cùng
project/revision và 10 row D_extended có corrected commit metadata.
Data-preparation boundary tạo alias cho revision trùng, fetch/checkout đúng
corrected revision cho 10 row còn lại và áp upstream build patch nếu có;
analyzer chỉ thấy opaque target ID và không nhận mapping identity. Alternative
clone/build lại toàn bộ release bị loại vì tốn tài nguyên; alternative để
analyzer đọc canonical manifest bị loại vì phá label firewall.

LLM là optional `hybrid` reranker: Structured Outputs chỉ cho phép permutation
đúng tập static hypothesis ID, tối đa một successful call/project, route
`openai/gpt-oss-20b`/AkashML và không fallback. Static là bước canonical đầu tiên
và có zero API cost. Evaluation chỉ ở process có role evaluator, báo
Recall@1/3/5/10 và MRR; failure tính là miss. Chi tiết này khóa protocol Phase 6
ở `1.3.0`; Phase 5 artifacts/matrix tiếp tục giữ snapshot `1.2.3`.

## D-018 — Family-balanced static ranking và candidate-pool diagnostic (2026-09-14)

Full development run static v1 `p6_static_dev_full_001` đã pass validator trên
96/96 project, đạt Recall@1/3/5/10 lần lượt 0.3333/0.4479/0.5208/0.5625 và MRR
0.4020. Audit zero-hint sau khi run kết thúc cho thấy candidate đúng xuất hiện
trong pool Top-40 ở 68/96 project, nhưng Top-10 bị lệch về CWE-22: trong 42
Top-10 miss có 14 candidate đúng ở rank 11–40 và 28 không có trong pool. Đây là
vấn đề ordering/coverage có thể tách riêng trước khi dùng LLM reranker.

Static ranking v2 giữ nguyên signal patterns, score và maximum 40 candidates,
nhưng interleave theo depth giữa các CWE family: lấy candidate tốt nhất của mỗi
family trước candidate thứ hai của mỗi family, với score và stable key làm
tie-break trong từng layer. Evaluator bổ sung candidate-pool Recall@40 và MRR để
phân biệt lỗi retrieval khỏi lỗi Top-10 ranking; primary Top-k metrics không đổi.
Artifact v1 là immutable và validator tiếp tục hỗ trợ manifest v1 không có
`ranking_version`; run v2 phải khai báo `phase6-family-balanced-v2` xuyên suốt
manifest/candidates/hypotheses. Alternative gọi hybrid ngay bị hoãn vì chưa đo
được phần lợi ích miễn phí của static reranking. Protocol tăng từ `1.3.0` lên
`1.3.1`; dataset, split, signal patterns, Top-10, model route và budget không đổi.

## D-019 — Khóa Phase 6 static v2 và Top-k=10 (2026-09-14)

Full development run `p6_static_v2_dev_full_001` tại commit
`6483e10aaa59a63a0811900430dc16d8b174871c` pass validator với 96/96 analysis
success và zero LLM/API call. Recall@1/3/5/10 là 32/79/84/84 trên 96
(0.3333/0.8229/0.8750/0.8750), MRR 0.5546875; candidate-pool Recall@40 là
84/96 và candidate-pool MRR cũng là 0.5546875. So với static v1, v2 chuyển 30
project từ Top-10 miss thành hit, không gây Top-10 regression; 12 project còn
lại không có candidate đúng trong pool Top-40.

Từ đây `phase6-family-balanced-v2`, static generator và Top-k=10 được khóa cho
các phase downstream. Hybrid không được chọn làm canonical vì strict reranker
không thể tăng coverage cho 12 pool miss; nếu chạy sau này chỉ được ghi là
exploratory ranking ablation và không thay khóa này. Manifest SHA-256 là
`11380495eafffe02924beaf9409e7ed343111cc4b74806a4f869e5155b41d2c2`; aggregate
metrics SHA-256 là
`563b8ed230c3d3d9fbd7b6ba377f618b701e9f9fc047f274b5f8f5a05f7909ad`.
Quyết định này hoàn tất gate Phase 6 nhưng không đổi protocol `1.3.1`; dataset,
split, metrics và locked-test firewall giữ nguyên.

## D-020 — Phase 7 source-backed CodeQL Program Graph (2026-09-14)

Phase 7 dùng khóa Phase 6 D-019 và chỉ chạy trên 96 opaque development IDs.
Extractor v1 dùng CodeQL CLI 2.26.2 cùng `codeql/java-all@9.2.2` để trích node
`EXPR/STMT/CALLABLE/TYPE` và bảy edge kind: AST parent, call, def-use, data-flow,
control dependency, type và taint candidate. Node ID được hash từ project ID,
kind, source span, symbol/type descriptor; edge ID được hash từ kind và hai
endpoint. Raw code và
label/advisory/fix metadata không được ghi vào graph. Để bounded trên repository
lớn, graph giữ node trong các file được locked Top-10 hypothesis tham chiếu và
một endpoint kề qua CodeQL edge; scope này dùng source evidence, không dùng
evaluator label. Mỗi node/edge giữ query hash, extractor/tool version và
source-backed provenance.

Database preparation chỉ alias Phase 2 database khi repository revision giống
hệt, ở boundary được phép đọc canonical manifest nhưng chỉ persist opaque
availability. Snapshot hiện tái sử dụng 76/96 development databases; 20 database
thiếu có builder riêng dùng analysis-only manifest và pinned toolchains. Database
hoặc query failure được giữ `ANALYSIS_FAILED`, không thay bằng source-regex graph
vì fallback đó sẽ làm sai semantics CodeQL. Full run vẫn phải có đủ 96 final
statuses theo intention-to-analyze.

Graph validator yêu cầu source location tồn tại, deterministic ordering/digest,
provenance, checksum và edge-reference ratio tối thiểu 99%. Neighborhood,
forward slice và backward slice là bounded-hop traversal deterministic, có unit
test. Phase 7 không gọi LLM/API. Alternative materialize full AST bằng parser bị
loại vì không cung cấp CodeQL def-use/data-flow; alternative truy cập locked-test
để tăng coverage bị cấm. Contract mới tăng main protocol từ `1.3.1` lên `1.4.0`;
khóa Phase 6 và artifact cũ giữ nguyên protocol lịch sử.

## D-021 — Phase 7 failure-state and timeout hardening (2026-09-15)

Hai full attempt đầu tiên làm lộ hai implementation defects ở failure boundary.
Full 001 có một CodeQL query trả graph rỗng nhưng runner ghi `SUCCESS`, trái với
validator và gate D-020 yêu cầu successful graph phải có source-backed node.
Query timeout của cùng run chỉ dừng wrapper process, để lại query Java mồ côi giữ
IMB database-cache lock; do đó full 002 thất bại sớm trên database đó. Cả hai run
đủ 96 final statuses và checksum hợp lệ nhưng không được chọn làm canonical vì
validator từ chối zero-node success.

Runner nay coi graph không có node sau seed filtering là `ANALYSIS_FAILED`, chạy
mỗi CodeQL command trong process group riêng, gửi TERM rồi KILL toàn group khi
timeout, persist timeout log, và kiểm tra active cache lock trước query. Không
xóa lock file trong lúc owner process còn sống. Unit test bao phủ zero-node
classification, descendant cleanup và cache-lock rejection; regression pilot
trên chính zero-node project được validator chấp nhận dưới intention-to-analyze.

Đây là conformance fix cho contract D-020, không đổi dataset, split, extractor
semantics, timeout, graph schema, metric hoặc failure-as-miss rule, nên protocol
giữ `1.4.0`. Manifest implementation hash sẽ phân biệt full run mới với 001/002.
Full 001/002 vẫn immutable và chỉ được giữ làm diagnosed attempts; candidate
canonical tiếp theo phải dùng run ID mới.

## D-022 — Phase 7 cohesive CodeQL location binding (2026-09-16)

Full 003 có đúng 80 graph success và 16 recorded analysis failures, nhưng
validator tìm thấy 52 node span không hợp lệ trên năm successful projects: 38
range bị đảo và 14 range vượt quá file nguồn. Checksums pass, vì vậy đây không
phải artifact corruption. Điều tra cho thấy một CodeQL element có thể trả nhiều
`Location`; node/edge query gọi độc lập `getFile()` và `getLocation()` cho từng
column, cho phép QL tạo Cartesian combinations giữa file, start và end của các
location khác nhau. Duplicate classes giữa module làm lỗi xuất hiện rõ hơn.

Node query nay bind `Location nodeLocation = node.getLocation()` và lấy toàn bộ
file/span từ đúng binding đó. Edge query làm tương tự với source và target. Runner
gọi per-project integrity validator trước khi ghi `SUCCESS`, khiến mọi location
không hợp lệ còn sót lại trở thành intention-to-analyze miss thay vì chỉ bị phát
hiện sau atomic finalization. Regression test khóa query binding và malformed
span rejection; pilot trên project từng lỗi pass validator với 1.653 nodes,
2.498 edges và 100% resolved references. Sau đó cả năm project từng có invalid
span đều được chạy regression pilot và pass validator, tổng cộng 22.400 nodes,
35.354 edges và 100% resolved references.

Đây là correction để thực thi source-backed location contract D-020, không đổi
dataset, split, graph schema, edge kinds, thresholds hoặc failure-as-miss rule;
protocol giữ `1.4.0`. Query và implementation hashes trong manifest phân biệt
candidate full mới. Full 003 giữ immutable, không được sửa hoặc chọn canonical.

## D-023 — Khóa Phase 7 Program Graph full 004 (2026-09-16)

Full development run `p7_pg_dev_full_004` tại clean commit
`13a60162949b0a297b51050cccf6ed5cd4fbd241` pass validator với đủ 96/96 final
statuses. Có 81 graph success; 15 intention-to-analyze misses gồm 14 project
không có CodeQL database và một project có graph rỗng sau seed filtering. Run
tạo 275.674 nodes, 442.786 edges và resolve 442.786/442.786 edge references
(100%). Project từng timeout ở full 001 đã thành công trong full 004 với 1.253
nodes và 1.961 edges. Phase 7 không gọi LLM/API.

`p7_pg_dev_full_004` được khóa làm canonical development Program Graph cho các
phase downstream. `STATUS=FAILED` phản ánh sự tồn tại của 15 recorded misses,
không phủ định scientific validity; gate authoritative là checksum pass, đủ 96
final statuses và validator `PASS_WITH_ANALYSIS_FAILURES`. Không được loại các
failure khỏi mẫu, sửa hậu kỳ artifact hoặc thay canonical bằng conditional
rerun. Các full 001–003 chỉ là immutable diagnosed attempts.

Canonical checksums:

- manifest: `ce5f1d61616f6b990d863f75f94cfca35926a0973a08d5051655d9f35ce2c832`;
- graph summary: `a70bc3bbea0b4e8387ceeff1e804ff259db9152f925de0812f94fd6aa73462b7`;
- project statuses: `bf297df86ad82ab692ddc802fad087846e2f3e05f1ee3a6df4dec35de131080a`;
- checksum index: `f01e903cc4cbcdd6b8575faefbfded00733269f51bb025c20c044023a1fa9ee4`.

Khóa này hoàn tất gate Phase 7 nhưng không đổi protocol `1.4.0`: dataset, split,
extractor semantics, graph schema, edge threshold và failure-as-miss policy giữ
nguyên. Mọi thay đổi Phase 8 phải dùng đúng canonical run/checksum này làm input
development và tiếp tục giữ `test_locked` đóng.

## D-024 — Phase 8 global, pinned Security Knowledge Graph (2026-09-17)

Phase 8 dùng một KG toàn cục versioned; per-project view được hoãn đến Phase 9 để
không nhân bản knowledge hoặc trộn source program với knowledge facts quá sớm.
Scope khóa bốn root `CWE-22/78/79/94` và mọi quan hệ incident một hop trong MITRE
Research Concepts view 1000. Không mở rộng đệ quy vì dataset hiện chỉ có bốn family
và closure rộng sẽ đưa knowledge chưa được development audit vào pipeline.

Ba nguồn được materialize tại preparation boundary rồi build hoàn toàn offline:

- MITRE CWE 4.20, published 30/04/2026, XML SHA-256
  `1f5a78bd62e00f86436b4fe32d5034a57e8f0da88e4063b2072b664ae510912e`,
  theo CWE Terms of Use;
- OWASP Top 10:2021 tại commit
  `66ebc4798d2ca72973967a20264bdeb70dcf0a13`, CC-BY-SA-4.0;
- CodeQL `codeql/java-all@9.2.2`, build commit
  `94101634db019b00637dd5cfe241f7e570da290d`, model-tree SHA-256
  `b466420b95d11f5ce74e3e503757f8c3a307bfa7531e13add068eca50fef817a`, MIT.

Schema v1 có node `CWE`, `OWASP_CATEGORY`, `SOURCE`, `SINK`, `SANITIZER`,
`PROPAGATOR`, `PRECONDITION`, `MITIGATION`; edge `RELATED_CWE`,
`MAPS_TO_OWASP` và các edge `HAS_*`/`MITIGATED_BY`. ID hash canonical không phụ
thuộc thứ tự input. Mỗi fact bắt buộc có URL, version, license, artifact checksum,
locator, extraction rule và confidence. Fact deterministic và LLM-inferred nằm ở
hai thư mục serialization riêng; canonical Phase 8 có zero LLM call và inferred
layer rỗng.

API semantics chỉ lấy CodeQL model không experimental và có provenance đã qua bước
manual (`manual`, `df-manual`, `ai-manual`, `hq-manual`). `manual`/`df-manual`/
`hq-manual` có confidence 1.0, `ai-manual` 0.9; upstream generated-only models bị
loại thay vì gọi là verified. Propagator bị bounded trong cùng model file có ít
nhất một source/sink/barrier liên quan. Sanitizer coverage hiện sparse và được giữ
trung thực, không sinh placeholder hay dùng LLM bù fact.

Runner chỉ đọc checksum/aggregate manifest của lock Phase 6 D-019 và Phase 7 D-023;
không đọc project hypothesis, program graph content, evaluator-only, advisory hoặc
`test_locked`. Validator kiểm exact source/dependency checksums, layer separation,
canonical ordering/ID, endpoint integrity, provenance của mọi fact, leakage string,
và sample đủ relation bắt buộc cho từng root CWE. Alternative scrape web lúc
analysis, dùng latest không pin, recursive related-CWE closure, per-project KG và
trộn LLM facts vào deterministic facts đều bị loại. Contract này tăng main
protocol từ `1.4.0` lên `1.5.0`; không đổi RQ, split, LLM budget, metric hoặc khóa
Phase 6/7.

## D-025 — Khóa Phase 8 Security Knowledge Graph full 002 (2026-09-17)

Full run `p8_skg_global_full_002` được tạo tại clean implementation commit
`50ed53ee5b99ce3adeae81fbbf9c41c33e4fe70a`; manifest ghi `git.dirty: false`.
Validator pass với 2.619 nodes, 5.285 edges, 7.904 deterministic facts, zero
LLM-inferred fact, zero LLM/network call trong build và audit `PASS` cho cả bốn
root CWE. Graph digest
`8685f50d8e5f3727aa8cba9361f739c58fc57fb3ba444d59a9577dc413fbc805`
khớp byte-for-byte về canonical fact content với pilot 002 và dirty-tree
diagnostic full 001, chứng minh builder tái tạo deterministic trên clean commit.

`p8_skg_global_full_002` được khóa làm canonical development Security KG cho
Phase 9 trở đi. Full 001 vẫn là immutable validated diagnostic nhưng không được
dùng downstream do provenance Git dirty; không được sửa hoặc thay full 002 bằng
conditional rerun. Exact lock checksums:

- manifest: `91ca35b8ee2b9f153ba8dedfe75a4e165231b5a3b86cc5219e7623a2497f270a`;
- KG summary: `85bff62c1c4e541885f411e8cde90060dcd9e063d09ff9c8bf98d5723b570308`;
- audit sample: `8cabf57e1e67e6946d6560ded5736e4c8c1e754c4b31323758f7b125f0f810f2`;
- checksum index: `a051e41e7e5194f25d3ac08f9654a30af6f7cab0e14846952cce0fb64cb8953c`.

Experiment config `phase8_security_kg.yaml` giữ nguyên byte content đã được
manifest pin; canonical selection metadata nằm trong `main.yaml` để không làm
mất khả năng validate artifact sau khi khóa. Quyết định này hoàn tất Phase 8,
không đổi protocol `1.5.0`, schema, scope, source policy, confidence hoặc leakage
firewall. Phase 9 phải pin đúng run/checksum trên, tiếp tục development-only và
không mở `test_locked`.

## D-026 — Phase 9 iteration-0 Evidence Graph và USEG (2026-09-17)

Phase 9 tạo một USEG development-only bằng exact lock Phase 6
`p6_static_v2_dev_full_001`, Phase 7 `p7_pg_dev_full_004` và Phase 8
`p8_skg_global_full_002`. Runner lấy tập 96 opaque project trực tiếp từ manifest
Phase 6, không đọc split/evaluator/advisory/patch hoặc `test_locked`; build dùng
zero LLM và zero network call. Mười lăm failure Phase 7 được truyền nguyên trạng
thành `ANALYSIS_FAILED`, không tạo partial/placeholder graph.

Schema `phase9-useg-v1` khai báo Evidence node `HYPOTHESIS`, `ASSERTION`,
`CODEQL_FINDING`, `TAINT_PATH`, `SANITIZER_EVIDENCE`, `CONTRADICTION`,
`VERIFICATION_RESULT`; Program và Security facts được nhập bằng reference node
giữ nguyên upstream ID. Edge bị giới hạn ở `SUPPORTS`, `CONTRADICTS`,
`VERIFIED_BY`, `DERIVED_FROM`, `MATCHES`. Mọi record có `analysis_iteration=0`,
artifact checksum và record-level provenance. Confidence là danh sách component
độc lập kèm basis; cấm aggregate confidence scalar để tránh gộp bằng chứng sớm.

Cross-layer mapping v1 dùng exact candidate-CWE identity; location assertion map
tới tối đa ba Program nodes cùng file và chứa line, ưu tiên exact symbol; API fact
map bằng exact symbol với callable/type trong đúng source/sink role của CWE;
precondition map qua quan hệ CWE membership. Mỗi hypothesis lấy tối đa 16
`TAINT_CANDIDATE` incident với Program node đã map. Các edge này chỉ được ghi là
`CODEQL_FINDING`/`TAINT_PATH` có status `unverified_candidate` và
`complete_path=false`; chúng không phải verified vulnerability. Finding/path,
assertion và reference đều có stable canonical ID/order.

`SANITIZER_EVIDENCE`, `CONTRADICTION` và `VERIFICATION_RESULT` chưa được
materialize vì upstream iteration 0 không có đủ evidence xác nhận; schema hỗ trợ
nhưng policy cấm bịa placeholder. Tương tự, Phase 9 có zero final finding nên gate
final-finding trace trả `PASS_NO_FINAL_FINDINGS_PHASE9`; Phase 11 phải materialize
verification thật và validator khi đó yêu cầu trace tới Program location,
Security fact và tool/model call.

Validator kiểm exact dependency/config/implementation checksums, 96 final status,
canonical IDs/order, resolved endpoints, record provenance, independent
confidence components, leakage strings, graph rebuild determinism, acyclic
dependency graph, lossless JSONL round-trip và trace Program+Security cho mọi
candidate path. Full candidate `p9_useg_dev_full_001` pass với 81/96 graph
success, 15 inherited misses, 7.527 nodes, 16.398 edges và 823/823 candidate
paths traceable; 0 cycle, zero LLM/network call. Hai successful projects không có
incident taint candidate phù hợp và được giữ ở 0 path thay vì sinh dữ liệu giả.
Manifest full 001 ghi Git dirty nên chưa được khóa canonical; cần clean commit và
full run ID mới. Contract tăng protocol từ `1.5.0` lên `1.6.0`, không đổi dataset,
split, budget, metric hoặc lock Phase 6–8.

## D-027 — Khóa Phase 9 USEG full 003 (2026-09-17)

Full run `p9_useg_dev_full_003` được tạo tại clean implementation commit
`2395d219789ad5401e1fecdb26cee9030208c19b`; manifest ghi `git.dirty: false`.
Validator trả `PASS_WITH_ANALYSIS_FAILURES` với đủ 96/96 final statuses: 81
graph success và 15 intention-to-analyze misses kế thừa nguyên trạng từ Phase 7.
Run có 7.527 nodes, 16.398 edges và 823/823 candidate taint paths truy được tới
cả Program location lẫn Security fact; dependency graph có zero cycle, JSONL
round-trip lossless, zero final finding và zero LLM/network call.

Graph digest
`918707ee3bbb59858b2b2d8dd9aafb762467f983bf579c97e35ba4191a1a41fa`
khớp full 001 và full 002. Hai run trước vẫn là immutable diagnostics nhưng không
được dùng downstream vì manifest đều ghi dirty worktree; full 002 được chạy khi
implementation đã stage nhưng chưa commit. `p9_useg_dev_full_003` được khóa làm
canonical development USEG cho Phase 10 trở đi. Exact lock checksums:

- manifest: `83dce921c979db710762bd205588c667033bc10fb6c64c4581fce9a8c84810c7`;
- USEG summary: `06c33ace27422141494a1287b612c59ceb3cdc0fd5ee4d2d2e1eddfb59300ff7`;
- trace audit: `838b8735d0c2cf8e9b2fa3100dc6d053bac72db8e03ef48837fc7d50a1420480`;
- project statuses: `37feda20d9f712d4343607b1f851cd00a83bb74b381bb1cf5de0310259645638`;
- project summaries: `755263d55a7da26dfae76151912be5039dd4169a3d0afab5bc9ef0d7e87e92bf`;
- checksum index: `45d1ed92e1a8f7adb365aa0bced3872f21e5815fe574a4d62838cb7747784235`.

Canonical selection nằm trong `configs/experiments/main.yaml`; experiment config
`phase9_useg.yaml` giữ nguyên byte content đã được manifest pin. Quyết định này
hoàn tất Phase 9 mà không đổi protocol `1.6.0`, schema, mapping, confidence,
failure-as-miss hoặc leakage policy. Phase 10 phải pin exact run/checksum trên,
tiếp tục development-only và không mở `test_locked`.

## D-028 — Phase 10 grounded retrieval và compile-only specification (2026-09-17)

Phase 10 pin exact canonical USEG `p9_useg_dev_full_003` và triển khai bốn
strategy dưới cùng prompt/schema/model/provider/budget: B6 giữ Evidence anchors
cùng Program layer; B7 giữ Evidence anchors cùng Security layer; B8 lấy toàn bộ
connected component của hypothesis mà không giới hạn hop/node; B9 dùng traversal
bốn hop, tối đa 80 node. Traversal là undirected trên dependency edges vì Phase 9
assertion/finding provenance hướng về hypothesis trong khi knowledge match hướng
ra ngoài. Mọi edge vẫn bị project-isolated, nên global Security node không được
dùng để kéo evidence từ repository khác.

Compact serializer giữ stable node/edge IDs và các thuộc tính cần cho synthesis,
ghi riêng structural pruning với serialization truncation. Context budget được
tính bảo thủ bằng UTF-8 byte estimate, có 3.072-token prompt/schema reserve và không
được vượt 8.192 input tokens/call. Mỗi project giữ tối đa 10 hypothesis; mỗi
hypothesis có một initial call và nhiều nhất hai repair, vừa đúng hard cap 30
calls/project. Runner kiểm actual provider usage với giới hạn 160.000 input
tokens/project; transport retries và mọi repair đều được log.

Strict Structured Output chỉ cho model chọn node ID có trong serialized context.
Program node, exact-role Security node hoặc Phase 6/9 location assertion đều có
thể làm grounded endpoint; Security fact sai role bị local validator từ chối.
Source và sink là bắt buộc. Nếu context không có candidate cho một role, runner
fail-closed trước API thay vì yêu cầu model bịa fact. Sanitizer/propagator chỉ
được ghi khi có node tương ứng; precondition phải cite context node.

Spec hợp lệ được render thành deterministic Java CodeQL query constraint và chạy
`codeql query compile --check-only` với CLI 2.26.2/`java-all@9.2.2`. Compile
success chỉ chứng minh query có cú pháp/type hợp lệ, không phải taint path hay
vulnerability verification. Tất cả output Phase 10 mang trạng thái
`SYNTHESIZED_UNVERIFIED`, zero final finding; B9 vẫn bị chặn bởi Phase 11 static
verification và Phase 12 calibration. Alternatives cho LLM tự trả file/symbol tự
do, dùng compile success làm verdict, hoặc dùng patch/advisory để repair đều bị
loại.

Contract này tăng main protocol từ `1.6.0` lên `1.7.0`; không đổi dataset,
split, model, provider route, token/call budget, evaluation metric hoặc khóa
Phase 6–9. Dry-run B6–B9 phải chạy trước API pilot, không gọi mạng; mọi API run
yêu cầu `--confirm-api-spend`, tuần tự một request và development-only. Full run
chỉ được khóa sau clean implementation commit, successful pilot, complete
project statuses, grounding/budget audit và final-query compile report.

Full-coverage dry 001 sau các one-project pilots cho thấy fixed context reserve
chưa đủ cho mọi strict-schema enum: conservative whole-request estimate vượt cap
ở một số context dù graph text riêng nằm trong cap. D-028 do đó yêu cầu adaptive
serialization deterministic: giảm budget chỉ cho context bị overflow, serialize
lại, dựng lại schema và lặp preflight với 128-token margin. Metadata lưu
`initial_token_budget`, final `token_budget` và `request_budget_adapted`; nếu
grounded role mất đi hoặc request vẫn quá lớn thì hypothesis fail trước API.

## D-029 — Khóa Phase 10 full development và annotated proxy gate (2026-09-20)

Bốn API full run B6–B9 được tạo tuần tự từ clean implementation commit
`184fef10ec629bee1f395c8961e051a44dcb38cb`, giữ đúng canonical Phase 9
`p9_useg_dev_full_003`, protocol 1.7.0, GPT-OSS 20B/AkashML và budget-matched
contract. Validator độc lập chấp nhận cả bốn với đủ 96 final statuses. B6/B7/B8/B9
lần lượt tạo 763/619/801/801 grounded specifications; mọi emitted final query
compile thành công. Project success là 54/34/78/78 trên 96; 15 misses downstream
ở mọi baseline kế thừa Phase 7/9 và các miss còn lại là fail-closed missing source.

Gate precision/recall đã được materialize bằng evaluator process riêng, không sửa
raw synthesis artifacts và không mở `test_locked`. Tập annotated gồm 91/96
development projects có fix-location record; 5 project không có annotation được
ghi rõ và loại khỏi proxy denominator. Specification được tính proxy-positive chỉ
khi candidate CWE khớp development label và ít nhất một grounded source/sink
location giao method, rồi class, rồi file fix scope. Đây là paper-compatible
fix-location proxy, không phải verified path, và không được dùng để sửa prompt,
retrieval hay specification sau khi quan sát kết quả.

Canonical evaluator run `p10_dev_spec_eval_003` được tạo từ clean commit
`6117b00b72bd6bca204c1cf33a1880d476836144`, validator pass và tái tạo byte-identical
aggregate so với hai diagnostic runs trước. Với B9, 762 specs thuộc annotated
subset, 254 có candidate CWE đúng, 14 proxy-positive và 6/91 project detected
(recall ITA proxy 0.065934). Kết quả thấp được giữ trung thực; Phase 11 phải chạy
CodeQL dataflow thật và không được gọi proxy này là vulnerability verification.

Exact evaluation locks:

- manifest: `e20c5c43d34bab7665c1f0411870c6e1c476d18eac80b9f965595e0b5874bbe6`;
- aggregate: `bd7161a9dd933dc90fe179161c0814eab934fce48246f750c182a63217053c23`;
- checksum index: `cf15847234351ce21c390879cedbbac56d351914e6fe9438a43f80b9e398bc5a`.

Quyết định này khóa Phase 10 cho Phase 11 development. Nó materialize gate đã có,
không đổi RQ, dataset, split, model, budget hay metric family nên protocol giữ
`1.7.0`. Bốn synthesis run và evaluator run là immutable; rerun phải dùng ID mới.

## D-030 — Phase 11 static path và vulnerable/fixed differential (2026-09-20)

Phase 11 dùng hai deterministic CodeQL queries cho mỗi frozen B9 specification:
endpoint inventory và Java global-taint `path-problem`. Query đầu phân biệt
descriptor không resolve với endpoint resolve nhưng không có flow; query sau lưu
full SARIF code flow. Sanitizer là barrier và propagator là additional flow step.
Compiler/query engine vẫn là CodeQL 2.26.2 với `java-all@9.2.2`.

Một vulnerable path đơn lẻ chưa phải verified finding. Trạng thái
`VERIFIED_DIFFERENTIAL` chỉ được cấp khi cùng frozen specification có path trên
vulnerable database và không có path trên fixed database. Mọi trường hợp còn lại
ghi explicit `UNVERIFIED_*` hoặc `ANALYSIS_FAILED`; LLM verdict bị cấm và Phase 11
v1 có zero LLM calls/tokens. Negative evidence, query attempts, resource usage và
USEG delta iteration 1 đều được persist/checksum.

Fixed DB preparation là evaluator-only: chỉ development IDs, kiểm split disjoint,
đọc fix revision rồi persist database/status bằng opaque project ID; không chuyển
commit ID, advisory hay identity mapping sang analyzer artifact. Vulnerable-only
pilot được phép để kiểm query/runtime nhưng không đủ điều kiện khóa Phase 11.

Loop v1 có đúng một iteration; tối đa 4 paths/spec và 40 query invocations/project.
Stop reason deterministic theo `EVIDENCE_THRESHOLD_MET`, `BUDGET_EXHAUSTED`, rồi
`NO_NEW_EVIDENCE`. USEG update chỉ thêm `VERIFICATION_RESULT`/`TAINT_PATH` và cạnh
không tạo cycle. Full run bắt buộc differential, clean worktree, toàn bộ 96 project
statuses và không cho subset/spec limit. Alternatives dùng compile success, LLM
verdict hoặc vulnerable-only path làm final finding đều bị loại.

Decision này tăng protocol `1.7.0` lên `1.8.0` vì thêm verifier, evidence threshold,
fixed-database boundary, iteration/stop policy và query budget mới. Phase 9/10
artifacts giữ historical protocol của chúng; main experiment tiếp tục `draft` cho
tới khi Phase 12 khóa calibration thresholds.

## D-031 — Phase 11 fixed-database failure accounting (2026-09-21)

Full fixed preparation tạo được 61/78 database và ghi 17
`CODEQL_DB_FAILED`. Preflight runner ban đầu lại yêu cầu đủ 78 database nên dừng
toàn bộ trước khi nhánh project-level `ANALYSIS_FAILED` có thể chạy. Điều này mâu
thuẫn với D-030 và primary intention-to-analyze: build/database failure phải là
miss có trạng thái, không được drop project và cũng không được vô hiệu hóa kết
quả của các project còn lại.

Runner và validator vì vậy snapshot/count đủ required, available và unavailable
fixed databases; database thiếu trở thành project-level `ANALYSIS_FAILED`, còn
database sẵn có tiếp tục differential. Fixed preparer đồng thời expand revision
viết tắt bằng commit graph evaluator-only trước khi fetch vì upstream không nhận
abbreviated object ID; giá trị revision vẫn không được persist vào analyzer
artifact. Alternative loại 17 project bị bác vì làm sai denominator; alternative
dùng no-build database bị bác vì có thể biến extraction thiếu thành false
negative evidence. Đây là sửa implementation để thực thi policy đã khóa, không
đổi split, evidence threshold, query budget hay metric, nên protocol giữ `1.8.0`.

## D-032 — Khóa Phase 11 differential verification (2026-09-30)

Canonical development run là `p11_diff_dev_full_002`, tạo từ clean commit
`4b898bfe9a3f16c494ec1942caf95f51e29db221`. Evaluator-only fixed preparation
account đủ 78 Phase 10-success projects và tạo 78/78 opaque fixed CodeQL
databases; 12 database mà ordinary build không tạo được chỉ được nhận sau
`build-mode=none` khi database có Java nodes và còn match các endpoint file đã
khóa ở Phase 10. Recovery này được pilot differential trước full run;
không persist identity mapping/fix revision và không mở `test_locked`.

Run ghi đủ 96 final project statuses: 78 `SUCCESS` và 18 inherited Phase 10
`ANALYSIS_FAILED` được tính là intention-to-analyze misses. Trên 776 frozen
specifications, run materialize 28 `VERIFIED_DIFFERENTIAL`, 748 explicit
`UNVERIFIED_*`, 213 taint paths và 1.513 query invocations, với zero LLM
calls/tokens. `STATUS=FAILED` là aggregate status dự kiến khi còn recorded
project misses; gate có thẩm quyền là validator
`PASS_WITH_ANALYSIS_FAILURES`, checksum và exact dependency locks.

Full 001 được giữ immutable là diagnostic predecessor vì còn 12 fixed DB
unavailable. Full 002 được pin trong `configs/experiments/main.yaml` là input
duy nhất của Phase 12 development. Chỉ `VERIFIED_DIFFERENTIAL` được coi
là verified-positive input; `UNVERIFIED_*` và project failure không được
chuyển thành negative label. Quyết định này materialize gate D-030/D-031,
không đổi threshold, budget, split hay metric, nên protocol giữ `1.8.0`.
Main experiment vẫn `draft` cho tới khi Phase 12 fit và khóa calibration
thresholds chỉ trên development.

Exact Phase 11 locks:

- manifest: `6d22442cb41877b79c274e23aa2a3d4b0a97f2400384e14ebbc6a8c5262467f7`;
- summary: `98b035896755b6f82051db38a629cf5bc664c1d9599560afa80bf40424f1002d`;
- project statuses: `2eba44a54ff9ff7ecdb6519912d480403883934c68525eaabc19219ca12df6fe`;
- verification results: `12d6a882690eeaf65b9c984cbfe7936598a222c984a3f938d76f18a309d5e656`;
- checksum index: `5c5e9b1054b667ce3ec55f9c693866840375a8385277a8bcb0f8340d085efeaa`;
- fixed preparation/status: `945f4acb11a154cf6c63c7d4e9aba636dd5671a3aada0f2a369e8aafc41a5edc` /
  `fc20f535da33bf275b058c1bf212dde03586c4cefd6fce9d8858bf3373505754`.

## D-033 — Phase 12 calibration cohort, grouped validation và routing (2026-09-30)

Phase 12 fit chỉ trên 28 canonical Phase 11 rows có
`VERIFIED_DIFFERENTIAL`. Development evaluator gán target 1 khi candidate CWE
khớp ground-truth CWE, target 0 khi differential finding mang CWE sai. 748
`UNVERIFIED_*` và 18 inherited project failures không được dùng là negative;
alternative coi absence of verification là negative bị bác vì trộn unresolved,
no-path và fixed-persistence với false finding.

Feature vector `phase12-features-v1` chỉ dùng evidence đã có trước label:
path quality, source/sink resolution, sanitizer evidence, Security-KG role
coverage, provenance, hypothesis score/rank, contextual CWE agreement và Program
grounding. So sánh dependency-free Platt, isotonic PAV và L2 multivariate
logistic. Mọi metric chọn model/threshold dùng leave-one-repository-group-out
predictions; không dùng in-sample refit probability. Thứ tự chọn deterministic
là Brier, ECE equal-width 10 bins, AURC, tên model; ECE equal-mass được báo
là sensitivity.

Routing có ba decision: `ACCEPT` khi `p >= tau_accept`, `VERIFY` khi
`tau_verify <= p < tau_accept`, còn lại `ABSTAIN`. `tau_abstain` phân tầng
high-confidence abstention trong nhóm abstain; mọi abstain đều không được
tính là negative. Development targets là precision 0.8 cho auto-accept (tối
thiểu hai rows), recall 0.8 cho verify coverage và positive rate 0.05 cho
high-confidence abstention. Nếu không đủ bằng chứng accept, `tau_accept=1.0`
và model fail-closed với zero auto-accept.

Runner bắt buộc evaluator role, exact Phase 9/10/11 checksums, development-only
split và grouped folds; `test_locked` bị cấm. Full run cấm subset và yêu cầu
clean Git worktree. Quyết định này khóa calibration/routing semantics mới nên
protocol tăng `1.8.0` lên `1.9.0`; main config vẫn `draft` cho tới clean full
run, validator pass và exact threshold/model checksum được pin.

## D-034 — Khóa Phase 12 model và thresholds (2026-09-30)

Canonical run `p12_calibration_dev_full_001` được tạo từ clean commit
`581f0dcaf1883bb03613532c398bfe11fea1ea8e`, dùng đúng 28 Phase 11
`VERIFIED_DIFFERENTIAL` findings trong 8 development repository groups. Run có
5 candidate-CWE-correct và 23 incorrect, không đọc/chạy `test_locked`, không
gọi LLM hay network. Exact dependency/config checksum, output checksum coverage
và independent validator đều pass.

Frozen selection order chọn Platt: Brier `0.18275788681173383`, ECE equal-width
`0.2377189350288208`, ECE equal-mass `0.30785991131202645`, AURC
`0.9666066487572699`. Development không có threshold nào đạt precision 0.8
với tối thiểu hai auto-accepted rows; vì vậy `tau_accept=1.0` và zero
`ACCEPT` là kết quả fail-closed được khóa, không được hạ threshold để
làm đẹp coverage. `tau_verify=0.08891881554651841` và
`tau_abstain=0.08868497505852474` tạo 25 `VERIFY`, 3 `ABSTAIN`; abstention
không phải negative.

Exact canonical locks:

- manifest: `926dd9b2f396c8ccd918e5330165c182eb5f93f81de9a8f7050347f15b71fdf9`;
- model: `45d3939f0fc751912cc2603457b8390e8c624c93e3635be910502aeb563a4674`;
- thresholds: `67ba06be74da15ac16de6b3c68e62865717a9abaf314c3c014c5b966ef93d760`;
- summary: `97061fcc1a42d629b66992e80112a6ae90c482a91d053e948474f57595b15ce3`;
- features/OOF/routing/risk-coverage:
  `49ca783a5f31e1c17c8f5d82ad3d6047c4d1b7a370f638e8bb9d5462c9fe6f08`,
  `5be59d241f3894aef0f16f2ee68ce343ab7dd8db05f94bd90c35dc27c323468a`,
  `70c67a276441898b199a2e97e2ade1df1e7dd7e400f9ebab242beae606d91eba`,
  `2dc7f05792ec9e3d82294aa8d39c61130a8369a55082bf468b5227255a9c426e`;
- checksum index: `a860d5a8ea41557bcbf755651be49f5586de0b8498cda79c81d092a23b875964`.

Main experiment config chuyển từ `draft` sang `frozen`. Phase 13 phải dùng
nguyên model/thresholds này cho full experiments, ablation và robustness;
không tune lại sau khi mở test. Quyết định materialize gate đã frozen ở
D-033 nên protocol giữ `1.9.0`.

## D-035 — Tách Phase 13 thành analyzer/evaluator process boundary (2026-09-30)

Phase 13 dùng hai pass tuần tự. Analyzer pass chỉ được đọc 24 opaque test IDs,
vulnerable source, CodeQL databases và các dependency đã khóa; evaluator labels,
advisory, patch/fix và true CWE vẫn đóng. Chỉ sau khi B0/B3-B9 analyzer outputs
được materialize bất biến mới chuyển process/role sang evaluator cho B1/B2,
fixed-version differential verification, áp dụng nguyên calibration/threshold
Phase 12, metrics và robustness.

Ma trận A0-A5/Full, canonical seed `1234`, temperature `0`, budget-matched và
năm robustness seeds đã được materialize trong
`configs/experiments/phase13.yaml`; không được đổi dựa trên test output.
Analyzer pipeline chạy tuần tự, resumable, failure-counts-as-miss vì giới hạn
32 GB RAM. Preflight không đọc evaluator labels. Một static one-project plumbing
pilot đã được chạy sau Phase 12 lock để kiểm tra split/manifest firewall; pilot
không gọi LLM/network, không được dùng để tune và không phải paper artifact.

Alternatives bị bác: đổi tên test thành development để tái dùng runner (làm mờ
provenance/leakage boundary), mở evaluator labels cùng process với analyzer, và
chạy nhiều CodeQL/LLM jobs song song. Protocol giữ `1.9.0` vì không đổi RQ,
model, threshold, metric hay budget; đây là materialization của gate đã khóa.

## D-036 — Khóa analyzer snapshot và materialize test verification (2026-10-01)

Audit đủ Phase 6/7/9, B0 và B3-B9 trước evaluator access; checksum, scope và
project coverage phải hợp lệ, các analysis failures giữ nguyên và tính là miss.
`analyzer_snapshot.json` khóa toàn bộ run roots, split, database metadata và
Phase 12 model/threshold. Test verification dùng scope `test_locked` explicit,
role evaluator và snapshot hash; development contract không được đổi tên hay
nới scope ngầm. Differential policy/query budget giữ nguyên Phase 11, calibration
chỉ predict/route bằng model đã fit trên development. Metrics/routing ghi vào
output riêng, không thay analyzer artifacts. B1/B2 oracle, robustness/bootstrap
và final ablation report là workload riêng, chưa được pass này đánh dấu hoàn tất.
Protocol giữ `1.9.0`; không thay model, prompt, threshold, split hoặc budget.

## D-037 — Audit differential evidence và follow-up evaluator (2026-10-02)

User yêu cầu triển khai follow-up Phase 13 sau khi evaluator pass hoàn tất.
Audit riêng đọc source archives và chạy lại hai query endpoint-equivalent trên
fixed DB với exact unchanged-line remapping. Cả bốn canonical specifications
còn path; original source endpoint dòng 306 đã chuyển sang 307 và sink 308 sang
309. Bốn specs chia thành hai endpoint groups, không phải bốn vulnerability
độc lập. Verifier cũ dùng absolute source line nên endpoint-unresolved đã bị
diễn giải như differential path disappearance. Canonical artifacts vẫn immutable;
audit `verification_audit_001` là diagnostic, không được promote.

Thêm B1/B2 oracle runner riêng, checkpoint theo project và validator tái tính
raw metrics. B2 giữ primary model/provider/budget đã frozen và chỉ chuyển CWE
oracle sang IRIS; patch/advisory hints và upstream internal evaluation bị loại.
CodeQL compatibility adapter được ghi là toolchain substitution, không claim
exact numerical reproduction. Request budget failure được persist và tính miss
kể cả upstream IRIS bắt exception.

Report hiện tại sinh từ canonical artifacts, bootstrap paired 10.000 lần theo
repository cluster và McNemar/Holm chỉ trong compatible proxy-metric families.
Full verdict/robustness/final report chưa hoàn tất vì verifier evidence cần review
và thiếu development-only strongest-baseline selection lock. Seed-config preparer
giữ nguyên prompt/retrieval/provider/budget, chỉ đổi predeclared seed.

Alternatives bị bác: sửa immutable outputs, dùng test để chọn baseline/tune
descriptor hoặc threshold, coi VERIFY cohort là final Full verdict, và sao chép
một LLM response thành năm robustness seeds. Protocol vẫn 1.9.0, không thay
main/ablation/Phase 11–13 frozen configs hay existing analyzer/verifier code.
Correction của verifier và Full verdict policy cần decision riêng trước khi có
scientific replacement run; follow-up không tự tạo một canonical replacement.

## D-038 — Restart development từ Phase 6 bằng pipeline v2 (2026-10-05)

Người dùng quyết định sửa thiết kế trước rerun, bắt đầu bằng development-only
error audit Phase 6–10; lượt này chỉ hoàn tất audit và thiết kế, chưa triển khai
generator/graph/specification/verifier mới hoặc chạy API/full pipeline.

Audit `p6_p10_dev_audit_v2_001` đọc tám historical development runs, xác minh
checksum toàn bộ input trước/sau và ghi 1.398 observation records. Phase 6 có
251/956 hypotheses thiếu source; 238/806 đi vào Phase 9 và B9 sinh 233/801
specifications từ hypothesis thiếu source gốc. Phase 9 có 100 source và 97 sink
location assertions không map Program. Phase 6 Recall@10 0.875 chỉ đo CWE match;
B9 cached evaluator có 254/762 specs CWE-correct và 14 fix-location proxy matches.
Các proxy nonmatches không tự động là false positive. Không đọc raw evaluator
labels hoặc test artifacts; không gọi CodeQL/LLM và không sửa immutable inputs.

Ghi `p13_test_analysis_001` là **corrective/incomplete**, chỉ diagnostic khi
rerun. Disposition nằm trong `configs/experiments/pipeline_v2.yaml`, không sửa
historical STATUS/manifest/verdict. Holdout hiện tại đã dùng để debug verifier
theo D-037 và yêu cầu người dùng, nên không còn eligible cho confirmatory v2.
Canonical test mới cần repository-group split chưa dùng cho tuning/debugging.

Chốt thiết kế: Phase 6 có source/sink/callable/file/symbol/dataflow-role provenance;
Phase 7 tách instance ID khỏi semantic descriptor và cross-version equivalence;
Phase 9 loại insufficient grounding trước evidence chain; Phase 10 inventory
resolve trên vulnerable DB trước API và recheck frozen endpoints sau synthesis;
Phase 11 v3 exact-line/path/callable/symbol mapping cùng fixed semantic query,
fail-closed khi equivalence chưa chứng minh. Phase 12 chỉ fit v3 verified cohort
có hai target classes và group support được khóa trước fit, nếu không bỏ
calibrated Full và dùng conservative routing. Target CWE correctness không được
claim là vulnerability FDR. Toàn pipeline phải khóa trước holdout mới.

Protocol kế tiếp đăng ký `2.0.0-draft` do thay grounding/equivalence, calibration
eligibility và test-claim policy; chưa frozen. Protocol/configs 1.9.0 và Phase
6–12 locks giữ nguyên cho historical reproduction, không được dùng như v2 locks.
Detailed design/gates và namespace:
`docs/19_PIPELINE_V2_RESTART.md`, `configs/experiments/pipeline_v2.yaml`.

Alternatives bị bác: chỉ vá Phase 11; chạy lại nguyên code/config; overwrite
historical outputs; dùng test đã debug làm confirmatory mới; chuyển unresolved
endpoint thành negative; tái dùng calibration từ cohort chưa reverified.

## D-039: Triển khai và tự động chạy development pipeline v2 / verifier v3

Ngày: 2026-10-05. Người dùng cho phép tự động triển khai sau D-038 và dùng tmux
cho phiên dài. Protocol thực thi mới `2.0.0`; giữ nguyên config, lock và artifact
lịch sử. Config riêng `configs/experiments/pipeline_v2_execution.yaml` và runner
`src/pipeline_v2`; chưa có canonical confirmatory result hoặc holdout mới.

Phase 6 discovery chuyển từ regex/proximity sang typed CodeQL source/sink models,
grounded file/span/callable, role-specific dataflow slot, target signature và source
fingerprint. CWE families hiện thực 22/78/79/94. Discovery có global taint candidate,
same-callable và tối đa hai caller/callee steps; structural relation không phải flow
proof. Family-balanced Top-10 có score 0.9/0.7/0.6, giảm 0.3 cho test/example/sample
path segments. Quy tắc này không dùng evaluator label hoặc patch/advisory.
Semantic mapping giữ instance IDs và descriptors riêng, không dùng line-only match.

Phase 7 v2 scope là selected endpoints/enclosing callables; đây là thay đổi graph
contract so với historical full CPG. Phase 9 dùng global CWE facts đã pin cùng
project-specific role model bindings. B6–B9 cùng phải qua typed endpoint contract,
giữ khác biệt retrieval layers/pruning; không claim so sánh trực tiếp historical
ablation như cùng một implementation. Hypothesis thiếu grounding bị loại trước API.
Mọi specification phải resolve từng source/sink trên vulnerable DB sau synthesis.

Verifier v3 require unique full semantic equivalence và actual fixed-side endpoint/
path queries. Exact unchanged lines, safe path/rename, enclosing callable, target
symbol, expression fingerprint và model semantics đều được audit. Ambiguity,
changed/deleted endpoints hoặc query failures không được xem là fixed-no-path.
V3 USEG delta không gán VERIFIED_BY hay negative evidence cho unresolved results.

Đăng ký calibration support **trước full cohort/fitting**: tối thiểu 8 repository
groups, 5 records mỗi class, 2 groups mỗi class; tất cả leave-one-group-out training
folds có hai classes. Minima là gate kỹ thuật, không khẳng định statistical power.
Target chỉ là candidate-CWE correctness trên VERIFIED_DIFFERENTIAL v3 cohort,
không phải vulnerability correctness/FDR. So sánh Platt/isotonic/logistic theo
OOF Brier/ECE/AURC. ACCEPT cần >=20 accepted OOF records, >=3 groups, Wilson lower
95% >=0.8; observation-level bound không chứng minh group independence.
Thiếu eligibility: không fit hoặc xuất calibrated Full, ACCEPT tắt, verified →
VERIFY và unverified → ABSTAIN. Không lấy misses/unverified làm negative.

Model/provider route, 8.192 input tokens/call, 2.048 output tokens/call, 30 synthesis
attempts/project và 160.000 input tokens/project giữ contract lịch sử. Resume reserve
attempt/input budget trước request. Provider HTTP retries vẫn được log riêng và bị
giới hạn bởi pinned model config. CodeQL 2.26.2, java-all 9.2.2, 2 threads, 8.192 MiB,
1 project worker, timeout 1.800s; verifier tối đa 40 attempted queries/project gồm
timeouts/failures. Không chạy CodeQL và API concurrently trong controller.

Controller chạy toàn development P6/7/9, dry cả B6–B9 trước API, API pilots trước
full, rồi evaluator v3/calibration tách process. Full chỉ từ clean local commit,
immutable artifacts, hashed implementation/config/dependencies; không overwrite.
Historical Phase 13 vẫn corrective/incomplete, diagnostic-only. Controller không
mở test và final development lock ghi new unopened repository-group holdout còn thiếu.

Alternative bị bác: tái dùng permissive endpoint roles; generic Security API làm
resolved occurrence; đổi CWE theo labels; gọi LLM để sửa unresolved mapping;
reset budget khi resume; tự fit cohort một class hoặc dùng test đã mở làm holdout mới.

## Quy trình thay đổi

Decision mới phải ghi ngày, lý do, alternatives, impact, protocol version và
config/result bị ảnh hưởng. Không sửa ngầm RQ, split, budget, model, tool, metric
hoặc threshold.
