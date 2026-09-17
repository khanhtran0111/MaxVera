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

## Quy trình thay đổi

Decision mới phải ghi ngày, lý do, alternatives, impact, protocol version và
config/result bị ảnh hưởng. Không sửa ngầm RQ, split, budget, model, tool, metric
hoặc threshold.
