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

## Quy trình thay đổi

Decision mới phải ghi ngày, lý do, alternatives, impact, protocol version và
config/result bị ảnh hưởng. Không sửa ngầm RQ, split, budget, model, tool, metric
hoặc threshold.
