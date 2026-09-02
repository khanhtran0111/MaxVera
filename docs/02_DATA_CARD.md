# Data Card — CWE-Bench Java Phase 2

**Mục đích:** khóa provenance, manifest, split, leakage boundary và trạng thái
build của dữ liệu dùng trong MaxVera.

## Release đã materialize

| Track | Upstream commit | CVE rows | Repository groups | CWE |
|---|---|---:|---:|---:|
| `D_repro_v1` | `698fb7248ae30cb7f7782d59c841f05ad70ea9cc` | 120 | 77 | 4 |
| `D_extended` | `afe0ebd0adc237abb46255f9cd479b1d71819136` | 120 | 77 | 4 |

Nguồn là `https://github.com/iris-sast/cwe-bench-java.git`, license MIT.
Acquisition chỉ chấp nhận detached checkout có origin, HEAD và clean worktree
khớp config. Raw checkout không được sửa sau khi tải.

Tên `D_extended` là tên track đã khóa trong protocol, nhưng commit pin hiện vẫn
chỉ có 120 CVE thuộc CWE-22/78/79/94. Nó sửa metadata/fix locations so với v1,
không phải snapshot 213 CVE/49 CWE được README upstream nhắc tới ở thời điểm lập
kế hoạch. MaxVera báo đúng số quan sát và không gán dữ liệu chưa tồn tại cho SHA
này.

## Manifest và checksum

- Canonical v1: `data/processed/manifests/cwe_bench_v1.csv` (120 unique
  vulnerability/project rows).
- Extended snapshot: `data/processed/manifests/cwe_bench_extended.csv`.
- `D_repro_v1_checksums.sha256` và `D_extended_checksums.sha256` checksum mọi
  artifact release.
- Mỗi `*_source_checksums.sha256` checksum ba CSV gốc, advisory JSON, patch,
  package-name metadata và tool-version metadata ở raw checkout.
- Advisory content không vào analysis view; canonical manifest chỉ ghi SHA256
  của advisory để audit integrity.

Release checksum được tính lại bằng `bash scripts/tools/create_data_manifests.sh`;
split checksum phải giống hệt khi input SHA/config không đổi.

| Artifact index | SHA256 |
|---|---|
| `D_repro_v1_checksums.sha256` | `3eb9abab17431082d92e4c105b2a289fd01bd62d59876c3fdf5d72dd8c3dc63c` |
| `D_extended_checksums.sha256` | `ccbb3b26819b7d08767778a345a05960f3e6a9891d0de41b7fd16c75ab396c8b` |
| `development.csv` | `f534192c4272320f358602d66caf094b2d479ae4aa83a338b3f2389d0ad183ce` |
| `test_locked.csv` | `7e948c65be2896c0eaec680ad2c3a709b8a3f4b7b0e759dcccd2af2086945b6a` |

## Group split

`D_extended` dùng seed 1234 và tỷ lệ 80/20. Nhóm là lower-cased
`github_username/github_repository_name`; thứ tự nhóm dùng SHA256 thay vì RNG
phụ thuộc runtime. Kết quả:

| Split | Rows | CWE-22 | CWE-78 | CWE-79 | CWE-94 |
|---|---:|---:|---:|---:|---:|
| development | 96 | 42 | 11 | 25 | 18 |
| test_locked | 24 | 13 | 2 | 6 | 3 |

Hai split không overlap repository group. CSV public cho analyzer chỉ chứa
opaque `project_id` và split; mapping group nằm trong evaluator-only view.

## Leakage firewall

`analysis_input/` chỉ có opaque ID (`proj_<20 hex>`), relative source path và
build-tool metadata tối thiểu. Nó cấm CVE, CWE, upstream slug, owner/repository,
advisory, buggy/fix commit và fix location. Generator quét thêm literal
`CVE-`/`CWE-` trước khi ghi.

`evaluator_only/` giữ canonical labels, split-group mapping và fix locations.
Analysis phải chạy qua `scripts/tools/run_analysis_isolated.sh`; container chỉ
được mount analysis view, opaque project sources và CodeQL DB read-only. Script
fail-closed nếu Docker không có và không mount raw, canonical manifest hay
evaluator-only view.

## Build và CodeQL status

Upstream metadata báo 120/120 build success, nhưng đó không được coi là local
reproduction. `data/interim/build_info/build_status.jsonl` có đúng 120 record;
trạng thái ban đầu là `PENDING`. Mỗi project được fetch/build tuần tự bằng đúng
10 pinned JDK/Maven/Gradle attempts; mọi attempt có log và exit code. Chỉ build
thành công mới được CodeQL 2.26.2 trace lại bằng cùng command.

Maven 3.2.1/3.5.0/3.9.8 và Gradle 6.8.2/7.6.4/8.9 được download theo checksum.
Do Oracle archive cũ yêu cầu interactive account, JDK 7u80 và 8u202 dùng public
Azul Zulu CA exact-update archives; JDK 17 dùng Oracle GA archive. URL, vendor và
SHA256 đều được pin trong toolchain config; version sai làm pipeline dừng.

Gate đầy đủ kiểm bằng `bash scripts/tools/validate_phase2.sh`. Trên máy hiện tại,
gate chưa pass cho đến khi 120 trạng thái local là final và mọi `SUCCESS` có
CodeQL DB. Không đổi `PENDING` thành exclusion/build failure khi chưa thực sự
chạy.
