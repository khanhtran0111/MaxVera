# Phase 7 Runbook

**Mục đích:** trích program graph source-backed từ CodeQL cho 96 opaque project
development, giữ node/edge ID ổn định, source location và provenance; tuyệt đối
không đọc hoặc chạy `test_locked`.

## Contract đã khóa

- Input hypothesis: Phase 6 canonical `p6_static_v2_dev_full_001`, static
  family-balanced v2, Top-k=10.
- CodeQL CLI `2.26.2`, `codeql/java-all@9.2.2`.
- Extractor `phase7-java-program-graph-v1`.
- Node: source-backed callable/type, call, variable access/update, return/throw,
  condition and block nodes, normalized as `EXPR`, `STMT`, `CALLABLE`, `TYPE`.
- Edge: `AST_PARENT`, `CALL`, `DEF_USE`, `DATA_FLOW`, `CONTROL_DEP`, `TYPE`,
  `TAINT_CANDIDATE`.
- Scope: các file được locked Phase 6 Top-10 hypothesis tham chiếu cộng một
  endpoint CodeQL kề; không dùng ground-truth label để chọn graph.
- Static/CodeQL only; Phase 7 không gọi LLM hoặc API.
- Analysis/database failure giữ trạng thái cuối và được downstream tính là miss.

## 1. Preflight và chuẩn bị database

```bash
cd ~/Documents/MaxVera
git pull origin main
bash scripts/tools/setup_codeql.sh
bash scripts/tools/prepare_phase7_databases.sh
```

Preparation chỉ tạo alias opaque khi D_extended revision giống hệt database
Phase 2 đã thành công. Trên snapshot hiện tại có 76/96 database dev tái sử dụng
được và 20 database thiếu. Không mapping repository/CVE/CWE nào được ghi vào
analysis artifact.

Có thể chạy Phase 7 ngay; 20 database thiếu sẽ được ghi `ANALYSIS_FAILED`. Để
tăng coverage, build lại các database thiếu bằng `tmux`. Bước này có thể lâu và
không gọi API:

```bash
tmux new -s phase7_db_build
cd ~/Documents/MaxVera
bash scripts/tools/build_phase7_databases.sh
```

Detach bằng `Ctrl+B`, rồi `D`; attach lại bằng
`tmux attach -t phase7_db_build`. Builder thử các toolchain pin, ghi final status
cho từng opaque project và không ghi đè database thành công. Exit khác 0 có thể
chỉ ra một số project vẫn không build được. Sau builder, refresh preparation:

```bash
bash scripts/tools/prepare_phase7_databases.sh
```

## 2. Dry-run và pilot

Mỗi run ID immutable. Dry-run và pilot thật phải dùng ID riêng:

```bash
bash scripts/tools/run_phase7_program_graph.sh \
  --mode pilot --project-id proj_7341ff37e347ec3be4ce \
  --dry-run --run-id p7_pg_dev_dry_002

bash scripts/tools/run_phase7_program_graph.sh \
  --mode pilot --project-id proj_7341ff37e347ec3be4ce \
  --run-id p7_pg_dev_pilot_006

bash scripts/tools/validate_phase7.sh \
  --run-root results/graphs/program/p7_pg_dev_pilot_006
```

## 3. Full development run bằng tmux

```bash
tmux new -s phase7_graph
cd ~/Documents/MaxVera
bash scripts/tools/run_phase7_program_graph.sh \
  --mode full --run-id p7_pg_dev_full_001
```

Attach lại bằng:

```bash
tmux attach -t phase7_graph
```

Nếu process bị dừng trước khi atomic finalization, resume đúng in-progress run:

```bash
bash scripts/tools/run_phase7_program_graph.sh \
  --mode full --run-id p7_pg_dev_full_001 --resume
```

Sau khi hoàn thành, validate và xem aggregate:

```bash
bash scripts/tools/validate_phase7.sh \
  --run-root results/graphs/program/p7_pg_dev_full_001

jq . results/graphs/program/p7_pg_dev_full_001/graph_summary.json
```

`PASS_WITH_ANALYSIS_FAILURES` vẫn là artifact hợp lệ khi đủ 96 final statuses;
không được chạy lại có điều kiện rồi loại project fail.

## 4. Neighborhood và slice query

Chọn seed bằng source file/line và lấy neighborhood hai hop:

```bash
bash scripts/tools/query_phase7_graph.sh \
  --run-root results/graphs/program/p7_pg_dev_full_001 \
  --project-id PROJECT_ID \
  --file src/main/java/example/Example.java --line 42 \
  --hops 2 --direction both \
  --output /tmp/phase7_neighborhood.json
```

Forward slice chỉ trên data/taint edges:

```bash
bash scripts/tools/query_phase7_graph.sh \
  --run-root results/graphs/program/p7_pg_dev_full_001 \
  --project-id PROJECT_ID --node-id NODE_ID \
  --hops 4 --direction out \
  --edge-kind DATA_FLOW --edge-kind TAINT_CANDIDATE
```

Backward slice dùng cùng lệnh với `--direction in`.

## Gate Phase 7

- Mọi successful node map được về Java/Kotlin source location tồn tại.
- Node/edge ID và ordering tái tạo deterministic; mỗi graph có canonical digest.
- Ít nhất 99% edge tham chiếu node tồn tại; normalizer hiện đóng graph trên mọi
  endpoint và validator kiểm tra lại tỷ lệ thực tế.
- Neighborhood/forward/backward slice có bounded-hop unit/regression tests.
- Full run bao phủ đúng 96 development final statuses và không chứa locked-test ID.
