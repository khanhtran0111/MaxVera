# Phase 12 — Calibration và selective routing

Phase 12 chỉ dùng canonical Phase 11 `p11_diff_dev_full_002` và development
labels trong evaluator process. `test_locked` bị cấm cho tới khi model,
`tau_accept`, `tau_verify` và `tau_abstain` đã được khóa.

## 1. Contract

- protocol `1.9.0`, feature version `phase12-features-v1`;
- chỉ 28 Phase 11 rows có `VERIFIED_DIFFERENTIAL` được fit/routing;
- target dương khi candidate CWE khớp development ground-truth CWE;
- 748 `UNVERIFIED_*` và 18 project failures không phải negative examples;
- grouped out-of-fold theo repository group, không random row split;
- so sánh Platt, isotonic và multivariate logistic theo Brier, ECE, AURC;
- zero LLM/network calls; artifact evaluator-only và atomic;
- `ABSTAIN` không được tính là negative.

Feature frozen gồm path count/compactness, source/sink resolution, sanitizer,
Security-KG role coverage, provenance, Phase 6 hypothesis score/rank, contextual
CWE agreement và Program grounding. Raw score chỉ là input cho Platt/isotonic;
logistic nhận toàn bộ feature vector.

## 2. Routing semantics

- `p >= tau_accept`: `ACCEPT`;
- `tau_verify <= p < tau_accept`: `VERIFY`;
- `p < tau_verify`: `ABSTAIN`;
- trong nhóm abstain, `p <= tau_abstain` là `HIGH_CONFIDENCE`, phần còn lại
  là `CONSERVATIVE`.

Threshold chỉ được chọn từ grouped out-of-fold development predictions.
`tau_accept` nhắm precision 0.8 với ít nhất hai rows; nếu development không
đủ bằng chứng, threshold là 1.0 và không row nào được auto-accept.
`tau_verify` nhắm recall 0.8; `tau_abstain` là low-score cutoff lớn nhất có
positive rate không quá 0.05.

## 3. Pilot

```bash
export MAXVERA_DATA_ROLE=evaluator
bash scripts/tools/run_phase12_calibration.sh \
  --mode pilot \
  --limit 28 \
  --run-id p12_calibration_pilot_002

bash scripts/tools/validate_phase12.sh \
  --run-root results/calibration/phase12/p12_calibration_pilot_002
unset MAXVERA_DATA_ROLE
```

Pilot 001 là diagnostic trước khi output materialize abstention tier; pilot 002
là post-tier dirty-tree diagnostic. Cả hai không được promote. Selected clean
pilot `p12_calibration_pilot_003` tại commit `9fd1661` có đủ 28 rows, 5
positive/23 negative trong 8 repository groups, chọn Platt và validator pass.
Development không đủ bằng chứng precision 0.8 cho auto-accept, nên pilot
fail-closed với `tau_accept=1.0`, 25 `VERIFY`, 3 `ABSTAIN`, zero `ACCEPT`.

## 4. Full development run trong tmux

Full run cấm `--limit`, yêu cầu clean worktree và run ID mới:

```bash
tmux new-session -s phase12_calibration
cd /home/khanhtg/Documents/MaxVera
export MAXVERA_DATA_ROLE=evaluator
bash scripts/tools/run_phase12_calibration.sh \
  --mode full \
  --run-id p12_calibration_dev_full_001
```

Detach bằng `Ctrl-b`, sau đó nhấn `d`. Theo dõi hoặc quay lại:

```bash
tmux ls
tmux attach -t phase12_calibration
```

Sau khi runner xong:

```bash
bash scripts/tools/validate_phase12.sh \
  --run-root results/calibration/phase12/p12_calibration_dev_full_001
unset MAXVERA_DATA_ROLE
```

Phase này offline và thường chỉ mất vài giây; tmux vẫn hữu ích để
giữ quy trình chạy nhất quán với các phase sau.

## 5. Output và gate

```text
results/calibration/phase12/<run-id>/
  features.jsonl
  oof_predictions.jsonl
  candidate_metrics.json
  model.json
  thresholds.json
  routing_decisions.jsonl
  risk_coverage.jsonl
  calibration_summary.json
  manifest.json
  config.resolved.yaml
  environment.json
  command.txt
  checksums.sha256
  STATUS
```

Gate Phase 12 yêu cầu checksum coverage đầy đủ; exact Phase 9/10/11 locks;
28 differential rows; ba calibrator; ECE equal-width 10 bins, equal-mass
sensitivity, Brier và AURC; ordered thresholds; `locked_test_used=false`; và
validator `PASS`. Chỉ sau full clean run + validator pass mới pin canonical
hash và chuyển `configs/experiments/main.yaml` từ `draft` sang `frozen`.
