# Phase workflows

Thư mục này là giao diện chạy thực nghiệm theo phase. Implementation dùng lại nằm trong `src/openiris/`; các file dưới `scripts/` chỉ điều phối và trình bày kết quả cho notebook.

## 📓 Trạng thái notebook

| Phase | Notebook canonical | Trạng thái |
|---:|---|---|
| 0 | `notebooks/phase_00_reproducibility.ipynb` | Runnable smoke end-to-end |
| 1 | `notebooks/phase_01_zero_hint_baseline.ipynb` | Tạo khi bắt đầu Phase 1 |
| 2 | `notebooks/phase_02_program_graph.ipynb` | Tạo khi bắt đầu Phase 2 |
| 3 | `notebooks/phase_03_security_kg.ipynb` | Tạo khi bắt đầu Phase 3 |
| 4 | `notebooks/phase_04_evidence_graph.ipynb` | Tạo khi bắt đầu Phase 4 |
| 5 | `notebooks/phase_05_graph_retrieval.ipynb` | Tạo khi bắt đầu Phase 5 |
| 6 | `notebooks/phase_06_spec_synthesis.ipynb` | Tạo khi bắt đầu Phase 6 |
| 7 | `notebooks/phase_07_static_verification.ipynb` | Tạo khi bắt đầu Phase 7 |
| 8 | `notebooks/phase_08_calibration.ipynb` | Tạo khi bắt đầu Phase 8 |
| 9 | `notebooks/phase_09_iterative_update.ipynb` | Tạo khi bắt đầu Phase 9 |

Không commit notebook giả cho Phase 1--9: một notebook chỉ xuất hiện khi script của phase đã có thể chạy và gate có thể tính bằng code.

## ▶️ Chạy Phase 0

```powershell
uv sync --extra dev --extra notebook --locked
uv run python -m ipykernel install --user --name maxvera-openiris
```

Mở `notebooks/phase_00_reproducibility.ipynb`, chọn kernel `maxvera-openiris`, rồi dùng **Restart Kernel and Run All**. Notebook mặc định chạy profile `smoke`; lần đầu sẽ tải dependency, CodeQL và model GGUF đã pin.

Kết quả aggregate/freeze được ghi ở `results/phases/phase_00/`. Raw command, log và database vẫn nằm trong `runs/<run_id>/` để bảo toàn contract append-only.

## 🧩 Quy tắc cell

Mỗi notebook phải có các nhóm cell theo đúng thứ tự:

1. metadata và parameter;
2. preflight;
3. chuẩn bị input/toolchain;
4. execution;
5. metric/visualization;
6. artifact links và gate cuối.

Mỗi execution cell phải độc lập về log, fail-fast và in đường dẫn kết quả ngay sau khi hoàn thành.
