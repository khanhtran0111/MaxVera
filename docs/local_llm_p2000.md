# Local Qwen runtime on Quadro P2000

This is the canonical runtime note for the experimental machine with an NVIDIA Quadro P2000 and 4 GB VRAM.

## 🎯 Frozen runtime

| Component | Pin |
|---|---|
| Model | `Qwen/Qwen2.5-Coder-3B-Instruct-GGUF` |
| Revision | `f74adce6aa16316c625447af059dbebe4983757c` |
| File | `qwen2.5-coder-3b-instruct-q4_k_m.gguf` |
| SHA-256 | `724fb256bec1ff062b2f65e4569e871ad2e95ab2a3989723d1769c54294730b7` |
| Backend | `llama.cpp` release `b10590`, commit `6657ded4faa3b8450221119fc6b4d002e35104a2` |
| CUDA | 12.4, target `sm_61` |

The official Qwen repository publishes the Q4_K_M GGUF at about 2.1 GB.[^qwen] Quadro P2000 is compute capability 6.1.[^p2000] CUDA 13 removed offline compilation and library support for Pascal, so this machine must remain on CUDA 12.x.[^cuda13]

## 🪟 Windows setup

1. Install an NVIDIA driver compatible with CUDA 12.4 and confirm that `nvidia-smi` sees the P2000.
2. Download the two assets from the pinned llama.cpp release:
   - `llama-b10590-bin-win-cuda-12.4-x64.zip`;
   - `cudart-llama-bin-win-cuda-12.4-x64.zip`.
3. Extract both archives into the same directory and add that directory to `PATH`.
4. Verify that `llama-server --version` contains `b10590`, `10590`, or commit prefix `6657ded`.

The pinned release exposes a separate Windows CUDA 12 binary and CUDA 12.4 DLL package.[^llama-release]

## ⬇️ Download and verify Qwen

From the repository root:

```powershell
uv sync --extra dev --extra notebook --locked
uv run python scripts/toolchain/fetch_qwen_gguf.py
```

The downloader writes to `models/qwen2.5-coder-3b-instruct-q4_k_m.gguf`, verifies SHA-256 before replacing any existing cache, and reuses a valid cached file without network access.

## 🧪 Standalone smoke

```powershell
$stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
uv run python workflows/scripts/phase_00/smoke_local_qwen.py `
  --model models/qwen2.5-coder-3b-instruct-q4_k_m.gguf `
  --output "results/phases/phase_00/model_smoke/qwen3b_$stamp.json"
```

The result records model identity, llama.cpp version, command, response usage, GPU memory snapshots and whether CUDA appeared in the server log.

## ⚙️ Four-GB VRAM policy

Start with context 4096, batch 128, flash attention disabled and automatic layer fitting. The GGUF file size alone is not the total VRAM requirement: KV cache, compute buffers and display reservation also consume memory. llama.cpp supports hybrid CPU/GPU inference when a model exceeds available VRAM.[^llama]

If the server reports OOM:

1. reduce batch size to 64;
2. reduce context to 3072, then 2048;
3. reduce GPU layers and allow CPU offload;
4. record the effective values in the run manifest.

Do not silently change quantization, model revision or switch to an API model. Such a change is a separate experiment configuration.

[^qwen]: Qwen, “Qwen2.5-Coder-3B-Instruct-GGUF.” https://huggingface.co/Qwen/Qwen2.5-Coder-3B-Instruct-GGUF/tree/f74adce6aa16316c625447af059dbebe4983757c
[^p2000]: NVIDIA Developer, “Legacy CUDA GPU Compute Capability.” https://developer.nvidia.com/cuda/gpus/legacy
[^cuda13]: NVIDIA, “CUDA Toolkit 13.0 Release Notes — Deprecated Architectures.” https://docs.nvidia.com/cuda/archive/13.0.0/cuda-toolkit-release-notes/index.html#deprecated-architectures
[^llama-release]: ggml-org, “llama.cpp release b10590.” https://github.com/ggml-org/llama.cpp/releases/tag/b10590
[^llama]: ggml-org, “llama.cpp.” https://github.com/ggml-org/llama.cpp
