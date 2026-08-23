# Kế hoạch triển khai nghiên cứu
## Graph-Grounded Zero-Hint Repository-Level Vulnerability Discovery with Resource-Efficient LLM-Assisted Static Analysis

> **Mục tiêu của tài liệu:** chuyển đề xuất nghiên cứu hiện tại thành một roadmap triển khai có thể thực nghiệm, đo lường, viết bài và mở rộng thành hệ thống nghiên cứu hoàn chỉnh.  
> **Phạm vi mặc định:** Java + CodeQL + CWE-Bench-Java, repository-level, zero-hint (không cung cấp CWE/CVE/vulnerability description cho hệ thống khi inference).

## Quy ước thực thi notebook-first

Từ phiên bản kế hoạch này, **mỗi phase có đúng một notebook điều phối chính**. Notebook là giao diện chạy end-to-end cho người làm thực nghiệm; implementation tái sử dụng vẫn nằm trong `src/`, còn entrypoint mỏng nằm trong `workflows/scripts/`.

Notebook của một phase chỉ được xem là hoàn thành khi đáp ứng toàn bộ contract sau:

| Thành phần | Yêu cầu bắt buộc |
|---|---|
| Tên file | `workflows/notebooks/phase_<NN>_<slug>.ipynb` |
| Chạy lại | `Restart Kernel and Run All` chạy theo thứ tự, không cần copy biến thủ công giữa notebook khác |
| Parameter cell | Có `profile`, seed, dataset snapshot, model config và các cờ chạy bước tốn thời gian |
| Preflight cell | Hiện phiên bản Git/Python/Docker/CodeQL/Java/GPU/CUDA và trạng thái PASS/WARN/FAIL |
| Execution cells | Mỗi cell gọi script/CLI version-controlled, fail-fast và ghi command log |
| Visual cells | Hiện bảng metric, trạng thái gate, runtime/token/VRAM và biểu đồ nhỏ khi có dữ liệu phù hợp |
| Artifact links | Sau mỗi bước phải hiện đường dẫn tương đối có thể bấm tới file hoặc thư mục kết quả |
| Final cell | Tổng hợp `PASS`, `PASS-WITH-RISK` hoặc `FAIL` và link phase report |

Notebook không được chứa business logic chỉ tồn tại trong `.ipynb`. Logic parse, evaluate, graph, retrieval và model adapter phải có API trong `src/openiris/`; notebook chỉ cấu hình, gọi và trình bày kết quả. File notebook được commit ở trạng thái **không chứa output thực nghiệm nặng hoặc dữ liệu nhạy cảm**; output chuẩn được ghi ra thư mục phase result.

Hai execution profile chuẩn:

- `smoke`: 1--3 project, dùng để kiểm tra máy mới và contract end-to-end;
- `full`: toàn bộ split đã freeze, dùng để tạo số liệu nghiên cứu.

Hiện tại chỉ `phase_00_reproducibility.ipynb` có implementation đủ để chạy end-to-end. Notebook Phase 1--9 được tạo khi bắt đầu phase tương ứng và chỉ được đánh dấu runnable sau khi các script của phase đạt DoD; không tạo notebook giả trả về thành công khi pipeline chưa tồn tại.

## Chính sách local-first và máy thực nghiệm chuẩn

Mô hình chính cho các contribution mới từ Phase 1 trở đi là `Qwen2.5-Coder-3B-Instruct-Q4_K_M` ở định dạng GGUF, chạy local bằng `llama.cpp` qua OpenAI-compatible HTTP endpoint. Model chính thức có file Q4_K_M khoảng 2.1 GB; model, revision và SHA-256 phải được pin trong config thay vì tải từ `main` dạng floating.[^qwen-gguf]

```yaml
provider: local_llama_cpp
model_id: Qwen/Qwen2.5-Coder-3B-Instruct-GGUF
revision: f74adce6aa16316c625447af059dbebe4983757c
filename: qwen2.5-coder-3b-instruct-q4_k_m.gguf
sha256: 724fb256bec1ff062b2f65e4569e871ad2e95ab2a3989723d1769c54294730b7
quantization: Q4_K_M
backend: llama.cpp
temperature: 0.0
seed: 345
```

API LLM không còn là dependency mặc định. Chỉ dùng API trong một experiment được gắn nhãn rõ là upper-bound/robustness check; không tự động fallback từ local sang API khi local model lỗi.

### Cấu hình Quadro P2000 4 GB

Quadro P2000 thuộc Pascal, compute capability 6.1.[^nvidia-p2000] CUDA Toolkit 13 đã loại bỏ offline compilation và library support cho Pascal, vì vậy runtime chuẩn của nghiên cứu phải ở nhánh CUDA 12.x, ưu tiên **CUDA 12.4** và build `llama.cpp` cho `sm_61`; không dùng CUDA 13 cho máy này.[^cuda13-pascal] Release `llama.cpp` được pin trong config; bản Windows CUDA 12.4 được ưu tiên vì upstream phát hành riêng asset CUDA 12.4.[^llama-release]

Thiết lập khởi đầu, sau đó tune một lần trên calibration machine và freeze:

```yaml
cuda_toolkit: "12.4"
cuda_architecture: "61"
context_size: 4096
batch_size: 128
flash_attention: false
gpu_layers: auto_fit
vram_safety_margin_mib: 768
```

Không khẳng định toàn bộ workload luôn nằm trong 4 GB VRAM chỉ dựa trên kích thước file GGUF: KV cache, compute buffer, context và phần VRAM dành cho display cũng tiêu tốn bộ nhớ. `llama.cpp` hỗ trợ CPU+GPU hybrid offload; nếu OOM, thứ tự xử lý là giảm batch, giảm context xuống 3072/2048, rồi giảm số GPU layers và ghi cấu hình thực tế vào run manifest.[^llama-cpp]

---

## 0. Nguồn dữ liệu, code tham chiếu và chính sách versioning

Phần này là **bắt buộc** trước khi bắt đầu code để tránh thay đổi benchmark/toolchain giữa các experiment.

## 0.1. Nguồn chính thức cần lưu trong project

| Resource | Link | Vai trò |
|---|---|---|
| CWE-Bench-Java legacy | https://github.com/iris-sast/cwe-bench-java | Benchmark gốc của IRIS/ICLR 2025; 120 CVEs, 4 CWEs; có scripts fetch/build, metadata, patch và fix locations |
| CWE-Bench-Java trên Hugging Face | https://huggingface.co/datasets/iris-sast/CWE-Bench-Java | Bản đóng gói thuận tiện để đọc metadata bằng Hugging Face Datasets; hiện vẫn mô tả benchmark legacy 120 CVEs/4 CWEs |
| IRIS repository | https://github.com/iris-sast/iris | Code IRIS, baseline, Docker, query/config và dữ liệu mở rộng |
| IRIS v2 data | https://github.com/iris-sast/iris/tree/v2/data | Nguồn dữ liệu mở rộng hiện tại; README v2 công bố 213 CVEs trên 49 CWEs |
| IRIS paper | https://arxiv.org/abs/2405.17238 | Paper gốc để reproduce protocol, metric và baseline |
| MITRE CWE downloads | https://cwe.mitre.org/data/downloads.html | Nguồn chuẩn để xây Security KG; phải snapshot version |
| CodeQL | https://github.com/github/codeql | Query/library reference |
| CodeQL docs | https://codeql.github.com/docs/ | Tài liệu CLI, database, dataflow/taint tracking |

## 0.2. Hai benchmark track phải tách riêng

### Track A — Legacy reproduction

Mục tiêu: so sánh trực tiếp với IRIS ICLR 2025.

```text
CWE-Bench-Java legacy
120 CVEs / 4 CWEs
+
IRIS v1 / paper protocol
+
CodeQL version tương thích với reproduction
```

Không trộn kết quả Track A với dataset v2 rồi gọi là reproduction của paper gốc.

### Track B — Main zero-hint research

Mục tiêu: đánh giá contribution mới, đặc biệt generalization.

```text
IRIS v2 CWE-Bench-Java snapshot
213 CVEs / 49 CWEs (theo README v2 hiện tại)
+
repository-only zero-hint protocol
+
toolchain được pin version
```

Bản v2 còn có **manually curated source/sink annotations cho 50 CVEs**, rất hữu ích cho RQ4/specification-quality evaluation.

## 0.3. Dataset freeze policy

Không dùng branch `master`/`v2` dạng floating cho experiment paper.

Mỗi dataset snapshot phải có:

```yaml
dataset_name: cwe_bench_java
track: legacy | v2
source_url: ...
git_commit: ...
downloaded_at: ...
num_instances: ...
num_unique_repositories: ...
num_cwes: ...
sha256_manifest: ...
```

Lưu tại:

```text
data/manifests/datasets/<dataset_snapshot_id>.yaml
```

Với knowledge source cũng tương tự. Ví dụ MITRE CWE phải ghi:

```yaml
source: MITRE CWE
version: 4.xx
download_date: YYYY-MM-DD
sha256: ...
```

## 0.4. Toolchain compatibility

Tách rõ:

- **Paper legacy:** paper gốc dùng CodeQL 2.15.3.
- **IRIS v2:** README v2 khuyến nghị CodeQL 2.23.2 với query version 1.8.1.

Mọi experiment phải pin:

```text
CodeQL CLI version
CodeQL query-pack version
Java/JDK version
Maven/Gradle version
IRIS commit (nếu dùng baseline)
Python lockfile
model ID/revision
prompt version
```

---

# 1. Mục tiêu khoa học

### 1.1. Bài toán trung tâm

Xây dựng một hệ thống nhận **duy nhất source repository** và trả về một tập vulnerability findings có:

- vị trí code;
- hypothesis về CWE/weakness;
- source/sink/sanitizer/propagator liên quan;
- evidence path;
- static-verification result;
- confidence;
- provenance;
- quyết định cuối cùng: `ACCEPT`, `VERIFY`, hoặc `ABSTAIN/REVIEW`.

Khác biệt cốt lõi với IRIS:

```text
IRIS:
Given repository + CWE
    -> infer taint specifications
    -> CodeQL verification
    -> contextual triage

Hướng đề xuất:
Given repository only
    -> discover vulnerability hypotheses
    -> construct/retrieve evidence graph
    -> synthesize specifications
    -> CodeQL/static verification
    -> calibrated decision
```

### 1.2. Mục tiêu nghiên cứu

Hệ thống cần chứng minh đồng thời 4 nhóm giá trị:

1. **Effectiveness**
   - tăng Recall/F1 hoặc Hypothesis Recall@k so với CodeQL và zero-hint baselines;
   - duy trì Precision/FDR hợp lý.

2. **Grounded reasoning**
   - LLM không đưa verdict độc lập;
   - mọi finding quan trọng phải có static evidence / graph evidence.

3. **Resource efficiency**
   - giảm input tokens;
   - giảm số LLM calls;
   - giảm latency;
   - giảm API cost;
   - giảm local context / GPU memory nếu dùng local model.

4. **Uncertainty handling**
   - không ép hệ thống phải kết luận khi evidence yếu;
   - hỗ trợ calibrated confidence, selective verification và abstention.

---

# 2. Research Questions và tiêu chí thành công

## RQ1 — Zero-hint discovery

**Câu hỏi:** không biết CWE trước, hệ thống có thể sinh đúng vulnerability hypothesis ở repository-level đến đâu?

### Metric chính

- CWE Recall@1 / @3 / @5 / @10
- Hypothesis Recall@k
- Repository vulnerability detection rate
- Recall / Precision / F1 sau static verification
- FDR

### Success criterion ban đầu

Một kết quả đủ mạnh để viết paper nên đạt ít nhất một trong các dạng:

- tăng rõ rệt Recall@k so với zero-hint static baseline;
- đạt gần mức IRIS oracle-CWE dù không nhận CWE;
- hoặc giữ tương đương effectiveness nhưng giảm mạnh cost.

---

## RQ2 — Graph vs text context

**Câu hỏi:** USEG + graph retrieval có tốt hơn raw source context hoặc text-RAG không?

### So sánh

```text
Raw context
vs
Text RAG
vs
Program Graph only
vs
Security KG only
vs
Program Graph + Security KG
vs
Full USEG
```

### Metric

- Recall
- Precision
- F1
- input tokens
- LLM calls
- latency
- cost/project

---

## RQ3 — Resource efficiency

**Câu hỏi:** minimal evidence subgraph giảm bao nhiêu resource mà không làm giảm đáng kể effectiveness?

### Metric

- input tokens / repository
- input tokens / hypothesis
- number of LLM calls
- wall-clock latency
- API cost/project
- peak GPU memory nếu local
- average context length
- average evidence-subgraph size

### Phân tích quan trọng

Nên báo:

```text
% token reduction
% cost reduction
% latency reduction
Delta Recall / Delta F1
```

Thay vì chỉ báo số tuyệt đối.

---

## RQ4 — Knowledge-constrained taint analysis

**Câu hỏi:** Security KG có giúp suy ra source/sink/sanitizer/propagator chính xác hơn không?

### Metric

- Source precision / recall
- Sink precision / recall
- Sanitizer precision / recall
- Propagator precision / recall
- verified taint-path count
- verified vulnerable path count
- rejected invalid spec count

---

## RQ5 — Calibration and abstention

**Câu hỏi:** evidence calibration + selective routing có giúp giảm false positives không?

### Metric

- ECE
- Brier Score
- FDR
- risk-coverage curve
- accuracy/F1 theo coverage
- % cases ACCEPT
- % cases VERIFY
- % cases ABSTAIN

---

## RQ6 — Generalization

**Câu hỏi:** hệ thống có generalize sang repository/CWE chưa xuất hiện trong development set không?

### Cần ít nhất hai protocol

1. **Unseen repository split**
2. **Unseen CWE split**

Nếu đủ dữ liệu, thêm:

3. **Unseen library/API split**

---

# 3. Nguyên tắc thiết kế nghiên cứu

## 3.1. Không xây hệ thống quá lớn ngay từ đầu

Sai lầm lớn nhất sẽ là implement đồng thời:

- CPG;
- Security KG;
- Evidence Graph;
- agent;
- CodeQL synthesis;
- calibration;
- local LLM;
- API LLM;
- multi-CWE discovery.

Nên xây theo hướng **minimal publishable pipeline**, sau đó mới bổ sung module.

---

## 3.2. Static analysis là verifier, không phải LLM verdict

Pipeline nên giữ nguyên nguyên tắc:

```text
LLM proposes / interprets
Static analysis verifies
Evidence graph records
Decision layer calibrates
```

LLM chỉ nên trực tiếp quyết định ở những thành phần semantic khó encode bằng rule.

---

## 3.3. Mỗi module phải gắn với một ablation

Nếu một module không có experiment để chứng minh giá trị, contribution của module đó sẽ yếu.

Ví dụ:

| Module | Experiment bắt buộc |
|---|---|
| Security KG | no-KG vs text-RAG vs graph-KG |
| Program Graph | raw code vs slice |
| USEG | separate stores vs unified evidence representation |
| Graph pruning | full subgraph vs minimal subgraph |
| LLM spec synthesis | static-only vs LLM-assisted |
| Selective routing | forced decision vs abstention |
| Iterative graph | stateless prompt vs graph memory |

---

# 4. Kiến trúc hệ thống đề xuất

```text
Repository
   |
   v
[1] Repository preprocessing
   |
   v
[2] Program Graph G_P
   |
   +----------------------+
   |                      |
   v                      v
[3] Static signals     [4] Security KG G_K
   |                      |
   +----------+-----------+
              |
              v
       [5] Zero-hint
      Hypothesis Generator
              |
              v
       [6] Evidence Graph G_E
              |
              v
       [7] USEG integration
              |
              v
   [8] Graph Retrieval / Pruning
              |
              v
  [9] LLM Spec Synthesis / Reasoning
              |
              v
     [10] CodeQL Verification
              |
              v
  [11] Evidence Calibration / Routing
        ACCEPT / VERIFY / ABSTAIN
              |
              v
      [12] Iterative Graph Update
```

---

# 5. Data model của Unified Security Evidence Graph

## 5.1. Program Graph `G_P`

### Node types

- repository
- module
- package
- class
- method
- parameter
- variable
- expression
- call
- return
- branch
- exception
- field
- source candidate
- sink candidate
- sanitizer candidate

### Edge types

- `CONTAINS`
- `CALLS`
- `RETURNS_TO`
- `PARAMETER_OF`
- `DEF_USE`
- `DATA_DEP`
- `CONTROL_DEP`
- `CFG_NEXT`
- `TAINT_REACHES`
- `OVERRIDES`
- `IMPLEMENTS`

### Metadata

- file
- start_line/end_line
- symbol
- signature
- package
- code snippet
- CodeQL node ID
- confidence nếu edge được suy ra probabilistically

---

## 5.2. Security Knowledge Graph `G_K`

### Node types

- CWE
- weakness concept
- source concept
- sink concept
- sanitizer
- propagator
- API
- precondition
- attack consequence
- mitigation
- related CWE

### Edge types

- `HAS_SOURCE`
- `HAS_SINK`
- `HAS_SANITIZER`
- `HAS_PROPAGATOR`
- `REQUIRES`
- `CAN_CAUSE`
- `MITIGATED_BY`
- `RELATED_TO`
- `SPECIALIZATION_OF`
- `MATCHES_API`

---

## 5.3. Evidence Graph `G_E`

### Node types

- hypothesis
- static finding
- taint path
- LLM assertion
- source assertion
- sink assertion
- sanitizer assertion
- contradiction
- verification result
- confidence score
- abstention decision

### Edge types

- `SUPPORTS`
- `CONTRADICTS`
- `VERIFIED_BY`
- `DERIVED_FROM`
- `MATCHES`
- `INVALIDATES`
- `REFINES`
- `TRIGGERED_BY`

### Provenance bắt buộc

Mỗi evidence node cần:

```yaml
producer:
  type: codeql | llm | rule | knowledge_base
  name: ...
version: ...
timestamp: ...
repo_commit: ...
file: ...
line: ...
confidence: ...
deterministic: true|false
```

---

# 6. Phase 0 — Reproducibility và baseline

## Mục tiêu

Không bắt đầu xây USEG trước khi reproduce được IRIS/CodeQL benchmark.

## Công việc

### 0.1. Chuẩn bị environment

- Java versions cần cho CWE-Bench-Java;
- Maven;
- CodeQL CLI;
- Python environment;
- Docker nếu cần;
- `llama.cpp` local runtime và script tải GGUF có kiểm tra revision/hash;
- adapter OpenAI-compatible dùng chung cho local endpoint, không yêu cầu API cloud;
- experiment config system.

### 0.2. Reproduce CodeQL baseline

Chạy built-in CodeQL queries trên CWE-Bench-Java.

Ghi:

```text
project
CVE
CWE
CodeQL query
number of paths
vulnerability detected?
runtime
```

### 0.3. Reproduce tối thiểu một IRIS configuration

Không nhất thiết reproduce toàn bộ 7 LLM.

Phase 0 giữ hai mục đích tách biệt:

- **paper-compatibility run:** cấu hình IRIS v1 + Qwen2.5-Coder-1.5B hiện có được giữ nguyên để so khớp smoke đã freeze;
- **primary local runtime smoke:** tải, verify hash và gọi thử `Qwen2.5-Coder-3B-Instruct-Q4_K_M` qua `llama.cpp` trên máy thực nghiệm.

Từ Phase 1, Qwen 3B Q4_K_M là model mặc định. Cấu hình 1.5B chỉ là artifact compatibility của Phase 0, không được dùng để đại diện cho model chính của proposed method.

### 0.4. Tạo experiment registry

Mọi run phải có:

```yaml
run_id:
git_commit:
dataset_version:
model:
prompt_version:
codeql_version:
temperature:
seed:
token_usage:
latency:
cost:
metrics:
```

## Deliverable

```text
workflows/notebooks/phase_00_reproducibility.ipynb
workflows/scripts/phase_00/
results/phases/phase_00/
    baselines/codeql/
    baselines/iris/
    baselines/published_reference/
    model_smoke/
    audits/
    report.md
    status.json
```

## Gate để sang Phase 1

- CodeQL baseline chạy ổn;
- dataset build được phần lớn project cần thiết;
- evaluator khớp logic ground truth của CWE-Bench-Java.
- notebook chạy được `Restart Kernel and Run All` với `profile=smoke` trên máy chuẩn;
- Qwen 3B GGUF đúng SHA-256 và local endpoint trả về response hợp lệ;
- mọi execution cell hiện trạng thái và link artifact tương ứng.

---

# 7. Phase 1 — Zero-hint baseline

Đây là phase quan trọng nhất để chứng minh bài toán trước khi xây graph phức tạp.

## 7.1. Mục tiêu

Từ repository-only sinh Top-k candidate weakness hypotheses.

## 7.2. Không cho model thấy

- CVE ID;
- CWE label;
- vulnerability description;
- fix description;
- patch;
- ground-truth vulnerable location.

Các trường đó chỉ evaluator được phép dùng.

## 7.3. Candidate signals

Nên bắt đầu từ static/rule-driven signals:

### Source-like

- request parameters;
- environment variables;
- command-line input;
- deserialization input;
- file/network input;
- public API parameters;
- archive entries;
- headers/cookies;
- database outputs nếu downstream handling relevant.

### Sink-like

- command execution;
- expression evaluation;
- SQL execution;
- filesystem access;
- path creation;
- HTML output;
- reflection;
- deserialization;
- process creation.

## 7.4. Hypothesis schema

```json
{
  "hypothesis_id": "H001",
  "weakness_candidates": ["CWE-78", "CWE-94"],
  "source": {...},
  "sink": {...},
  "preconditions": [...],
  "candidate_paths": [...],
  "evidence": [...],
  "score": 0.0
}
```

## 7.5. Baseline variants

### ZH-Static

Không dùng LLM.

```text
static source/sink candidates
+ rule matching
+ ranking
```

### ZH-LLM-Raw

LLM đọc compact repository summaries / candidate APIs.

### ZH-Text-RAG

CWE/OWASP knowledge dưới dạng text retrieval.

## Output cần đo

- Recall@k của ground-truth CWE
- Recall@k của vulnerable location
- candidate count/project
- runtime
- token cost

## Gate

Nếu hypothesis Recall@10 quá thấp, chưa nên đi tiếp sang full CodeQL synthesis.

---

# 8. Phase 2 — Program Graph

## Mục tiêu

Thay raw context bằng program-structure evidence.

## Implementation strategy

### Giai đoạn đầu

Không cần tự viết CPG engine.

Ưu tiên tận dụng:

- CodeQL database;
- CodeQL query results;
- call graph;
- dataflow/taint paths;
- AST/CFG metadata nếu truy xuất được.

### Sau đó

Nếu cần representation thống nhất hơn mới cân nhắc Joern/CPG.

## Các graph slice cần có

### Source-centered slice

```text
source
-> caller
-> def-use
-> branch
-> downstream API calls
```

### Sink-centered slice

```text
upstream values
-> control/data dependencies
-> sink
```

### Source-to-sink slice

Giữ:

- source;
- sink;
- call-chain;
- dataflow;
- sanitizer candidates;
- relevant control conditions.

## Experiment

```text
Raw code
vs
±N lines
vs
CodeQL path
vs
Program Graph slice
```

### Metric

- hypothesis accuracy;
- spec accuracy;
- tokens;
- latency.

---

# 9. Phase 3 — Security Knowledge Graph

## 9.1. Knowledge sources

Bản đầu chỉ nên dùng:

- MITRE CWE;
- OWASP;
- CodeQL existing source/sink models;
- verified CVE examples;
- API security semantics.

Không nên ingest toàn bộ NVD text ngay lập tức.

## 9.2. Chuẩn hoá schema

Ví dụ:

```yaml
cwe: CWE-78
concept: OS Command Injection
sources:
  - untrusted command input
sinks:
  - Runtime.exec
  - ProcessBuilder
sanitizers:
  - strict allowlist
preconditions:
  - attacker_controlled_input
effects:
  - command_execution
```

## 9.3. API-semantic entity

```yaml
api:
  package: java.lang
  class: Runtime
  method: exec
role:
  sink_for:
    - CWE-78
confidence:
source:
  - codeql
  - mitre
```

## 9.4. Graph retrieval

Input:

```text
API candidates + program slice + hypothesis
```

Output:

```text
relevant CWE nodes
source/sink semantics
sanitizers
related weaknesses
```

## Experiment

```text
No knowledge
vs
Text RAG
vs
Security KG
```

---

# 10. Phase 4 — Evidence Graph và USEG

## Mục tiêu

Hợp nhất:

```text
G_P + G_K + G_E
```

thành một external memory có provenance.

## 10.1. Cross-layer edges

Ví dụ:

```text
Program::Runtime.exec
    MATCHES
Knowledge::CommandExecutionSink

Program::request.getParameter
    MATCHES
Knowledge::UntrustedInput

StaticPath::P14
    SUPPORTS
Hypothesis::CWE78

Sanitizer::allowlist
    CONTRADICTS
Hypothesis::CWE78

CodeQLRun::Q32
    VERIFIED_BY
Hypothesis::H12
```

## 10.2. Storage

Prototype:

- NetworkX hoặc SQLite relational tables.

Research-scale:

- Neo4j / Memgraph / graph DB.

### Khuyến nghị

Không dùng graph DB ngay từ ngày đầu.  
Dùng typed Python graph abstraction trước để dễ unit-test.

---

# 11. Phase 5 — Graph retrieval / pruning

Đây có thể là contribution mạnh nhất về resource efficiency.

## 11.1. Input

```text
hypothesis H
USEG G
budget B
```

## 11.2. Output

```text
minimal subgraph G_H
```

## 11.3. Retrieval constraints

Giữ:

- candidate source;
- candidate sink;
- shortest/taint path;
- call context;
- sanitizers;
- relevant CWE concepts;
- contradicting evidence;
- provenance.

Loại:

- unrelated files;
- unrelated symbols;
- redundant path nodes;
- repeated documentation;
- unrelated CWE subtrees.

## 11.4. Algorithms nên thử

### Baseline A — k-hop

```text
all nodes within k hops
```

### Baseline B — path-based

```text
source-to-sink paths only
```

### Baseline C — weighted evidence retrieval

Score:

```text
score(v) =
    a * structural_relevance
  + b * semantic_relevance
  + c * evidence_strength
  + d * provenance_quality
  - e * redundancy
```

### Proposed — budget-aware minimal subgraph

Objective:

```text
maximize information coverage
subject to token_budget <= B
```

## 11.5. Ablation

- no pruning
- top-k nodes
- k-hop
- path-only
- proposed budget-aware pruning

---

# 12. Phase 6 — LLM-assisted taint specification synthesis

## 12.1. Input

Không đưa raw repository.

Chỉ đưa:

```text
hypothesis
minimal program slice
security KG facts
existing evidence
```

## 12.2. Output schema

```json
{
  "sources": [],
  "sinks": [],
  "sanitizers": [],
  "propagators": [],
  "preconditions": [],
  "uncertainties": [],
  "requested_verification": []
}
```

## 12.3. Guardrail

LLM không sinh arbitrary QL code ở bản đầu.

Thay vào đó:

```text
LLM -> normalized specification
template -> CodeQL
```

Ví dụ:

```yaml
role: sink
package: java.lang
class: Runtime
method: exec
target: argument[0]
cwe_candidates:
  - CWE-78
```

Sau đó template compiler sinh QL.

Lợi ích:

- giảm invalid query;
- dễ benchmark spec accuracy;
- reproducible;
- dễ isolate contribution.

---

# 13. Phase 7 — Static verification

## 13.1. CodeQL workflow

```text
normalized spec
-> QL template compiler
-> query execution
-> SARIF/path output
-> path normalization
-> evidence graph update
```

## 13.2. Verification outcome

```text
VERIFIED_PATH
NO_PATH
QUERY_ERROR
TIMEOUT
AMBIGUOUS
```

## 13.3. Evidence sau verification

Mỗi path ghi:

- source;
- sink;
- intermediate nodes;
- sanitizer candidates;
- path length;
- CodeQL query;
- runtime;
- matched hypothesis;
- ground-truth overlap chỉ ở evaluation layer.

---

# 14. Phase 8 — Evidence calibration và selective routing

## 14.1. Feature vector

Có thể bắt đầu bằng:

```text
static_path_exists
source_match_score
sink_match_score
sanitizer_present
kg_consistency
llm_confidence
llm_agreement
path_length
number_of_independent_evidence
contradiction_count
provenance_quality
```

## 14.2. Calibration model

Bắt đầu đơn giản:

- logistic regression;
- isotonic regression;
- Platt scaling.

Không cần neural calibrator.

## 14.3. Decision policy

```text
confidence >= tau_accept:
    ACCEPT

tau_verify <= confidence < tau_accept:
    VERIFY

confidence < tau_verify:
    ABSTAIN
```

## 14.4. VERIFY actions

Có thể gồm:

- retrieve larger subgraph;
- call stronger LLM;
- rerun alternate CodeQL query;
- inspect sanitizer/control path;
- retrieve more KG evidence.

## Experiment

```text
forced binary decision
vs
majority vote
vs
calibrated selective routing
```

---

# 15. Phase 9 — Iterative graph update

## Mục tiêu

Tránh gửi full reasoning history trong prompt.

Workflow:

```text
G_t
  -> retrieve evidence
  -> reason
  -> verify
  -> append new evidence
  -> G_{t+1}
```

LLM call tiếp theo chỉ query state mới.

## Experiment

```text
full conversation history
vs
stateless re-prompt
vs
graph memory
```

Metric:

- tokens;
- latency;
- consistency;
- final F1;
- repeated evidence rate.

---

# 16. Dataset design

## 16.1. Dataset strategy

Không nên chỉ ghi chung chung `CWE-Bench-Java`. Phải chỉ rõ **snapshot nào được dùng cho mục đích nào**.

### A. Legacy benchmark — direct comparability

Dùng cho:

- reproduce CodeQL/IRIS;
- kiểm tra evaluator;
- đối chiếu trực tiếp với số liệu paper;
- sanity check MVP.

Nguồn:

- GitHub: https://github.com/iris-sast/cwe-bench-java
- Hugging Face: https://huggingface.co/datasets/iris-sast/CWE-Bench-Java

Đặc điểm:

```text
120 CVEs
4 CWEs:
CWE-22, CWE-78, CWE-79, CWE-94
```

### B. Extended benchmark — main zero-hint evaluation

Dùng IRIS v2 data:

- https://github.com/iris-sast/iris/tree/v2/data

README v2 hiện mô tả:

```text
213 CVEs
49 CWEs
```

Đây nên là dataset chính để kiểm tra:

- zero-hint trên search space rộng hơn;
- unseen-CWE;
- rare-CWE;
- generalization;
- scalability.

**Quan trọng:** freeze bằng commit SHA ngay khi bắt đầu experiment chính.

### C. Curated source/sink subset

IRIS v2 cung cấp source/sink annotations thủ công cho 50 CVEs.

Dùng riêng cho:

- source precision/recall;
- sink precision/recall;
- specification synthesis evaluation;
- error analysis RQ4.

Không dùng annotation này làm input cho runtime zero-hint.

## 16.2. Runtime view vs evaluation-only view

### Runtime view

Hệ thống được phép thấy:

```text
repository source ở vulnerable revision
README
build/dependency metadata cần thiết để compile/analyze
public source documentation nằm trong repository
```

### Evaluation-only view

Hệ thống không được thấy:

```text
CVE ID
CWE ground-truth label
advisory vulnerability description
fix commit
patch
fixed version source
ground-truth vulnerable methods/lines
manual source/sink annotations
```

Các trường này chỉ evaluator được truy cập.

## 16.3. Leakage prevention bằng code

Không chỉ ghi policy trong tài liệu. Phải enforce bằng package boundary:

```text
src/openiris/data/runtime_view.py
src/openiris/evaluation/ground_truth.py
```

Runtime pipeline **không được import** `ground_truth.py`.

Test bắt buộc:

```text
tests/leakage/test_runtime_manifest_has_no_cve.py
tests/leakage/test_runtime_manifest_has_no_cwe_label.py
tests/leakage/test_runtime_cannot_read_fix_info.py
tests/leakage/test_runtime_cannot_read_advisory.py
```

## 16.4. Dataset inventory report

Mỗi snapshot phải tự động sinh:

```text
reports/datasets/<snapshot_id>/
├── summary.md
├── cwe_distribution.csv
├── repository_distribution.csv
├── build_status.csv
├── duplicate_repository_versions.csv
└── leakage_audit.json
```

`summary.md` tối thiểu phải ghi:

- số benchmark instances;
- số unique GitHub repositories;
- số CWE;
- phân bố CWE;
- số build thành công/thất bại;
- repository xuất hiện nhiều CVE/version;
- missing fix/source/sink metadata;
- snapshot hash.
# 17. Split protocol

Không dùng random split duy nhất.

## Split A — Repository holdout

Không cùng repository giữa train/dev/test.

## Split B — CWE holdout

Ví dụ:

```text
Develop:
CWE-22
CWE-79
CWE-94

Test generalization:
CWE-78
```

Sau đó rotate nếu sample đủ.

## Split C — API/library holdout

Các package/API có trong test không được xuất hiện trong learned API memory.

## Split D — Chronological

Nếu có metadata thời gian:

```text
knowledge cutoff < test vulnerability disclosure date
```

Đây là experiment rất mạnh nếu muốn chứng minh non-memorization.

---

# 18. Baselines cần có

## Static

1. CodeQL
2. CodeQL + heuristic zero-hint candidate generation

## LLM

3. LLM raw repository summary
4. LLM + candidate API list
5. LLM + text-RAG

## Prior-system reference

6. IRIS Oracle-CWE

Phải ghi rõ:

> IRIS Oracle-CWE có nhiều thông tin đầu vào hơn proposed zero-hint system nên là upper-information/reference baseline, không phải apples-to-apples baseline.

## Graph

7. Program Graph only
8. Security KG only
9. Program Graph + Security KG
10. Full USEG

---

# 19. Main ablation matrix

| ID | Configuration |
|---|---|
| A0 | CodeQL |
| A1 | Zero-hint static hypothesis |
| A2 | A1 + raw LLM |
| A3 | A1 + text-RAG |
| A4 | A1 + Program Graph |
| A5 | A1 + Security KG |
| A6 | Program Graph + Security KG |
| A7 | + Evidence Graph / USEG |
| A8 | + graph pruning |
| A9 | + LLM taint-spec synthesis |
| A10 | + CodeQL verification |
| A11 | + calibration |
| A12 | + selective VERIFY/ABSTAIN |
| FULL | complete method |

Không nhất thiết chạy tất cả trên toàn dataset từ đầu.  
Có thể chạy development subset trước.

---

# 20. Experiment matrix

## E1 — Zero-hint hypothesis quality

Output:

```text
CWE Recall@1/3/5/10
Hypothesis Recall@1/3/5/10
```

## E2 — Static verification effectiveness

Output:

```text
Recall
Precision
F1
FDR
#Detected
```

## E3 — Graph context efficiency

Output:

```text
tokens
calls
latency
cost
Delta F1
```

## E4 — Specification quality

Output:

```text
source P/R
sink P/R
sanitizer P/R
propagator P/R
```

## E5 — Calibration

Output:

```text
ECE
Brier
risk-coverage
FDR at fixed coverage
```

## E6 — Generalization

Output:

```text
seen-CWE
unseen-CWE
seen-repo
unseen-repo
unseen-API
```

## E7 — Model scaling

Model chính cho toàn bộ main table:

```text
Qwen2.5-Coder-3B-Instruct-Q4_K_M + llama.cpp + CUDA 12.4
```

Model scaling là experiment phụ, không phải dependency để chạy pipeline:

```text
primary: Qwen2.5-Coder-3B-Instruct-Q4_K_M local
small ablation: Qwen2.5-Coder-1.5B local
optional upper bound: 1 strong API LLM, tách bảng và khai báo chi phí
```

Mục tiêu không phải chứng minh model X tốt nhất mà chứng minh contribution vẫn có ý nghĩa trong ngân sách local cố định. Main claim không được dựa riêng vào API model.

---

# 21. Statistical protocol

Để paper chắc hơn:

## LLM experiments

Nếu inference stochastic:

- ≥3 seeds hoặc repeated runs;
- report mean ± std;
- fixed temperature nếu cần deterministic baseline.

## Comparison

Dùng:

- bootstrap confidence intervals;
- paired bootstrap;
- McNemar test cho per-project detection nếu phù hợp.

## Calibration

Báo:

- ECE;
- reliability diagram;
- Brier score.

---

# 22. Cost accounting

Mỗi LLM call log:

```json
{
  "model": "",
  "prompt_tokens": 0,
  "completion_tokens": 0,
  "latency_ms": 0,
  "estimated_cost_usd": 0.0,
  "hypothesis_id": "",
  "purpose": ""
}
```

Per repository:

```text
total tokens
total calls
total cost
total latency
peak context length
```

Đây là dữ liệu bắt buộc nếu muốn claim resource-efficient.

---

# 23. Repository structure đề xuất

Cấu trúc mới tách rõ **workflow notebook**, **implementation reusable**, **raw run**, **phase result**, **ground truth** và **paper outputs**. `workflows/` chỉ chứa notebook và các script điều phối liên quan; `results/phases/` là nơi duy nhất chứa kết quả đã aggregate/freeze theo phase.

```text
openiris/
├── README.md
├── LICENSE
├── pyproject.toml
├── uv.lock / requirements.lock
├── Makefile
├── .env.example
├── .gitignore
│
├── configs/
│   ├── datasets/
│   │   ├── legacy.yaml
│   │   └── v2_snapshot.yaml
│   ├── models/
│   ├── codeql/
│   ├── retrieval/
│   ├── calibration/
│   └── experiments/
│       ├── rq1/
│       ├── rq2/
│       ├── rq3/
│       ├── rq4/
│       ├── rq5/
│       └── rq6/
│
├── schemas/
│   ├── hypothesis.schema.json
│   ├── specification.schema.json
│   ├── evidence.schema.json
│   ├── verification.schema.json
│   └── run_manifest.schema.json
│
├── prompts/
│   ├── hypothesis/
│   │   └── v001.md
│   ├── spec_synthesis/
│   │   └── v001.md
│   └── triage/
│       └── v001.md
│
├── workflows/                 # chỉ notebook và thin orchestration scripts
│   ├── README.md
│   ├── notebooks/
│   │   ├── phase_00_reproducibility.ipynb
│   │   ├── phase_01_zero_hint_baseline.ipynb
│   │   ├── phase_02_program_graph.ipynb
│   │   ├── phase_03_security_kg.ipynb
│   │   ├── phase_04_evidence_graph.ipynb
│   │   ├── phase_05_graph_retrieval.ipynb
│   │   ├── phase_06_spec_synthesis.ipynb
│   │   ├── phase_07_static_verification.ipynb
│   │   ├── phase_08_calibration.ipynb
│   │   └── phase_09_iterative_update.ipynb
│   └── scripts/
│       ├── common/
│       └── phase_<NN>/
│
├── data/
│   ├── manifests/
│   │   ├── datasets/
│   │   ├── knowledge/
│   │   └── splits/
│   ├── external/              # gitignored/raw third-party downloads
│   │   ├── cwe_bench_legacy/
│   │   ├── cwe_bench_v2/
│   │   └── mitre_cwe/
│   ├── runtime_views/         # sanitized input visible to system
│   ├── ground_truth/          # evaluator-only; never imported by runtime
│   ├── processed/
│   └── cache/
│
├── knowledge/
│   ├── builders/
│   ├── snapshots/
│   └── validators/
│
├── src/
│   └── openiris/
│       ├── data/
│       ├── preprocessing/
│       ├── candidates/
│       ├── program_graph/
│       ├── security_kg/
│       ├── evidence_graph/
│       ├── useg/
│       ├── hypothesis/
│       ├── retrieval/
│       ├── llm/
│       ├── specifications/
│       ├── codeql/
│       ├── calibration/
│       ├── routing/
│       ├── evaluation/
│       ├── logging/
│       └── utils/
│
├── queries/
│   ├── extraction/
│   ├── verification/
│   ├── templates/
│   └── tests/
│
├── scripts/
│   ├── data/
│   │   ├── fetch_dataset.py
│   │   ├── freeze_snapshot.py
│   │   ├── create_runtime_views.py
│   │   └── create_splits.py
│   ├── baselines/
│   │   ├── run_codeql.py
│   │   └── run_iris.py
│   ├── pipeline/
│   │   ├── extract_program_graph.py
│   │   ├── build_security_kg.py
│   │   ├── generate_hypotheses.py
│   │   ├── synthesize_specs.py
│   │   └── verify.py
│   ├── experiments/
│   │   └── run_experiment.py
│   └── analysis/
│       ├── evaluate.py
│       ├── aggregate_runs.py
│       ├── make_tables.py
│       └── make_figures.py
│
├── runs/                      # immutable per-run artifacts; gitignored
│   └── <run_id>/
│       ├── manifest.yaml
│       ├── config.resolved.yaml
│       ├── environment.json
│       ├── hypotheses.jsonl
│       ├── specs.jsonl
│       ├── verification.jsonl
│       ├── decisions.jsonl
│       ├── usage.jsonl
│       ├── metrics.json
│       ├── errors.jsonl
│       └── logs/
│
├── artifacts/                 # generated reusable research artifacts
│   ├── codeql_databases/
│   ├── program_graphs/
│   ├── security_kg/
│   └── useg/
│
├── results/                   # aggregated/frozen, source-controlled khi publish
│   └── phases/
│       ├── phase_00/
│       │   ├── baselines/
│       │   ├── audits/
│       │   ├── model_smoke/
│       │   ├── tables/
│       │   ├── figures/
│       │   ├── report.md
│       │   └── status.json
│       └── phase_<NN>/        # cùng contract cho Phase 1--9
│
├── reports/                   # report dùng chung, không thuộc riêng một phase
│   ├── datasets/
│   ├── cross_phase/
│   └── final/
│
├── paper/
│   ├── tables/
│   ├── figures/
│   └── numbers/
│
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── regression/
│   ├── leakage/
│   └── reproducibility/
│
└── docs/
    ├── architecture.md
    ├── dataset_protocol.md
    ├── experiment_protocol.md
    ├── leakage_policy.md
    ├── metric_definitions.md
    ├── threat_model.md
    ├── decisions.md
    ├── research_log.md
    └── reproducibility.md
```

## 23.1. Quy tắc bố cục

### `src/`

Chỉ chứa implementation reusable. Không hard-code:

- dataset path;
- model;
- CWE;
- experiment ID;
- prompt;
- threshold.

Tất cả phải đi qua config.

### `scripts/`

Entry point dùng chung/CLI cấp project; business logic nằm trong `src/`.

### `workflows/`

Chỉ chứa một notebook canonical cho mỗi phase và thin scripts phục vụ notebook. Notebook phải gọi API/CLI trong `src/` hoặc `scripts/`; không copy lại thuật toán vào cell. Phase chưa implement không được có notebook báo PASS giả.

### `data/ground_truth/`

Evaluator-only. Runtime pipeline không được import hoặc đọc.

### `runs/`

Mỗi lần chạy là **immutable**. Không sửa file trong run cũ.

### `results/`

`results/phases/phase_<NN>/` là nơi duy nhất chứa kết quả đã aggregate/freeze của phase, gồm baseline, audit, table, figure, status và report. Mọi file phải truy ngược được về một hoặc nhiều `run_id`; model/cache/database/raw log lớn vẫn nằm ngoài Git.

### `paper/`

Table/figure phải sinh từ script và có mapping ngược về `run_id`.

### Quan hệ notebook--script--result

```text
workflows/notebooks/phase_<NN>.ipynb
    -> workflows/scripts/phase_<NN>/ hoặc scripts/
    -> src/openiris/
    -> runs/<run_id>/                     # raw, immutable, gitignored
    -> results/phases/phase_<NN>/         # aggregate + report + links
```

Notebook là canonical user interface nhưng không phải canonical implementation. Vì vậy vẫn có thể chạy cùng pipeline headless trong CI bằng chính CLI mà notebook gọi.
# 24. Logging schema bắt buộc

## `hypotheses.jsonl`

```json
{
  "repo": "",
  "hypothesis_id": "",
  "rank": 1,
  "cwe_candidates": [],
  "source": {},
  "sink": {},
  "score": 0.0,
  "evidence_ids": []
}
```

## `specs.jsonl`

```json
{
  "hypothesis_id": "",
  "role": "source",
  "symbol": "",
  "confidence": 0.0,
  "provenance": ""
}
```

## `verification.jsonl`

```json
{
  "hypothesis_id": "",
  "query_id": "",
  "status": "VERIFIED_PATH",
  "paths": [],
  "runtime_ms": 0
}
```

## `decision.jsonl`

```json
{
  "hypothesis_id": "",
  "confidence": 0.0,
  "decision": "ACCEPT",
  "evidence_ids": []
}
```

---

# 24A. Run artifact contract

Mỗi run phải đủ thông tin để một người khác biết chính xác **code nào + data nào + config nào + model nào** tạo ra kết quả.

## `manifest.yaml`

```yaml
run_id: 2026xxxx_rq1_zh_static_001
started_at: ...
git_commit: ...
dirty_worktree: false

dataset:
  snapshot_id: ...
  manifest_sha256: ...
  split_id: ...

toolchain:
  codeql_version: ...
  query_pack_version: ...
  java_version: ...
  python_version: ...

model:
  provider: ...
  model_id: ...
  revision: ...
  temperature: ...
  seed: ...

prompt_versions:
  hypothesis: v001
  spec_synthesis: v001

config_sha256: ...
```

## Run completion invariant

Một run chỉ được đánh dấu `COMPLETE` khi có:

```text
manifest.yaml
config.resolved.yaml
metrics.json
usage.jsonl
errors.jsonl
```

và các artifact phase tương ứng.

Run lỗi vẫn phải giữ manifest + error log để audit.

---

# 24B. Phase control matrix

Mọi phase phải dùng cùng một template:

```text
Goal
Inputs
Implementation tasks
Required outputs
Metrics
Tests
Failure taxonomy
Gate/DoD
Phase report
```

Ngoài output chuyên môn bên dưới, mọi phase bắt buộc có:

```text
workflows/notebooks/phase_<NN>_<slug>.ipynb
workflows/scripts/phase_<NN>/              # chỉ tạo khi cần thin wrapper riêng
results/phases/phase_<NN>/status.json
results/phases/phase_<NN>/report.md
```

Gate của phase phải được tính bằng code và hiển thị ở final notebook cell; không đánh dấu PASS bằng nhận xét thủ công.

## Phase 0 — Reproduction & benchmark freeze

**Inputs**

- legacy dataset snapshot;
- IRIS v1/paper;
- CodeQL pinned version.

**Required outputs**

```text
data/manifests/datasets/...
data/manifests/splits/...
results/phases/phase_00/baselines/codeql/
results/phases/phase_00/baselines/iris/
results/phases/phase_00/report.md
```

**DoD**

- dataset snapshot hash frozen;
- build inventory generated;
- evaluator reproduces ground-truth matching logic;
- CodeQL baseline run is reproducible;
- at least one IRIS reference configuration runs;
- primary Qwen 3B Q4_K_M artifact and local endpoint smoke are verified;
- leakage tests pass.

## Phase 1 — Zero-hint baseline

**Required outputs**

```text
runs/<id>/candidates.jsonl
runs/<id>/hypotheses.jsonl
results/phases/phase_01/tables/recall_at_k.csv
results/phases/phase_01/report.md
```

**DoD**

- runtime receives repository-only view;
- ZH-Static implemented;
- at least one LLM zero-hint baseline implemented;
- Recall@1/3/5/10 measured;
- errors categorized as hypothesis-generation vs ranking failures;
- no test-set tuning.

**Go/No-Go**

Do not proceed to full graph work if Recall@10 is too low to produce meaningful verification candidates.

## Phase 2 — Program Graph

**Required outputs**

```text
artifacts/program_graphs/<snapshot>/<project_slug>/
    nodes.parquet
    edges.parquet
    metadata.json
```

**DoD**

- graph schema validated;
- node source locations resolve back to code;
- deterministic extraction on same CodeQL DB;
- source/sink/path slice serializer tested;
- raw-context vs graph-slice experiment completed.

## Phase 3 — Security KG

**Required outputs**

```text
data/manifests/knowledge/mitre_cwe_<version>.yaml
artifacts/security_kg/<kg_version>/
results/phases/phase_03/report.md
```

**DoD**

- knowledge source/version frozen;
- parser unit tests pass;
- every KG fact has provenance;
- No-KG vs Text-RAG vs Graph-KG comparison exists;
- runtime KG contains no benchmark fix/advisory ground truth.

## Phase 4 — Evidence Graph / USEG

**DoD**

- typed IDs prevent node collisions;
- all cross-layer edges carry provenance;
- hypothesis can be traced to program evidence + knowledge evidence;
- graph state can be serialized/reloaded losslessly;
- schema regression tests pass.

## Phase 5 — Retrieval / pruning

**Required experiment grid**

At least:

```text
no-pruning
k-hop
path-only
top-k
budget-aware
```

Across fixed context budgets, e.g.:

```text
2k / 4k / 8k tokens
```

**DoD**

- retrieval deterministic given graph + config;
- token estimator logged;
- quality-cost trade-off measured;
- no method claims efficiency without showing Delta Recall/F1.

## Phase 6 — LLM specification synthesis

**DoD**

- output validates against JSON schema;
- arbitrary QL generation disabled in MVP;
- invalid specs explicitly logged;
- source/sink P/R measured on curated annotation subset;
- prompt version/hash recorded.

## Phase 7 — CodeQL verification

**Required outputs**

```text
query_source.ql
query_config.json
result.sarif
normalized_paths.jsonl
verification.jsonl
```

**DoD**

- QL template compiler unit-tested;
- timeout/error status standardized;
- SARIF retained;
- normalized paths map to repository locations;
- evaluation overlap only happens after runtime finishes.

## Phase 8 — Calibration & selective routing

**Critical split rule**

Calibration parameters and thresholds are fitted on **calibration/dev only**.

Never choose `tau_accept`/`tau_verify` using test results.

**DoD**

- calibration dataset manifest frozen;
- ECE/Brier reported;
- threshold selection procedure recorded;
- risk-coverage generated;
- test thresholds loaded read-only from frozen calibration artifact.

## Phase 9 — Iterative graph update

Phase này nên là **optional extension cho paper đầu tiên** nếu Phase 1–8 đã đủ story.

Chỉ đưa vào main method nếu experiment chứng minh graph memory cải thiện:

- context cost;
- consistency;
- hoặc effectiveness.

Không nên để Phase 9 làm chậm MVP/core paper.

## Phase report template

Mỗi phase kết thúc phải có:

```text
results/phases/phase_<NN>/report.md
results/phases/phase_<NN>/status.json
```

Template:

```markdown
# Phase N Report
## Goal
## Dataset snapshot / split
## Git commit
## Environment
## Implemented components
## Tests
## Experiments executed
## Key results
## Failures / anomalies
## Decisions made
## Open issues
## Gate decision: PASS / PASS-WITH-RISK / FAIL
## Next phase
```

---

# 25. Timeline triển khai đề xuất

## Tháng 1 — Reproduce và chuẩn hoá benchmark

### Deliverable

- CodeQL baseline;
- IRIS reference run;
- dataset loader;
- evaluator;
- leakage tests;
- run registry.

### Paper value

Chưa đủ paper, nhưng là nền tảng bắt buộc.

---

## Tháng 2 — Zero-hint baseline

### Deliverable

- static candidate extractor;
- repository-only hypothesis generator;
- Recall@k benchmark;
- ZH-static / ZH-LLM / text-RAG baselines.

### Research checkpoint

Nếu zero-hint Recall@10 có tín hiệu tốt, hướng nghiên cứu khả thi.

---

## Tháng 3 — Program Graph

### Deliverable

- CodeQL-based program graph extraction;
- source/sink slices;
- path serialization;
- graph-vs-raw experiment.

---

## Tháng 4 — Security KG

### Deliverable

- CWE/API graph;
- retrieval;
- text-RAG vs graph-KG comparison;
- spec inference experiment.

---

## Tháng 5 — USEG

### Deliverable

- unified schema;
- cross-layer edges;
- provenance;
- graph persistence;
- hypothesis ↔ evidence linking.

---

## Tháng 6 — Minimal evidence retrieval

### Deliverable

- k-hop baseline;
- path-only baseline;
- budget-aware pruning;
- token/cost experiment.

### Potential first strong paper story

```text
Graph-grounded zero-hint vulnerability discovery
+ resource-efficient evidence retrieval
```

---

## Tháng 7 — LLM specification synthesis + CodeQL

### Deliverable

- normalized spec schema;
- QL templates;
- query runner;
- static verification;
- spec precision/recall.

---

## Tháng 8 — Calibration

### Deliverable

- confidence model;
- ACCEPT/VERIFY/ABSTAIN;
- ECE/Brier;
- risk-coverage.

---

## Tháng 9 — Generalization + full ablation

### Deliverable

- unseen repo;
- unseen CWE;
- unseen API;
- full ablation;
- model scaling.

---

## Tháng 10 — Paper freeze

### Deliverable

- final tables;
- plots;
- error analysis;
- case studies;
- artifact README;
- reproducibility script;
- manuscript.

---

# 26. Publication strategy

Không nên cố nhét toàn bộ hệ thống vào một paper nếu contribution trở nên loãng.

## Hướng Paper A — Core discovery

### Story

> Zero-hint repository-level vulnerability discovery grounded by program/security/evidence graphs.

### Trọng tâm

- problem formulation;
- hypothesis generation;
- USEG;
- graph retrieval;
- CodeQL verification.

### Venue profile phù hợp

- software engineering;
- security;
- program analysis.

---

## Hướng Paper B — Resource-efficient reasoning

### Story

> Budget-aware graph retrieval for repository-scale LLM-assisted static analysis.

### Trọng tâm

- minimal evidence subgraph;
- token/cost/latency;
- quality-cost Pareto frontier.

Có thể tách thành paper nếu improvement rất rõ.

---

## Hướng Paper C — Calibrated vulnerability auditing

### Story

> Provenance-aware evidence calibration and selective verification for LLM-assisted SAST.

### Trọng tâm

- confidence;
- abstention;
- risk-coverage;
- false positive reduction.

Chỉ nên tách nếu calibration có đủ novelty độc lập.

---

# 27. Hội nghị mục tiêu theo hướng nghiên cứu

Không khóa cứng vào một venue ngay từ đầu.

## Security-oriented

Phù hợp nếu paper nhấn mạnh:

- real-world vulnerability discovery;
- static verification;
- new vulnerabilities;
- developer security workflow.

Ví dụ nhóm venue:

- USENIX Security
- ACM CCS
- NDSS

## Software Engineering / Program Analysis

Phù hợp nếu paper nhấn mạnh:

- static analysis;
- CodeQL;
- query/specification synthesis;
- repository analysis;
- evaluation methodology.

Ví dụ:

- ICSE
- FSE
- ASE
- ISSTA
- OOPSLA / PLDI tùy mức program-analysis novelty

### Quy tắc chọn venue

```text
Nếu contribution mạnh nhất = security findings
    -> security venue

Nếu contribution mạnh nhất = static analysis method
    -> SE / PL venue

Nếu contribution mạnh nhất = LLM reasoning architecture
    -> ML/AI venue chỉ khi methodology đủ general và evaluation đủ rộng
```

---

# 28. Các kết quả tối thiểu để paper có sức nặng

Một paper mạnh nên có ít nhất:

1. **Một problem formulation rõ ràng**
   - zero-hint repository vulnerability discovery.

2. **Một methodological contribution rõ**
   - USEG hoặc budget-aware graph retrieval.

3. **Một end-to-end system**
   - hypothesis → spec → CodeQL → evidence → decision.

4. **Strong baselines**
   - CodeQL;
   - zero-hint static;
   - raw LLM;
   - text-RAG;
   - IRIS Oracle-CWE reference.

5. **Full ablation**

6. **Efficiency evaluation**

7. **Calibration evaluation**

8. **Generalization**

9. **At least 2–3 detailed case studies**

10. Nếu có thể:
    - tìm được previously unknown vulnerability;
    - hoặc reproduce missed vulnerabilities của CodeQL/IRIS.

---

# 29. Error analysis bắt buộc

Mỗi false negative cần map vào taxonomy.

Ví dụ:

```text
H1: hypothesis not generated
H2: correct CWE but wrong source
H3: correct source but wrong sink
H4: missing propagator
H5: sanitizer misunderstood
H6: CodeQL missing edge
H7: side-effect not modeled
H8: graph retrieval pruned necessary evidence
H9: LLM synthesis error
H10: calibration rejected true finding
```

False positive:

```text
P1: source not attacker-controlled
P2: sink not security-sensitive
P3: sanitizer exists
P4: impossible control path
P5: library API semantics wrong
P6: KG incorrect/outdated
P7: over-approximate CodeQL path
P8: insufficient context
```

Error taxonomy này có thể trở thành một phần quan trọng trong Discussion.

---

# 30. Threats to validity

## Internal validity

- LLM stochasticity;
- prompt sensitivity;
- CodeQL version;
- project build failures;
- incomplete vulnerability labels.

## Construct validity

- FDR của benchmark có thể coi unknown true vulnerability là FP;
- CWE match không đồng nghĩa exploitability;
- fix-location overlap không phải proof-of-exploit.

## External validity

- Java only;
- 4 CWE chính trong CWE-Bench-Java;
- CodeQL-specific implementation;
- repository styles khác nhau.

## Leakage

- pretrained LLM có thể đã thấy CVE/project;
- CWE description có thể leak;
- fix commit không được lộ.

### Mitigation

- chronological split;
- holdout repositories;
- no CVE/fix metadata;
- API/library holdout;
- report model knowledge limitation.

---

# 31. Các rủi ro kỹ thuật lớn

## Risk 1 — Zero-hint search space quá lớn

### Mitigation

Không enumerate tất cả CWE.

Dùng hierarchical narrowing:

```text
repository signals
-> weakness family
-> candidate CWE
-> source/sink hypothesis
```

---

## Risk 2 — USEG quá phức tạp

### Mitigation

Bản đầu chỉ cần:

```text
Program nodes
Security concept nodes
Hypothesis/evidence nodes
```

Không cần graph ontology hoàn chỉnh.

---

## Risk 3 — CodeQL query synthesis lỗi

### Mitigation

Không sinh arbitrary QL.

Dùng:

```text
structured spec -> trusted template compiler
```

---

## Risk 4 — Cost LLM quá cao

### Mitigation

- candidate ranking trước LLM;
- caching;
- graph pruning;
- small model for first-pass;
- strong model chỉ cho VERIFY.

---

## Risk 5 — Không chứng minh được novelty

### Mitigation

Systematic literature review phải chạy song song.

Tạo bảng:

| Paper | Zero-hint | Repo-level | Program graph | Security KG | Evidence graph | Static verification | Calibration | Cost-aware |
|---|---:|---:|---:|---:|---:|---:|---:|---:|

Mọi claim novelty phải dựa trên bảng này.

---

# 32. Minimum Viable Research Prototype

Đây là phiên bản nên implement trước tiên.

```text
Input Java repository
    |
CodeQL candidate extraction
    |
Rule-based zero-hint hypothesis ranking
    |
Minimal Program Graph slice
    |
Small Security KG
    |
LLM structured source/sink inference
    |
CodeQL verification
    |
Simple evidence score
    |
Finding report
```

Chưa cần:

- graph DB;
- multi-agent;
- neural ranking;
- complex ontology;
- sophisticated calibration.

Nếu MVP không tạo signal tốt, dừng để sửa bài toán trước khi mở rộng.

---

# 33. Definition of Done cho MVP

MVP hoàn thành khi chạy được end-to-end trên ít nhất một development subset và sinh:

```text
repo
hypothesis
candidate CWE
source
sink
graph evidence
LLM spec
CodeQL path
confidence
final decision
```

và evaluator tự động sinh:

```text
Recall@k
Precision
Recall
F1
FDR
tokens
calls
latency
cost
```

---

# 34. Definition of Done cho paper-ready system

Paper-ready khi:

- dataset protocol frozen;
- no leakage test pass;
- baselines reproduced;
- all main RQs có experiment;
- ablation complete;
- statistical analysis complete;
- error analysis complete;
- ≥2 model families;
- efficiency table complete;
- calibration plots complete;
- artifact reproducible;
- logs/version/config đầy đủ.

---

# 35. Thứ tự ưu tiên thực tế

Nếu nguồn lực hạn chế, ưu tiên:

## Tier 1 — bắt buộc

1. CodeQL baseline
2. zero-hint hypothesis
3. Program Graph slice
4. Security KG
5. LLM structured spec inference
6. CodeQL verification
7. cost logging
8. ablation

## Tier 2 — paper strengthening

9. USEG
10. graph pruning
11. calibration
12. abstention
13. generalization

## Tier 3 — extension

14. iterative graph memory
15. multiple languages
16. dynamic verification
17. exploitability analysis
18. agentic orchestration

---

# 36. Kế hoạch làm việc theo sprint

## Sprint 1

- reproduce CodeQL;
- dataset loader;
- evaluator;
- leakage guard.

## Sprint 2

- candidate API extraction;
- zero-hint static ranking;
- Recall@k baseline.

## Sprint 3

- Program Graph extraction;
- graph slice serializer;
- raw vs graph context experiment.

## Sprint 4

- Security KG v1;
- KG retrieval;
- text vs graph knowledge experiment.

## Sprint 5

- structured LLM spec synthesis;
- spec evaluator.

## Sprint 6

- CodeQL template compiler;
- verification runner;
- path normalization.

## Sprint 7

- USEG integration;
- provenance.

## Sprint 8

- graph pruning;
- efficiency evaluation.

## Sprint 9

- calibration;
- routing;
- abstention.

## Sprint 10

- generalization;
- full ablation;
- case studies.

---

# 37. Các bảng/figure nên chuẩn bị từ sớm

## Figure 1

Full architecture.

## Figure 2

USEG schema.

## Figure 3

Example zero-hint hypothesis lifecycle.

## Figure 4

Minimal evidence subgraph vs raw context.

## Table 1

Overall comparison.

## Table 2

Hypothesis Recall@k.

## Table 3

Resource efficiency.

## Table 4

Specification quality.

## Table 5

Ablation.

## Figure 5

Risk-coverage.

## Figure 6

Quality-cost Pareto frontier.

## Table 6

Generalization.

---

# 38. Kết quả paper nên kể thành câu chuyện như nào

Một narrative mạnh:

```text
1. Existing LLM-assisted SAST systems usually need a target CWE/CVE.
2. This assumption is unrealistic for repository auditing.
3. Removing the hint creates a huge search/context problem.
4. We solve it by representing program structure, security knowledge,
   and analysis evidence in one graph.
5. The graph allows the system to generate hypotheses and retrieve only
   minimal relevant evidence.
6. LLMs synthesize semantic specifications, while CodeQL verifies paths.
7. Provenance-aware evidence calibration controls false positives and
   allows abstention.
8. The result is a zero-hint system that is both effective and cheaper
   than raw-context/LLM-heavy alternatives.
```

Đây nên là backbone của paper và cả implementation.

---

# 39. Milestone quyết định Go / No-Go

## M1

**Zero-hint Recall@10 có đủ cao?**

Nếu không:
- cải thiện candidate generation;
- chưa build USEG full.

## M2

**Program Graph/KG có giúp hơn raw/text-RAG?**

Nếu không:
- graph contribution yếu;
- cần redesign retrieval.

## M3

**LLM-assisted specs có tạo thêm verified paths?**

Nếu không:
- contribution static-analysis không đủ mạnh.

## M4

**Graph pruning giảm đáng kể cost mà giữ quality?**

Nếu có:
- đây là contribution rất đáng nhấn mạnh.

## M5

**Calibration giảm FDR ở coverage hợp lý?**

Nếu có:
- giữ selective routing trong main method;
- nếu không, chuyển thành appendix/future work.

---

# 40. Kết luận triển khai

Trình tự hợp lý nhất cho hướng nghiên cứu này là:

```text
Reproduce
-> define zero-hint task
-> build zero-hint baseline
-> extract Program Graph
-> build small Security KG
-> synthesize structured hypotheses/specs
-> CodeQL verify
-> unify evidence in USEG
-> optimize retrieval
-> calibrate decisions
-> evaluate generalization
-> freeze paper
```

Điểm cần giữ xuyên suốt toàn bộ dự án:

> **Đừng để graph, LLM hay multi-agent trở thành mục tiêu tự thân.**

Mỗi thành phần phải phục vụ trực tiếp ít nhất một trong ba mục tiêu:

```text
better discovery
better verification
lower resource cost
```

Nếu triển khai theo roadmap này, hướng nghiên cứu có thể hình thành một hệ thống đủ rõ về **problem formulation**, **methodology**, **evaluation** và **research contribution** để nhắm tới các hội nghị security hoặc software engineering cấp cao, thay vì chỉ dừng ở một prototype kết hợp LLM + SAST.

---

# 41. Quality-control checklist

## Dataset

- [ ] Dataset snapshot được pin bằng commit/hash.
- [ ] Legacy 120/4 và v2 extended không bị trộn metric.
- [ ] Số instances / repos / CWEs được inventory tự động.
- [ ] Runtime view và ground truth tách vật lý.
- [ ] Split manifest được version-control.
- [ ] Duplicate repository/version được audit.
- [ ] Build failures được ghi lại, không silently drop.

## Leakage

- [ ] Runtime không thấy CVE.
- [ ] Runtime không thấy ground-truth CWE.
- [ ] Runtime không thấy advisory text.
- [ ] Runtime không thấy patch/fix commit/fixed source.
- [ ] Runtime không thấy curated source/sink labels.
- [ ] Calibration không dùng test labels.
- [ ] Prompt không chứa project-specific ground truth.

## Reproducibility

- [ ] Git commit sạch được log.
- [ ] Dataset hash được log.
- [ ] CodeQL/query-pack version được log.
- [ ] Model ID/revision được log.
- [ ] Prompt version/hash được log.
- [ ] Seed/temperature được log.
- [ ] Resolved config được lưu.
- [ ] Raw output được giữ.
- [ ] Table/figure có thể regenerate bằng script.
- [ ] Notebook của phase chạy được `Restart Kernel and Run All` với profile đã khai báo.
- [ ] Mỗi execution cell hiện trạng thái và link artifact/result.
- [ ] Phase report/status được ghi vào `results/phases/phase_<NN>/`.
- [ ] Qwen GGUF, `llama.cpp`, CUDA và effective GPU offload được log chính xác.

## Experiment quality

- [ ] Baseline protocol frozen trước khi tune proposed method.
- [ ] Main metric definition không đổi giữa chừng.
- [ ] Ablation config chỉ thay đúng module cần kiểm tra.
- [ ] Cost/token/latency logging bật ở mọi LLM experiment.
- [ ] Error taxonomy được gắn vào false positive/negative.
- [ ] Failed/timeout runs vẫn được tính và báo cáo rõ.
- [ ] Mean/std hoặc CI được dùng khi cần.
- [ ] Không cherry-pick seed/model/project.

## Code quality

- [ ] `src/` không hard-code đường dẫn/CWE/model.
- [ ] Schema validation cho mọi artifact JSON/JSONL.
- [ ] Unit tests cho parser/serializer/scorer/compiler.
- [ ] Integration test trên 1–3 tiny repositories.
- [ ] Regression tests cho known benchmark cases.
- [ ] Static type/lint/format check trong CI.
- [ ] Không có business logic chỉ tồn tại trong notebook.

---

# 42. Checklist trước khi bắt đầu code

Thứ tự nên làm ngay:

1. Freeze **legacy** và **v2** dataset snapshots.
2. Sinh dataset inventory report.
3. Tạo `runtime_views/` và `ground_truth/` boundary.
4. Tạo deterministic split manifests.
5. Pin CodeQL/toolchain.
6. Tạo run-manifest + config system trước khi experiment.
7. Reproduce CodeQL baseline.
8. Reproduce một IRIS reference run.
9. Viết evaluator + leakage tests.
10. Chỉ sau đó implement Phase 1 zero-hint baseline.

**Nguyên tắc:** nếu một experiment không thể truy ngược từ số trong paper về `run_id -> config -> code commit -> dataset snapshot`, experiment đó chưa đạt chuẩn paper-ready.

[^qwen-gguf]: Qwen, “Qwen2.5-Coder-3B-Instruct-GGUF,” model repository and Q4_K_M file metadata. https://huggingface.co/Qwen/Qwen2.5-Coder-3B-Instruct-GGUF/tree/f74adce6aa16316c625447af059dbebe4983757c
[^nvidia-p2000]: NVIDIA Developer, “Legacy CUDA GPU Compute Capability,” listing Quadro P2000 under compute capability 6.1. https://developer.nvidia.com/cuda/gpus/legacy
[^cuda13-pascal]: NVIDIA, “CUDA Toolkit 13.0 Release Notes,” deprecated architectures section. https://docs.nvidia.com/cuda/archive/13.0.0/cuda-toolkit-release-notes/index.html#deprecated-architectures
[^llama-release]: ggml-org, “llama.cpp release b10590,” including the Windows CUDA 12 package and CUDA 12.4 runtime asset. https://github.com/ggml-org/llama.cpp/releases/tag/b10590
[^llama-cpp]: ggml-org, “llama.cpp,” CUDA backend and CPU+GPU hybrid inference documentation. https://github.com/ggml-org/llama.cpp
