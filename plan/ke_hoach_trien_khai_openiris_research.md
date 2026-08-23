# Kế hoạch triển khai nghiên cứu
## Graph-Grounded Zero-Hint Repository-Level Vulnerability Discovery with Resource-Efficient LLM-Assisted Static Analysis

> **Mục tiêu của tài liệu:** chuyển đề xuất nghiên cứu hiện tại thành một roadmap triển khai có thể thực nghiệm, đo lường, viết bài và mở rộng thành hệ thống nghiên cứu hoàn chỉnh.  
> **Phạm vi mặc định:** Java + CodeQL + CWE-Bench-Java, repository-level, zero-hint (không cung cấp CWE/CVE/vulnerability description cho hệ thống khi inference).

---

## 1. Mục tiêu khoa học

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
- LLM API wrapper;
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

Nên ưu tiên:

- một API model mạnh;
- một local/open model.

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
results/baselines/
    codeql.jsonl
    iris_api.jsonl
    iris_local.jsonl
```

## Gate để sang Phase 1

- CodeQL baseline chạy ổn;
- dataset build được phần lớn project cần thiết;
- evaluator khớp logic ground truth của CWE-Bench-Java.

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

## 16.1. Primary dataset

CWE-Bench-Java.

Lý do:

- real repositories;
- compilable;
- fix locations;
- vetted vulnerabilities;
- phù hợp CodeQL;
- trực tiếp đối chiếu IRIS.

## 16.2. Ground truth leakage prevention

Tạo hai views:

### Runtime view

Hệ thống được thấy:

```text
repository source
README
dependency metadata
public docs
```

### Evaluation-only view

Hệ thống không được thấy:

```text
CVE
CWE label
fix commit
patch
vulnerability description
ground-truth vulnerable methods
```

Đây phải là invariant được enforce bằng code.

---

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

Tối thiểu:

```text
1 strong API LLM
1 medium local/open model
1 small model
```

Mục tiêu không phải chứng minh model X tốt nhất mà chứng minh pipeline robust theo model scale.

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

```text
openiris/
├── README.md
├── pyproject.toml
├── configs/
│   ├── datasets/
│   ├── models/
│   ├── codeql/
│   └── experiments/
│
├── data/
│   ├── raw/
│   ├── processed/
│   ├── security_kg/
│   └── splits/
│
├── src/
│   └── openiris/
│       ├── preprocessing/
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
│       └── utils/
│
├── queries/
│   ├── extraction/
│   ├── verification/
│   └── templates/
│
├── scripts/
│   ├── build_codeql_db.py
│   ├── extract_program_graph.py
│   ├── build_security_kg.py
│   ├── generate_hypotheses.py
│   ├── run_verification.py
│   ├── run_experiment.py
│   └── evaluate.py
│
├── experiments/
│   ├── rq1/
│   ├── rq2/
│   ├── rq3/
│   ├── rq4/
│   ├── rq5/
│   └── rq6/
│
├── results/
│   ├── raw/
│   ├── tables/
│   └── figures/
│
├── tests/
│   ├── unit/
│   ├── integration/
│   └── leakage/
│
└── docs/
    ├── architecture.md
    ├── dataset_protocol.md
    ├── threat_model.md
    └── experiment_protocol.md
```

---

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
