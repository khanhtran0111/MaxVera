# Full reproduction executions — 2026-10-21

Historical execution record. The user-requested cleanup removed the reproduction outputs and logs referenced below; on 23 October the retained machine-readable summaries were also removed. These runs cannot be resumed. See the [current recheck](research_smoke_2026-10-23.md) for present status.

## Fast run (historical)

The user explicitly requested runtime/flow optimization and approved changing the fixed provider while retaining GPT-OSS-20B. The previous AkashML run was stopped at a request boundary at 21:11 UTC+7; its artifacts and paid-request history remain intact.

- Session: `maxvera-repro-fast-20261021T142440Z`.
- Run: `repro_fast_20261021T142440Z`, all 120 canonical cases; CLI started 21:25:49 UTC+7.
- Config: `configs/pipelines/reproduce_fast.yaml`; model profile: `configs/models/gpt_oss_20b_openrouter_fast.yaml`; process provider override: `MAXVERA_OPENROUTER_PROVIDER=groq`.
- Logs/state: `logs/reproduction_sessions/20261021T142440Z/`; outputs: `results/reproduction/repro_fast_20261021T142440Z/`.
- Implementation hash: `44ac35e1202ae9499a2de26f3e2bb399e36de2a4c2de7ab0643b196995ad75b5`.

This is a fresh run with empty paid journals. Provider changes are not applied to old request keys or mixed with prior AkashML specifications. Original source/CWE/prompt/query/evaluation methods, sampling and 2048-token output cap remain. Project/model requests remain sequential; no unsafe concurrent journal writes or overlapping unpriced requests are introduced.

Measured bottlenecks were fixed 30-second sleeps after completed responses and60–600-second429 backoff. The fast profile sets no fixed completion sleep and 1–30-second bounded backoff, honoring longer provider Retry-After. A valid single JSON Markdown fence no longer triggers another paid generation. Model/budget failures swallowed by upstream fail the enclosing stage and block later calls instead of publishing partial output as success.

After these fixes, the same 6 diagnostic prompts (3 API labeling,3 context filtering) succeeded through the actual journal client in 7.840 seconds on Groq (6 attempts) versus 107.146 seconds on AkashML (7 attempts, including one 429). This is a small live diagnostic, not a full-run runtime guarantee or a scientific accuracy comparison. Initial Groq direct probes also encountered one 429, so provider availability remains variable. All 37 diagnostic attempts across the provider/probe checks had known total cost USD 0.003986665. Evidence: `logs/runtime_optimization_20261021T141224Z/benchmark_summary.json`, raw/private probe logs, `live_journal_summary.json`, and `verification.json`.

First live pipeline check at 21:32:10 UTC+7: DSpace reached `llm_specs`, accepted 18 unique prompt responses in 34 seconds, with median transport latency 1.171 seconds. One unusable received response was retried with its cost recorded; this is not a completed case or an all 120-case ETA. Evidence: `logs/runtime_optimization_20261021T141224Z/first_full_progress.json`.

Final code verification: 393 default tests passed, 2 opt-in CodeQL fixtures skipped (18.71 seconds), lint passed, mypy passed 126 configured source files; independent review found no remaining blocker. Fresh doctor and full-selection dry-run exited 0. The supervisor retains the 20 GiB disk guard, source/config hash guard, per-case ceilings, frozen checksums and separate 120-case `iris_paper` evaluation after completion. Build coverage/storage/future provider availability remain unproven; no completed full metric is claimed.

```bash
tmux attach -t maxvera-repro-fast-20261021T142440Z
```

Window 0 is workflow; window 1 is progress. Ctrl+b then 1 switches to progress; Ctrl+b then d detaches without stopping execution.

## Earlier AkashML run (stopped)

The user explicitly requested reproduction in a new tmux session after review of the repaired LLM transport. This starts full mode directly, without repeating the long smoke solely for that repair.

- Session: `maxvera-repro-full-20261021T092505Z`.
- Run: `repro_full_20261021T092505Z`, all 120 unique canonical cases.
- Full CLI started: **16:27:01 UTC+7**, 2026-10-21.
- Logs and live state: `logs/reproduction_sessions/20261021T092505Z/`.
- Output: `results/reproduction/repro_full_20261021T092505Z/`.
- Implementation hash: `964eca27a850a39235974a139ddc9f01463327eeadb12518f93f03208602391d`.

Initial verification: doctor exit0; full config/selection dry-run exit0; expected120 selected cases; pinned IRIS/dataset revisions match; no other active pipeline/model worker at launch; approximately284.6GiB free. The implementation had381 passing default tests (two opt-in CodeQL fixtures skipped), clean lint/type checks and isolated live API response-repair checks. See `llm_response_repair_2026-10-21.md` for their exact scope and limitations.

The new workflow runs the configured full pipeline with one project/model request at a time. It keeps the existing per-case ceilings:1,000 attempts,8,000,000 conservative input reservation units,2,048,000 reserved output tokens,USD1 and24hours. The output cap, pinned model/provider and30-second completion pacing are unchanged.

The supervisor polls disk space and stops the child process tree below20GiB free rather than deleting artifacts. It checks implementation/config hashes during subprocess execution and stops if they change. Logs are outside frozen scientific outputs. After normal pipeline completion, including completion with failed cases, it verifies frozen checksums and all 120 case records, then runs isolated `iris_paper` evaluation and checks the120-case evaluation denominator. A failed case remains in the denominator. No automatic fresh run or retry of an uncertain journal is scheduled.

Remaining limits are recorded in `preflight.json`:118 other projects were not pre-built; four obsolete Spring EBR coordinates remain quarantined/unresolved; full retained-output storage demand is unknown; provider/permanent/uncertain failures can still stop individual cases. That run is now stopped; its results are not reported as a completed benchmark.

## View

```bash
tmux attach -t maxvera-repro-full-20261021T092505Z
```

Historically, window1 was the15-second progress monitor and window0 the workflow log. The session and its previous smoke evidence have since been removed by the23 October cleanup; these commands are a record of the former run, not a live session.
