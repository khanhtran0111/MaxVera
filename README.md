# maxvera

## IRIS v1 reproduction (GPT-OSS 20B)

Faithful reproduction of IRIS (ICLR 2025, `iris-sast/iris@v1`) on CWE-Bench-Java with
`openai/gpt-oss-20b` via OpenRouter. See [iris_repro/README.md](iris_repro/README.md) for setup,
tmux launch, monitoring, resume and evaluation commands, and
[iris_repro/REPRODUCTION_REPORT.md](iris_repro/REPRODUCTION_REPORT.md) for the report.

```bash
scripts/setup_iris_env.sh                 # one-time environment setup
scripts/start_iris_tmux.sh --full         # launch (tmux session iris_repro_v1)
scripts/check_iris_status.sh              # status of runs/LATEST
scripts/resume_iris_reproduction.sh RUN   # resume
```
