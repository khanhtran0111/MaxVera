# Experiment protocol

Each experiment is resolved from version-controlled YAML. Secrets are referred
to only by environment-variable name and are never copied into a resolved
config or run manifest.

The legacy reproduction uses:

- IRIS commit `7aa94755d43898a623307935e853b954afc79a5d`;
- CWE-Bench-Java commit `698fb7248ae30cb7f7782d59c841f05ad70ea9cc`;
- IRIS release `2.15.3-patched` (the bundled executable reports CLI 2.15.5)
  and Java query pack 0.8.3;
- an oracle-CWE query mapping, explicitly marked in config.

All subprocess stages use a list of arguments, capture stdout/stderr, record
elapsed time and normalize failure as a status rather than dropping the case.
