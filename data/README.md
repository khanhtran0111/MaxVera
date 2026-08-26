# Data layout

`raw/` is immutable after download. Normalization writes to `interim/`; release
manifests, splits and isolated views live in `processed/`. Analysis jobs may read
only `processed/analysis_input`; evaluator jobs own `processed/evaluator_only`.
Generated repositories, databases, graphs and protected views are ignored by Git.
