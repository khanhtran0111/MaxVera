# Phase 0 containers

Build the images in dependency order from the repository root. First fetch the
patched CodeQL release; the downloader verifies the exact 807,846,025-byte file
and SHA-256, and performs no network request when the existing archive verifies.

```powershell
uv run python scripts/toolchain/fetch_codeql.py
```

Then build the pinned Linux/amd64 JDK 17 base:

```powershell
docker build --platform linux/amd64 `
  -t maxvera-phase0:jdk17 `
  docker/phase0
```

Build the patched CodeQL layer. Its Dockerfile independently verifies the same
archive SHA-256 before extraction:

```powershell
docker build --platform linux/amd64 `
  -f docker/phase0/Dockerfile.codeql `
  -t maxvera-phase0:codeql `
  tools/downloads
```

Finally build the local IRIS runtime, which inherits the CodeQL image:

```powershell
docker build --platform linux/amd64 `
  -f docker/phase0/Dockerfile.iris `
  -t maxvera-phase0:iris-local `
  docker/phase0
```

The base image supplies the deterministic smoke case. It does not replace the
legacy matrix: the full 120-instance run still requires the JDK/Maven/Gradle
versions recorded in `build_info.csv`.

Third-party source and generated databases are mounted separately, so the
benchmark ground truth never enters the analysis environment.
