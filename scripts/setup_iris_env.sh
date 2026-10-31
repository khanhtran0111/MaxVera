#!/usr/bin/env bash
# One-time environment setup for the IRIS v1 reproduction.
# Idempotent: re-running only performs missing steps and re-verifies pins/checksums.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PINS="$ROOT/iris_repro/config/pins.json"
IRIS="$ROOT/vendor/iris-v1"
DL="$ROOT/tools/downloads"
CONDA_DIR="$ROOT/tools/miniforge3"
JENV="$IRIS/data/cwe-bench-java/java-env"
pin(){ python3 -I -c "import json,sys;d=json.load(open('$PINS'));print(eval('d'+sys.argv[1]))" "$1"; }
log(){ echo "[setup $(date -u +%H:%M:%S)] $*"; }

# 1. IRIS v1 at the frozen commit, submodule at the frozen pointer
IRIS_COMMIT=$(pin "['iris']['commit']"); BENCH_COMMIT=$(pin "['cwe_bench_java']['commit']")
if [ ! -d "$IRIS/.git" ]; then
  git clone --branch v1 --recurse-submodules "$(pin "['iris']['url']")" "$IRIS"
fi
git -C "$IRIS" fetch -q origin v1 || true
git -C "$IRIS" checkout -q "$IRIS_COMMIT" 2>/dev/null || { log "cannot checkout $IRIS_COMMIT (local changes?)"; }
[ "$(git -C "$IRIS" rev-parse HEAD)" = "$IRIS_COMMIT" ] || { log "IRIS HEAD mismatch"; exit 1; }
[ "$(git -C "$IRIS" ls-tree HEAD data/cwe-bench-java | awk '{print $3}')" = "$BENCH_COMMIT" ] || { log "submodule pointer mismatch"; exit 1; }
git -C "$IRIS" submodule update --init --recursive
[ "$(git -C "$IRIS/data/cwe-bench-java" rev-parse HEAD)" = "$BENCH_COMMIT" ] || { log "cwe-bench-java HEAD mismatch"; exit 1; }
log "IRIS $IRIS_COMMIT / cwe-bench-java $BENCH_COMMIT verified"

# 2. Compatibility patch (isolated; see iris_repro/patches/README.md)
PATCH="$ROOT/iris_repro/patches/iris-v1-compat.patch"
if git -C "$IRIS" apply --check "$PATCH" 2>/dev/null; then
  git -C "$IRIS" apply "$PATCH"; log "applied compatibility patch"
elif git -C "$IRIS" apply --reverse --check "$PATCH" 2>/dev/null; then
  log "compatibility patch already applied"
else
  log "compatibility patch neither applies nor is applied; inspect 'git -C $IRIS status'"; exit 1
fi

# 3. Downloads + checksum verification against publisher digests
mkdir -p "$DL"
fetch(){ [ -s "$DL/$2" ] || curl -fL --retry 5 -o "$DL/$2" "$1"; }
for v in 7u80 8u202 17; do fetch "$(pin "['jdks']['$v']['url']")" "$(pin "['jdks']['$v']['file']")"; done
for v in 3.2.1 3.5.0 3.9.8; do u=$(pin "['maven']['$v']"); fetch "$u" "apache-maven-$v-bin.zip"; fetch "$u.sha1" "apache-maven-$v-bin.zip.sha1"; done
for v in 6.8.2 7.6.4 8.9; do u=$(pin "['gradle']['$v']"); fetch "$u" "gradle-$v-bin.zip"; fetch "$u.sha256" "gradle-$v-bin.zip.sha256"; done
fetch "$(pin "['codeql']['url']")" codeql-0.8.3-patched.zip
CI=$(pin "['python_env']['conda_installer']"); fetch "$CI" "$(basename "$CI")"
check(){ local got; got=$($1 "$DL/$2" | awk '{print $1}'); [ "$got" = "$3" ] || { log "CHECKSUM MISMATCH $2: $got != $3"; exit 1; }; log "checksum ok $2"; }
check md5sum    jdk-7u80-linux-x64.tar.gz   "$(pin "['jdks']['7u80']['oracle_md5']")"
check sha256sum jdk-8u202-linux-x64.tar.gz  "$(pin "['jdks']['8u202']['oracle_sha256']")"
check sha256sum jdk-17_linux-x64_bin.tar.gz "$(pin "['jdks']['17']['oracle_sha256']")"
for v in 3.2.1 3.5.0 3.9.8; do check sha1sum "apache-maven-$v-bin.zip" "$(cut -c1-40 "$DL/apache-maven-$v-bin.zip.sha1")"; done
for v in 6.8.2 7.6.4 8.9; do check sha256sum "gradle-$v-bin.zip" "$(cut -c1-64 "$DL/gradle-$v-bin.zip.sha256")"; done
[ "$(stat -c %s "$DL/codeql-0.8.3-patched.zip")" = "$(pin "['codeql']['expected_size_bytes']")" ] || { log "codeql.zip size mismatch"; exit 1; }

# 4. Java toolchains into cwe-bench-java/java-env (layout expected by upstream scripts)
mkdir -p "$JENV"
for v in 7u80 8u202 17; do
  d=$(pin "['jdks']['$v']['dir']"); f=$(pin "['jdks']['$v']['file']")
  [ -x "$JENV/$d/bin/javac" ] || { tar xzf "$DL/$f" -C "$JENV" --no-same-owner; log "extracted $d"; }
done
for v in 3.2.1 3.5.0 3.9.8; do [ -x "$JENV/apache-maven-$v/bin/mvn" ] || unzip -qo "$DL/apache-maven-$v-bin.zip" -d "$JENV"; done
for v in 6.8.2 7.6.4 8.9; do [ -x "$JENV/gradle-$v/bin/gradle" ] || unzip -qo "$DL/gradle-$v-bin.zip" -d "$JENV"; done

# 5. Patched CodeQL 2.15.3 inside the IRIS root (as scripts/setup_environment.sh does)
if [ ! -x "$IRIS/codeql/codeql" ]; then
  tmp="$IRIS/temp_codeql_extract"; rm -rf "$tmp"; mkdir -p "$tmp" "$IRIS/codeql"
  unzip -qo "$DL/codeql-0.8.3-patched.zip" -d "$tmp"; mv "$tmp/codeql"/* "$IRIS/codeql/"; rm -rf "$tmp"
  log "extracted patched CodeQL"
fi
mkdir -p "$IRIS/data/codeql-dbs"
"$IRIS/codeql/codeql" version --format=terse

# 6. Conda environment (Python 3.10) local to this repository
if [ ! -x "$CONDA_DIR/bin/conda" ]; then
  inst=$(ls "$DL"/Miniforge3-*Linux-x86_64.sh | head -1)
  bash "$inst" -b -p "$CONDA_DIR"
fi
if [ ! -x "$CONDA_DIR/envs/iris/bin/python" ]; then
  "$CONDA_DIR/bin/conda" env create -q -f "$ROOT/iris_repro/config/environment.iris.cpu.yml"
fi
"$CONDA_DIR/envs/iris/bin/python" -c "import sys,pandas,torch,transformers,openai,requests;print('python',sys.version.split()[0],'torch',torch.__version__)"
log "setup complete"
