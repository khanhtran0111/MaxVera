#!/usr/bin/env bash
set -euo pipefail

if [[ ! -f ./gradlew ]]; then
  echo "MaxVera CodeQL smoke expects ./gradlew in the runtime repository" >&2
  exit 2
fi

# A checkout copied on Windows can contain CRLF even when the upstream wrapper
# is executable on Linux.  Keep the normalized wrapper beside the original so
# Gradle's APP_HOME calculation still resolves gradle/wrapper correctly.
normalized_wrapper="./.maxvera-gradlew"
trap 'rm -f "${normalized_wrapper}"' EXIT
tr -d '\r' < ./gradlew > "${normalized_wrapper}"
chmod 0755 "${normalized_wrapper}"

"${normalized_wrapper}" \
  --no-daemon \
  -Dorg.gradle.dependency.verification=off \
  clean classes
