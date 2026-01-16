#!/usr/bin/env sh
# ---------------------------------------------------------------------------
# Initialize project-local state
# ---------------------------------------------------------------------------
# Creates .project-local/state.json from the committed example if it does not
# already exist. Safely exits without modifying an existing file.
#
# This script is POSIX-compatible and tested under WSL/Linux.
# ---------------------------------------------------------------------------

set -eu

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [ -z "${REPO_ROOT}" ]; then
  echo "Error: could not determine repository root." >&2
  exit 1
fi

cd "${REPO_ROOT}"

STATE_DIR=".project-local"
EXAMPLE_FILE="${STATE_DIR}/state.example.json"
TARGET_FILE="${STATE_DIR}/state.json"

# Ensure the directory exists
if [ ! -d "${STATE_DIR}" ]; then
  mkdir -p "${STATE_DIR}"
fi

# Abort if example file is missing
if [ ! -f "${EXAMPLE_FILE}" ]; then
  echo "Error: example state file not found at ${EXAMPLE_FILE}" >&2
  exit 1
fi

# Create state.json only if it does not already exist
if [ -f "${TARGET_FILE}" ]; then
  echo "✔ ${TARGET_FILE} already exists – nothing to do."
else
  cp "${EXAMPLE_FILE}" "${TARGET_FILE}"
  echo "✔ Created ${TARGET_FILE} from example schema."
fi
