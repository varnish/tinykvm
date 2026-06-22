#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build_phase3"
UNIT_DIR="${ROOT_DIR}/tests/build_unittests"
OUT_DIR="${ROOT_DIR}/tests/phase3/out"
SCENARIO="${1:-candidate}"
RUNS="${2:-10}"

mkdir -p "${OUT_DIR}"
mkdir -p "${BUILD_DIR}"

TS="$(date +%Y%m%d_%H%M%S)"
CSV_FILE="${OUT_DIR}/phase3_${SCENARIO}_${TS}.csv"
TXT_FILE="${OUT_DIR}/phase3_${SCENARIO}_${TS}.txt"

log() {
  printf '[phase3] %s\n' "$*"
}

warn() {
  printf '[phase3][warn] %s\n' "$*"
}

run_ms() {
  local start_ns end_ns elapsed_ns
  start_ns="$(date +%s%N)"
  if ! "$@" >/dev/null; then
    return 1
  fi
  end_ns="$(date +%s%N)"
  elapsed_ns=$((end_ns - start_ns))
  printf '%s' "$((elapsed_ns / 1000000))"
}

run_elf_case_ms() {
  local spec="$1"
  run_ms bash -lc "cd \"${UNIT_DIR}\" && ./elf \"${spec}\""
}

append_row() {
  local metric="$1"
  local iteration="$2"
  local value="$3"
  local notes="$4"
  printf '%s,%s,%s,%s,%s\n' "${SCENARIO}" "${metric}" "${iteration}" "${value}" "${notes}" >> "${CSV_FILE}"
}

log "Collecting environment metadata"
{
  echo "scenario=${SCENARIO}"
  echo "timestamp=${TS}"
  echo "hostname=$(hostname)"
  echo "kernel=$(uname -r)"
  echo "cpu_model=$(awk -F: '/model name/ {print $2; exit}' /proc/cpuinfo | sed 's/^ //')"
  echo "git_head=$(git -C "${ROOT_DIR}" rev-parse HEAD)"
  echo "git_branch=$(git -C "${ROOT_DIR}" rev-parse --abbrev-ref HEAD)"
} > "${TXT_FILE}"

log "Building project binaries"
cmake -S "${ROOT_DIR}" -B "${BUILD_DIR}" -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build "${BUILD_DIR}" -j4 >/dev/null

BENCH_GUEST="${ROOT_DIR}/guest/guest.elf"
CAN_RUN_BENCH=0

log "Attempting to build guest benchmark binary"
if (
  cd "${ROOT_DIR}/guest" &&
  bash ./build.sh >/dev/null
); then
  if [[ -f "${BENCH_GUEST}" ]]; then
    CAN_RUN_BENCH=1
  else
    warn "guest build succeeded but ${BENCH_GUEST} is missing; lifecycle bench will be skipped"
  fi
else
  warn "guest build failed in this environment; lifecycle bench will be skipped"
fi

log "Building unit tests"
(
  cd "${ROOT_DIR}/tests"
  bash ./run_unit_tests.sh -R "test_basic|test_elf" >/dev/null
)

printf 'scenario,metric,iteration,value_ms,notes\n' > "${CSV_FILE}"

log "Measuring relocation mode runtime lanes (${RUNS} runs each)"
for i in $(seq 1 "${RUNS}"); do
  ms="$(run_elf_case_ms "[Initialize],IRELATIVE strict-fail mode rejects dynamic Rust ELF")"
  append_row "irelative_strict_fail_case" "${i}" "${ms}" "unit test lane"

done
for i in $(seq 1 "${RUNS}"); do
  ms="$(run_elf_case_ms "[Initialize],Verify dynamic Rust ELF relocation support")"
  append_row "irelative_best_effort_case" "${i}" "${ms}" "unit test lane"

done
for i in $(seq 1 "${RUNS}"); do
  ms="$(run_elf_case_ms "[Initialize],IRELATIVE execute-resolver mode runs dynamic Rust ELF")"
  append_row "irelative_execute_resolver_case" "${i}" "${ms}" "unit test lane"

done

if [[ "${CAN_RUN_BENCH}" -eq 1 ]]; then
  log "Measuring lifecycle microbench lines from bench executable"
  BENCH_OUT="${OUT_DIR}/bench_${SCENARIO}_${TS}.log"
  if "${BUILD_DIR}/bench" "${BENCH_GUEST}" > "${BENCH_OUT}" 2>&1; then
    grep -E "VM fork:|vmcall:|timed_vmcall:|VM vmexit time:|Fast reset:|Fast vmcall:" "${BENCH_OUT}" >> "${TXT_FILE}" || true
    echo "bench_status=ok" >> "${TXT_FILE}"
  else
    warn "bench executable failed at runtime; lifecycle bench metrics will be marked unavailable"
    echo "bench_status=failed" >> "${TXT_FILE}"
  fi
else
  BENCH_OUT="(skipped)"
  echo "bench_status=skipped" >> "${TXT_FILE}"
fi

log "Outputs"
log "CSV: ${CSV_FILE}"
log "Report: ${TXT_FILE}"
log "Bench log: ${BENCH_OUT}"
