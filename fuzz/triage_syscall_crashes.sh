#!/usr/bin/env bash
# Group syscall-fuzzer crash artifacts by root-cause signature.
#
#   ./triage_syscall_crashes.sh [crash-dir]
#
# For each artifact this replays it under the sanitizers and reduces the report
# to (error kind, first frame inside lib/tinykvm). Identical signatures are the
# same bug reached by different inputs, so only the count and one representative
# input matter.
set -u

BUILD="$(dirname "$0")/.build-syscall"
CRASHDIR="${1:-$BUILD/crashes}"
FUZZER="$BUILD/syscallfuzzer"
OUT="$BUILD/triage"

mkdir -p "$OUT"
: > "$OUT/signatures.txt"

export ASAN_OPTIONS=detect_leaks=0:handle_segv=0:handle_sigfpe=0:allocator_may_return_null=1
export UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=0

classify() {
	local f="$1"
	local log
	log="$(timeout 60 "$FUZZER" "$f" 2>&1)"

	# Error kind: prefer a sanitizer diagnosis over libFuzzer's generic signal.
	local kind
	kind="$(printf '%s\n' "$log" | grep -oE "AddressSanitizer: [a-z-]+" | head -1)"
	if [ -z "$kind" ]; then
		kind="$(printf '%s\n' "$log" | grep -oE "runtime error: [^']*('[^']*')?" | head -1 \
			| sed 's/ of type .*/ of type .../')"
	fi
	if [ -z "$kind" ]; then
		kind="$(printf '%s\n' "$log" | grep -oE "libFuzzer: (deadly signal|out-of-memory|timeout)" | head -1)"
	fi
	[ -z "$kind" ] && kind="unknown"

	# First frame in the library or the fuzz harness, minus addresses.
	local frame
	frame="$(printf '%s\n' "$log" \
		| grep -oE "in [^ ]+ /home/[^ ]*/(lib/tinykvm|fuzz)/[^ ]+:[0-9]+" \
		| head -1 | sed 's|.*/\(lib/tinykvm\|fuzz\)/|\1/|')"
	[ -z "$frame" ] && frame="$(printf '%s\n' "$log" | grep -oE "/home/[^ ]*/lib/tinykvm/[^ ]+:[0-9]+" \
		| head -1 | sed 's|.*/lib/tinykvm/|lib/tinykvm/|')"
	[ -z "$frame" ] && frame="no-frame"

	printf '%s\t%s\t%s\n' "$kind" "$frame" "$f"
}
export -f classify
export FUZZER

find "$CRASHDIR" -type f -name 'crash-*' -o -type f -name 'oom-*' -o -type f -name 'timeout-*' \
	| sort > "$OUT/artifacts.txt"

echo "triaging $(wc -l < "$OUT/artifacts.txt") artifacts..."
xargs -a "$OUT/artifacts.txt" -P "$(nproc)" -I{} bash -c 'classify "$@"' _ {} \
	>> "$OUT/signatures.txt" 2>/dev/null

echo
echo "=== distinct signatures (count, error, first library frame, example input) ==="
awk -F'\t' '{key=$1"\t"$2; cnt[key]++; if (!(key in ex)) ex[key]=$3}
	END { for (k in cnt) printf "%6d\t%s\t%s\n", cnt[k], k, ex[k] }' \
	"$OUT/signatures.txt" | sort -rn
