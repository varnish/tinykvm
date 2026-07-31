#!/usr/bin/env bash
# Build and run the syscall-emulation fuzzer.
#
#   ./syscall_fuzzer.sh                 # run until interrupted
#   ./syscall_fuzzer.sh -runs=100000    # extra libFuzzer flags are passed through
#
# Findings land in ./.build-syscall/crashes/. Fork mode is on so a crash does
# not end the campaign -- each one is saved and the run continues.
set -e

cd "$(dirname "$0")"
BUILD=.build-syscall

export ASAN_OPTIONS=detect_leaks=0:handle_segv=0:handle_sigfpe=0:allocator_may_return_null=1
export UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=0

: "${CXX:=clang++}"
: "${CC:=clang}"
export CXX CC

mkdir -p "$BUILD"
(cd "$BUILD" && cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo >/dev/null && make -j"$(nproc)" syscallfuzzer)

python3 gen_syscall_seeds.py "$BUILD/seeds"
mkdir -p "$BUILD/corpus" "$BUILD/crashes"

cd "$BUILD"
exec ./syscallfuzzer \
	-fork="$(( $(nproc) / 2 ))" \
	-ignore_crashes=1 \
	-ignore_timeouts=1 \
	-ignore_ooms=1 \
	-timeout=10 \
	-rss_limit_mb=4096 \
	-max_len=4096 \
	-artifact_prefix=crashes/ \
	corpus seeds "$@"
