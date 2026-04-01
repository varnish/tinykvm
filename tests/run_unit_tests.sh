#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
FOLDER="${SCRIPT_DIR}/build_unittests"

if [[ ! -f "${ROOT_DIR}/tests/Catch2/CMakeLists.txt" ]]; then
	echo "Catch2 checkout missing; initializing tests/Catch2 submodule..."
	git -C "${ROOT_DIR}" submodule update --init --recursive tests/Catch2
fi

if [[ ! -f "${ROOT_DIR}/tests/Catch2/CMakeLists.txt" ]]; then
	echo "Failed to initialize tests/Catch2/CMakeLists.txt."
	exit 1
fi

mkdir -p "${FOLDER}"
pushd "${FOLDER}" >/dev/null
cmake ../unit -DCMAKE_BUILD_TYPE=Debug
cmake --build . -j4
ctest --verbose "$@"
popd >/dev/null
