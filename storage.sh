#!/bin/bash
set -e
pushd build
make -j8
popd
# We can't pass a symlink to the main VM, since we allow dynamic linker loading
# there, and TinyKVM refuses to use symlinks for security reasons.

# --rust:
# ./build/storagekvm guest/rust_storage/target/release/demo guest/rust_storage/storage
# --cpp
# ./build/storagekvm guest/storage/main guest/storage/storage

# Parse args
if [ "$1" = "--rust" ]; then
	MAIN=guest/rust_storage/target/release/demo
	SECONDARY=guest/rust_storage/storage
elif [ "$1" = "--cpp" ]; then
	MAIN=guest/storage/main
	SECONDARY=guest/storage/storage
else
	echo "Usage: $0 [--rust|--cpp]"
	exit 1
fi

# Verbose shell
set -x
# If second argument is --gdb, run under gdb
if [ "$2" = "--gdb" ]; then
	gdb --args ./build/storagekvm $MAIN $SECONDARY
else
	# Run normally
	./build/storagekvm $MAIN $SECONDARY
fi
