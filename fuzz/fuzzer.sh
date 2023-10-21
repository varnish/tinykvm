export ASAN_OPTIONS=disable_coredump=0::unmap_shadow_on_exit=1::handle_segv=0::handle_sigfpe=0

set -e
mkdir -p .build
pushd .build
cmake ..
make -j4
popd

echo "Starting: ./build/elffuzzer -fork=1 -handle_fpe=0"
./.build/elffuzzer -fork=8 -max_len=32768 -handle_fpe=0 -handle_segv=0 -handle_abrt=0 $@
