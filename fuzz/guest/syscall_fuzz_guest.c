/* Guest program for the syscall fuzzer.
 *
 * Its only job is to produce a realistic, fully-initialized master VM:
 * a loaded ELF with a stack, a heap, and a large writable data-segment
 * region ("scratch") that the harness hands to the fuzzer as a pool of
 * known-valid guest addresses. The fuzzer then drives syscalls directly
 * against forks of this master, so nothing here needs to issue syscalls
 * itself.
 *
 * scratch must be in .data (initialized) so the pages are actually
 * mapped writable by the ELF loader, and must not be optimized away.
 */

#define SCRATCH_SIZE (128 * 1024)

volatile unsigned char scratch[SCRATCH_SIZE] = { 1 };

/* A second, smaller region so the harness has two disjoint mapped areas. */
volatile unsigned char scratch_small[8192] = { 1 };

int main(void)
{
	/* Touch every page so the loader/CoW machinery has them present. */
	for (unsigned i = 0; i < SCRATCH_SIZE; i += 4096)
		scratch[i] = (unsigned char)(i >> 12);
	for (unsigned i = 0; i < sizeof(scratch_small); i += 4096)
		scratch_small[i] = (unsigned char)(i >> 12);
	return 0;
}
