#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <malloc.h>

static long nprimes = 0;

int main(int argc, char** argv)
{
	char* test = (char *)malloc(14);
	strcpy(test, argv[1]);
	printf("%.*s\n", 13, test);
	free(test);

	static const int N = 1000000;
	char prime[N];
	memset(prime, 1, sizeof(prime));
	for (long n = 2; n < N; n++)
	{
		if (prime[n]) {
			nprimes += 1;
			for (long i = n*n; i < N; i += n)
				prime[i] = 0;
		}
	}
	return 666;
}

extern "C" __attribute__((used))
int test_return()
{
	return 666;
}

extern "C" __attribute__((used))
void test_ud2()
{
	asm("ud2");
}

extern "C" __attribute__((used))
int test_read()
{
	assert(nprimes == 78498);
	return 200;
}

static int t = 0;

extern "C" __attribute__((used))
void test_write()
{
	asm("" ::: "memory");
	assert(t == 0);
	asm("" ::: "memory");
	t = 1;
	asm("" ::: "memory");
	assert(t == 1);
}

static int cow = 0;

extern "C" __attribute__((used))
int test_copy_on_write()
{
	assert(cow == 0);
	cow = 1;
	return 666;
}

extern "C" __attribute__((used))
long test_syscall()
{
	register long status asm("rdi") = 555;
	long ret = 60;
	asm("syscall" : "+a"(ret) : "r"(status) : "rcx", "r11", "memory");
	return ret;
}

extern "C" __attribute__((used))
long test_malloc()
{
	int *p = (int *)malloc(1024 * 1024 * 1);
	*p = 44;
	return (long)p;
}


#include <array>
#include <cmath>
#include <vector>
#include "/home/gonzo/git/vmprograms/examples/lodepng/lodepng.h"

inline constexpr uint32_t bgr24(uint32_t r, uint32_t g, uint32_t b) {
	return r | (g << 8) | (b << 16) | (255 << 24);
}

static constexpr std::array<uint32_t, 16> color_mapping {
	bgr24(66, 30, 15),
	bgr24(25, 7, 26),
	bgr24(9, 1, 47),
	bgr24(4, 4, 73),
	bgr24(0, 7, 100),
	bgr24(12, 44, 138),
	bgr24(24, 82, 177),
	bgr24(57, 125, 209),
	bgr24(134, 181, 229),
	bgr24(211, 236, 248),
	bgr24(241, 233, 191),
	bgr24(248, 201, 95),
	bgr24(255, 170, 0),
	bgr24(204, 128, 0),
	bgr24(153, 87, 0),
	bgr24(106, 52, 3),
};

inline void encode_color(uint32_t& px, int count, int max_count)
{
	px = color_mapping[count & 15];
}

using fractalf_t = float;

// Function to draw mandelbrot set
template <int DimX, int DimY, int MaxCount>
__attribute__((optimize("unroll-loops")))
std::array<uint32_t, DimX * DimY>
fractal(fractalf_t left, fractalf_t top, fractalf_t xside, fractalf_t yside)
{
	std::array<uint32_t, DimX * DimY> bitmap {};

	// setting up the xscale and yscale
	const fractalf_t xscale = xside / DimX;
	const fractalf_t yscale = yside / DimY;

	// scanning every point in that rectangular area.
	// Each point represents a Complex number (x + yi).
	// Iterate that complex number
	for (int y = 0; y < DimY / 2; y++)
	#pragma GCC unroll(8)
	for (int x = 0; x < DimX; x++)
	{
		fractalf_t c_real = x * xscale + left;
		fractalf_t c_imag = y * yscale + top;
		fractalf_t z_real = 0;
		fractalf_t z_imag = 0;
		int count = 0;

		// Calculate whether c(c_real + c_imag) belongs
		// to the Mandelbrot set or not and draw a pixel
		// at coordinates (x, y) accordingly
		// If you reach the Maximum number of iterations
		// and If the distance from the origin is
		// greater than 2 exit the loop
		#pragma GCC unroll 4
		while ((z_real * z_real + z_imag * z_imag < 4)
			&& (count < MaxCount))
		{
			// Calculate Mandelbrot function
			// z = z*z + c where z is a complex number
			fractalf_t tempx =
				z_real * z_real - z_imag * z_imag + c_real;
			z_imag = 2 * z_real * z_imag + c_imag;
			z_real = tempx;
			count++;
		}

		encode_color(bitmap[x + y * DimX], count, MaxCount);
	}
	for (int y = 0; y < DimY / 2; y++) {
		memcpy(&bitmap[(DimY-1 - y) * DimX], &bitmap[y * DimX], 4 * DimX);
	}
	return bitmap;
}

asm(".global backend_response\n" \
".type backend_response, function\n" \
"backend_response:\n" \
"	mov $0xFFFF, %eax\n" \
"	out %eax, $0\n");

extern "C" void __attribute__((noreturn))
backend_response(const void *t, uint64_t, const void *c, uint64_t);

extern "C" __attribute__((used))
long test_expensive()
{
	constexpr int counter = 0;
	constexpr size_t width  = 512;
	constexpr size_t height = 512;

	const fractalf_t factor = powf(2.0, counter * -0.1);
	const fractalf_t x1 = -1.5;
	const fractalf_t x2 =  2.0 * factor;
	const fractalf_t y1 = -1.0 * factor;
	const fractalf_t y2 =  2.0 * factor;

	auto bitmap = fractal<width, height, 120> (x1, y1, x2, y2);
	auto* data = (const uint8_t *)bitmap.data();

	std::vector<uint8_t> png;
	lodepng::encode(png, data, width, height);

	const char ctype[] = "image/png";
	backend_response(ctype, sizeof(ctype)-1, png.data(), png.size());
}
