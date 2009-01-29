
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <time.h>

// Есть мысли по увеличению производительности, их надо обкатывать.

// i686 Intel(R) Pentium(R) 4 CPU 2.00GHz
//
// r15: 28.59 sec, 1049 alloc/free per sec

namespace {
const uint32_t opcount = 30000;
const uint32_t ptrcount = 1000;
const uint32_t blocksize = 32768;	// это дает примерно 16 мегабайт...
}

int main (int argc, char **argv)
{
	void *ptrs[ptrcount] = {0};

	// Инициализируем генератор - константой, чтобы обеспечить воспроизводимость
	srand(0);

	struct timespec start, stop;
	clock_gettime(CLOCK_REALTIME, &start);

	for (uint32_t i = 0; i < ptrcount; i++) {
		ptrs[i] = malloc(rand() % blocksize + 1);
	}

	for (uint32_t c = 0; c < opcount - ptrcount; c++) {
		int i = rand() % ptrcount;
		free(ptrs[i]);
		ptrs[i] = malloc(rand() % blocksize + 1);
	}

	for (uint32_t i = 0; i < ptrcount; i++) {
		free(ptrs[i]);
	}

	clock_gettime(CLOCK_REALTIME, &stop);
	double run_time = (stop.tv_sec - start.tv_sec) + (double)(stop.tv_nsec - start.tv_nsec) / 1000000000.0;

	printf ("%.2f sec, %u alloc/free per sec\n", run_time, uint32_t(opcount / run_time));
}
