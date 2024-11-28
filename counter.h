#define uLong unsigned long long

#define PREWARM_RUNS 1000
#define MAX_RUNS 100000
#define CYCLES_PRECISION 0.01

#ifdef QUICK
    #undef PREWARM_RUNS
    #define PREWARM_RUNS 1000
    #undef MAX_RUNS
    #define MAX_RUNS 10000
#endif

#include <immintrin.h>

/// @brief times function f for at least PREWARM_RUNS and at most MAX_RUNS times,
///         or until the difference between two consecutive runs is less than CYCLES_PRECISION %;
///         # of runs is increased by a factor of 10 each time the difference is too large
/// @param f function to time
/// @return median of cycles per single run of f
double measureCycles(void (*f)(), void (*g)()){
    int num_runs = PREWARM_RUNS,
	 flag = 1;
    double cycles, previousCycles = 1, diff;
    uLong start, stop;

    for(int w = 0; w < PREWARM_RUNS; ++w){
        (*f)();
    }
    while(flag){
        (*g)();
        _mm_mfence();
        _mm_lfence();
        start = __rdtsc();
        for (int i = 0; i < num_runs; ++i) {
            (*f)();
        }   
        stop = __rdtsc();
        _mm_lfence();
        cycles = (stop - start) / num_runs;
        diff = abs(cycles - previousCycles);

        if((diff < (CYCLES_PRECISION * cycles) && diff > 0) || num_runs >= MAX_RUNS){
            flag = 0;
        }else{
            previousCycles = cycles;
            num_runs *= 10;
        }
    }
    return cycles;
}
