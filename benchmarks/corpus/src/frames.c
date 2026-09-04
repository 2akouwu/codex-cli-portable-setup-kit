/* Functions that need a real stack frame (locals, arrays, calls), so a frame-pointer
 * prologue appears at -O0 and disappears at -O2 — the difference the prologue benchmark
 * is supposed to see. */
#include <stdint.h>

#if defined(_WIN32)
#  define RV_EXPORT __declspec(dllexport)
#else
#  define RV_EXPORT __attribute__((visibility("default")))
#endif

RV_EXPORT uint64_t rv_frame_xor(uint64_t seed) {
    volatile uint64_t buf[16];
    for (int i = 0; i < 16; i++) buf[i] = seed * (uint64_t)(i + 1);
    uint64_t acc = 0;
    for (int i = 0; i < 16; i++) acc ^= buf[i];
    return acc;
}

static uint64_t rv_helper(uint64_t a, uint64_t b) { return (a * 31) ^ b; }

RV_EXPORT uint64_t rv_frame_calls(uint64_t a, uint64_t b) {
    uint64_t t = rv_helper(a, b);
    t = rv_helper(t, a);
    return rv_helper(t, b);
}

RV_EXPORT int rv_frame_sum(const int *xs, int n) {
    int total = 0;
    for (int i = 0; i < n; i++) total += xs[i];
    return total;
}
