/* Reproducible benchmark corpus: small exported functions with known behavior.
 * Built by benchmarks/corpus/build.py with every compiler on the host, at -O0 and -O2,
 * so the benchmarks run on binaries anyone can rebuild and redistribute. */
#include <stdint.h>

#if defined(_WIN32)
#  define RV_EXPORT __declspec(dllexport)
#else
#  define RV_EXPORT __attribute__((visibility("default")))
#endif

RV_EXPORT uint64_t rv_add(uint64_t a, uint64_t b) { return a + b; }

/* Mixed boolean-arithmetic identity: equals a + b for all inputs (prove_equiv fodder). */
RV_EXPORT uint64_t rv_mba_add(uint64_t x, uint64_t y) { return (x ^ y) + 2 * (x & y); }

RV_EXPORT uint32_t rv_popcount(uint64_t v) {
    uint32_t c = 0;
    while (v) { v &= v - 1; c++; }
    return c;
}

/* FNV-1a over n bytes. */
RV_EXPORT uint64_t rv_fnv1a(const unsigned char *s, uint64_t n) {
    uint64_t h = 1469598103934665603ULL;
    for (uint64_t i = 0; i < n; i++) { h ^= s[i]; h *= 1099511628211ULL; }
    return h;
}

RV_EXPORT int rv_strlen(const char *s) {
    int n = 0;
    while (s[n]) n++;
    return n;
}

RV_EXPORT const char *rv_banner(void) { return "reverify corpus banner string v1"; }
