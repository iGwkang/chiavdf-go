#pragma once
#include <stdint.h>
#include <stdbool.h>

typedef struct ConstBytes {
    uint8_t * data;
    int       len;
} ConstBytes;

// need free memory
const char * CreateDiscriminantWrapper(const ConstBytes challenge_hash, uint64_t discriminant_size_bits);

bool VerifyWesolowskiWrapper(const char * discriminant, const ConstBytes x_s, const ConstBytes y_s, const ConstBytes proof_s, uint64_t num_iterations);

bool VerifyNWesolowskiWrapper(const char * discriminant, const ConstBytes x_s, const ConstBytes proof_blob, uint64_t num_iterations, uint64_t disc_size_bits, uint64_t recursion);

void ProveWrapper(const ConstBytes challenge_hash, const ConstBytes x_s,  uint64_t discriminant_size_bits, uint64_t num_iterations, ConstBytes *ret_data);
