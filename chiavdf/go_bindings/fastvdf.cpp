extern "C" {
#include "fastvdf.h"
}
#include "../verifier.h"
#include "../prover_slow.h"
#include "../alloc.hpp"

const char * CreateDiscriminantWrapper(const ConstBytes challenge_hash, uint64_t discriminant_size_bits)
{
    std::vector<uint8_t> challenge_hash_bytes(challenge_hash.len);
    for (int i = 0; i < challenge_hash.len; ++i)
        challenge_hash_bytes[i] = challenge_hash.data[i];
    integer D = CreateDiscriminant(challenge_hash_bytes, discriminant_size_bits);
    return strdup(D.to_string().c_str());
}

bool VerifyWesolowskiWrapper(const char * discriminant, const ConstBytes x_s, const ConstBytes y_s, const ConstBytes proof_s, uint64_t num_iterations)
{
    integer D(discriminant);
    form x = DeserializeForm(D, x_s.data, x_s.len);
    form y = DeserializeForm(D, y_s.data, x_s.len);
    form proof = DeserializeForm(D, proof_s.data, proof_s.len);

    bool is_valid = false;
    VerifyWesolowskiProof(D, x, y, proof, num_iterations, is_valid);
    return is_valid;
}

bool VerifyNWesolowskiWrapper(const char * discriminant, const ConstBytes x_s, const ConstBytes proof_blob, uint64_t num_iterations, uint64_t disc_size_bits, uint64_t recursion)
{
    return CheckProofOfTimeNWesolowski(integer(discriminant), x_s.data, proof_blob.data, proof_blob.len, num_iterations, disc_size_bits, recursion);
}

void ProveWrapper(const ConstBytes challenge_hash, const ConstBytes x_s,  uint64_t discriminant_size_bits, uint64_t num_iterations, ConstBytes *ret_data)
{
    std::vector<uint8_t> challenge_hash_bytes(challenge_hash.len);
    for (int i = 0; i < challenge_hash.len; ++i)
        challenge_hash_bytes[i] = challenge_hash.data[i];

    integer D = CreateDiscriminant(
            challenge_hash_bytes,
            discriminant_size_bits
    );
    form x = DeserializeForm(D, x_s.data, x_s.len);
    auto result = ProveSlow(D, x, num_iterations);

    if (!result.empty())
    {
        ret_data->len = result.size();
        ret_data->data = (uint8_t *)malloc(ret_data->len);
        memcpy(ret_data->data, &result[0], ret_data->len);
    }
}
