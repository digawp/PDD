#include <algorithm>
#include <cstring>
#include <set>
#include <string>
#include <vector>
#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "Enclave_t.h"
#include "openssl/dh.h"

// To keep track of the current index
uint32_t p_idx;

// Label for the next record to keep
uint32_t c1;

// Label for the next record to discard
uint32_t c2;

/**
 * This is the "target" permutation. Example how to use:
 *
 * // After Unsealing and all
 * uint32_t target_idx = permutation[label];
 * // Put to appropriate bucket/chunk according to target_idx
 *
 * Afterwards, when doing compaction, just check the label.
 * Still haven't really thought how to manage the chunk number once it reaches S.
 * One thing for sure, it still has the original label so can rearrange to the
 * correct order.
 *
 */
std::vector<uint32_t> permutation;
std::set<std::string> hash_set;

/**
 * @brief      Initialization of PDedup. Generates the target permutation for the number of records given by max.
 *
 * @param[in]  max   The number of records to be permuted
 *
 * @return     1 if successful, 0 otherwise
 */
int init_dedup(uint32_t max) {
    if (permutation.max_size() < max) {
        ocall_print("Not enough memory to accommodate so many records.");
        return 0;
    }
    p_idx = 0;
    c1 = 0;
    c2 = max - 1;
    permutation.reserve(max);
    for (uint32_t i = 0; i < max; ++i) {
        permutation.push_back(i);
    }
    std::random_shuffle(permutation.begin(), permutation.end());
    return 1;
}

sgx_status_t label_chunk(sgx_sealed_data_t* sealed_data, size_t sealed_size) {
    size_t label_size = sizeof(uint32_t);
    size_t unsealed_size = sealed_size - sizeof(sgx_sealed_data_t);
    size_t labeled_sealed_size = sealed_size + label_size;

    uint8_t buf[labeled_sealed_size];
    // size of buf and unsealed_size different
    sgx_status_t status = unseal(sealed_data, sealed_size, buf, unsealed_size);

    if (status != SGX_SUCCESS) {
        ocall_print("Unsealing when labeling chunk failed.");
        return status;
    }

    // Check hash
    size_t digest_size = sizeof(sgx_sha256_hash_t);
    char digest[digest_size];
    status = sgx_sha256_msg(buf, unsealed_size, (sgx_sha256_hash_t*)digest);

    bool is_in_set = hash_set.insert(std::string(digest, digest_size)).second;

    uint32_t label = is_in_set ? c2 : c1;
    // label accordingly. Label is appended at the end of the buf without being sealed(?)
    std::memcpy(&buf[unsealed_size], &label, label_size);

    return status;
}
