#pragma once
#include "framework.h"
#include "AppExceptions.h"

#include <vector>

#define AES_128_KEYSIZE 16
#define AES_128_BLOCKLEN 16
#define OPM_OMAC_SIZE 16

template<typename A, typename B> A range_check(B val, B low, B high) {
    if (val < low || val > high) {
        throw OverflowFailure();
    }
    return (A)val;
}
std::vector<BYTE> decode_base64_str(std::vector<BYTE> in);
HRESULT ComputeOMAC(
    // TODO: change to vector (safety)
    PUCHAR aes_key,
    // TODO: change to vector (safety)
    PUCHAR pb,
    DWORD cb,
    // TODO: change to vector (safety)
    PUCHAR p_tag
);
inline void fxor(BYTE* a, const BYTE* b, int size);
inline void lshift(const BYTE* src, BYTE* dst);
void CopyMemoryReverse(void* dst, const void* src, int size);