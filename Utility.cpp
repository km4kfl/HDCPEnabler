#include "Utility.h"

#include "SmartHandleClass.h"

#include <memory>

inline void fxor(BYTE* a, const BYTE* b, int size) {
    for (int i = 0; i < size; ++i) {
        a[i] ^= b[i];
    }
}

inline void lshift(const BYTE* src, BYTE* dst) {
    for (int i = 0; i < AES_128_BLOCKLEN; ++i) {
        dst[i] = src[i] << 1;
        if (i < AES_128_BLOCKLEN - 1) {
            dst[i] |= ((unsigned char)src[i + 1]) >> 7;
        }
    }
}

void CopyMemoryReverse(void* dst, const void* src, int size) {
    BYTE* _dst = (BYTE*)dst;
    BYTE* _src = (BYTE*)src;

    for (int x = 0; x < size; ++x) {
        _dst[size - 1 - x] = _src[x];
    }
}

HRESULT ComputeOMAC(
    // TODO: change to vector (safety)
    PUCHAR aes_key,
    // TODO: change to vector (safety)
    PUCHAR pb,
    DWORD cb,
    // TODO: change to vector (safety)
    PUCHAR p_tag
) {

    HRESULT hr = S_OK;
    BCryptAlgProv h_alg;
    BCryptKey h_key;
    DWORD cb_key_obj = 0;
    DWORD cb_data = 0;

    struct {
        BCRYPT_KEY_DATA_BLOB_HEADER header;
        UCHAR key[AES_128_KEYSIZE];
    } KeyBlob;

    KeyBlob.header.dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
    KeyBlob.header.dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
    KeyBlob.header.cbKeyData = AES_128_KEYSIZE;
    // TODO: overflow check
    CopyMemory(KeyBlob.key, aes_key, sizeof(KeyBlob.key));

    BYTE rgb_lu[OPM_OMAC_SIZE];
    BYTE rgb_lu_1[OPM_OMAC_SIZE];
    BYTE rbuffer[OPM_OMAC_SIZE];

    if (FAILED(BCryptOpenAlgorithmProvider(
        h_alg.GetPointer(),
        BCRYPT_AES_ALGORITHM,
        MS_PRIMITIVE_PROVIDER,
        0
    ))) {
        throw ProcessFailure("ComputeOMAC: BCryptOpenAlgorithmProvider");
    }

    if (FAILED(BCryptGetProperty(
        h_alg.GetHandle(),
        BCRYPT_OBJECT_LENGTH,
        (PBYTE)&cb_key_obj,
        sizeof(DWORD),
        &cb_data,
        0
    ))) {
        throw ProcessFailure("ComputeOMAC: BCryptGetProperty");
    }

    auto pb_key_obj = std::unique_ptr<BYTE>(new BYTE[cb_key_obj]);

    if (FAILED(BCryptSetProperty(
        h_alg.GetHandle(),
        BCRYPT_CHAINING_MODE,
        (PBYTE)BCRYPT_CHAIN_MODE_CBC,
        sizeof(BCRYPT_CHAIN_MODE_CBC),
        0
    ))) {
        throw ProcessFailure("ComputeOMAC: BCryptSetProperty");
    }

    if (FAILED(BCryptImportKey(
        h_alg.GetHandle(),
        NULL,
        BCRYPT_KEY_DATA_BLOB,
        h_key.GetPointer(),
        pb_key_obj.get(),
        cb_key_obj,
        (PUCHAR)&KeyBlob,
        sizeof(KeyBlob),
        0
    ))) {
        throw ProcessFailure("ComputeOMAC: BCryptImportKey");
    }

    DWORD cb_buf = sizeof(rbuffer);
    ZeroMemory(rbuffer, sizeof(rbuffer));

    if (FAILED(BCryptEncrypt(
        h_key.GetHandle(), rbuffer, cb_buf, NULL, NULL, 0,
        rbuffer, sizeof(rbuffer), &cb_buf, 0
    ))) {
        throw ProcessFailure(__FUNCTION__ ": BCryptEncrypt");
    }

    const BYTE blu_comp_const = 0x87;
    LPBYTE pbl = rbuffer;


    lshift(pbl, rgb_lu);
    if (pbl[0] & 0x80) {
        rgb_lu[OPM_OMAC_SIZE - 1] ^= blu_comp_const;
    }

    lshift(rgb_lu, rgb_lu_1);
    if (rgb_lu[0] & 0x80) {
        rgb_lu_1[OPM_OMAC_SIZE - 1] ^= blu_comp_const;
    }

    h_key = BCryptKey();
    //hr = BCryptDestroyKey(h_key);

    if (FAILED(BCryptImportKey(
        h_alg.GetHandle(), NULL, BCRYPT_KEY_DATA_BLOB, h_key.GetPointer(),
        pb_key_obj.get(), cb_key_obj, (PUCHAR)&KeyBlob,
        sizeof(KeyBlob), 0
    ))) {
        throw ProcessFailure(__FUNCTION__ ": BCryptImportKey[2]");
    }

    PUCHAR pb_data_in_cur = pb;
    cb_data = cb;

    // TODO: consider improving buffer flow safety incase
    //       one day i come stumbling back and make some
    //       stupid change i wont create a bug that never
    //       gets found

    do {
        DWORD cb_buffer = 0;

        if (cb_data > OPM_OMAC_SIZE) {
            CopyMemory(rbuffer, pb_data_in_cur, OPM_OMAC_SIZE);
            if (FAILED(BCryptEncrypt(
                h_key.GetHandle(), rbuffer, sizeof(rbuffer), NULL,
                NULL, 0, rbuffer, sizeof(rbuffer), &cb_buffer, 0
            ))) {
                throw ProcessFailure(__FUNCTION__ ": BCryptEncrypt");
            }

            pb_data_in_cur += OPM_OMAC_SIZE;
            cb_data -= OPM_OMAC_SIZE;
        }
        else {
            if (cb_data == OPM_OMAC_SIZE) {
                CopyMemory(rbuffer, pb_data_in_cur, OPM_OMAC_SIZE);
                fxor(rbuffer, rgb_lu, AES_128_BLOCKLEN);
            }
            else {
                ZeroMemory(rbuffer, OPM_OMAC_SIZE);
                // M[m]
                CopyMemory(rbuffer, pb_data_in_cur, cb_data);
                // Append a 1 and then append the minimum numbers of 0s,
                // so that the total length becomes n-bits. Let X[m] be
                // M[m] xor Y[m-1] xor Lu2.

                // Here append the 1 and then the zeros are already there.
                rbuffer[cb_data] = 0x80;

                // xor with Lu2
                fxor(rbuffer, rgb_lu_1, AES_128_BLOCKLEN);
            }

            // xor Y[m-1] then E(K, X[m])
            if (FAILED(BCryptEncrypt(
                h_key.GetHandle(), rbuffer, sizeof(rbuffer), NULL, NULL,
                0, p_tag, OPM_OMAC_SIZE, &cb_buffer, 0
            ))) {
                throw ProcessFailure(__FUNCTION__ ": BCryptEncrypt");
            }

            cb_data = 0;
        }
    } while (S_OK == hr && cb_data > 0);

    return S_OK;
}

static const char* BASE64_DECODE = "=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::vector<BYTE> decode_base64_str(std::vector<BYTE> in) {
    unsigned int bits = 0;
    unsigned int bits_c = 0;

    auto out = std::vector<BYTE>();

    for (size_t x = 4; x < in.size() + 1; x += 4) {
        int a = in[x - 4];
        int b = in[x - 3];
        int c = in[x - 2];
        int d = in[x - 1];

        const char* a_c = strchr(BASE64_DECODE, a);
        const char* b_c = strchr(BASE64_DECODE, b);
        const char* c_c = strchr(BASE64_DECODE, c);
        const char* d_c = strchr(BASE64_DECODE, d);

        BOOL_THROW(a != NULL);
        BOOL_THROW(b != NULL);
        BOOL_THROW(c != NULL);
        BOOL_THROW(d != NULL);

        int _a_i = (int)(a_c - BASE64_DECODE);
        int _b_i = (int)(b_c - BASE64_DECODE);
        int _c_i = (int)(c_c - BASE64_DECODE);
        int _d_i = (int)(d_c - BASE64_DECODE);

        // padding = is special value (zero)
        int a_i = _a_i > 0 ? _a_i - 1 : _a_i;
        int b_i = _b_i > 0 ? _b_i - 1 : _b_i;
        int c_i = _c_i > 0 ? _c_i - 1 : _c_i;
        int d_i = _d_i > 0 ? _d_i - 1 : _d_i;

        int whole =
            (a_i << (6 * 3)) |
            (b_i << (6 * 2)) |
            (c_i << (6 * 1)) |
            (d_i << (6 * 0));

        int b0 = whole >> 16;
        int b1 = (whole >> 8) & 0xff;
        int b2 = whole & 0xff;

        // only output a byte if there was at least
       // one non padding input
        if (_b_i != 0)
            out.push_back((BYTE)b0);
        if (_c_i != 0)
            out.push_back((BYTE)b1);
        if (_d_i != 0)
            out.push_back((BYTE)b2);
    }

    return out;
}