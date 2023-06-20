//
// COPYRIGHT (c) 2023 L. K. McGuire Jr.
// ALL RIGHTS RESERVED
// 
// THIS PROGRAM MAY BE FREELY USED BY THE U.S. GOVERNMENT. THE U.S.
// GOVERNMENT MAY DERIVE FROM, RETRANSMIT, RELICENSE, OR USE THIS
// SOFTWARE IN ANY WAY, SHAPE OR FORM. ANY DISPUTES OR ISSUES SHOULD 
// BE RESOLVED BY A JUDGE IN U.S. TERRITORY AND THIS JUDGE SHOULD 
// RULE IN THE BEST INTEREST OF ALL PARTIES.
// 

#include "framework.h"
#include "test.h"

#include <dshow.h>
#include <strmif.h>
#include <wincrypt.h>
#include <d3d11.h>
#include <initguid.h>
#include <dxva.h>
#include <bcrypt.h>

#include <optional>
#include <memory>
#include <vector>
#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>

inline void fxor(BYTE *a, const BYTE *b, int size) {
    for (int i = 0; i < size; ++i) {
        a[i] ^= b[i];
    }
}

#define AES_128_KEYSIZE 16
#define AES_128_BLOCKLEN 16

inline void lshift(const BYTE *src, BYTE *dst) {
    for (int i = 0; i < AES_128_BLOCKLEN; ++i) {
        dst[i] = src[i] << 1;
        if (i < AES_128_BLOCKLEN - 1) {
            dst[i] |= ((unsigned char)src[i + 1]) >> 7;
        }
    }
}

void CopyMemoryReverse(void* dst, const void* src, int size) {
    BYTE *_dst = (BYTE*)dst;
    BYTE *_src = (BYTE*)src;

    for (int x = 0; x < size; ++x) {
        _dst[size - 1 - x] = _src[x];
    }
}

class ProcessFailure : public std::exception {
private:
    std::string msg;
public:
    ProcessFailure(std::string msg) : msg(msg) {
    }

    std::string GetMessage() {
        return msg;
    }
};

class OverflowFailure : public std::exception {
};

class ObjectNotInitialized : public std::exception {
public:
    ObjectNotInitialized() {
    }

    ~ObjectNotInitialized() {
    }
};

class SuspectBuggyUsage : public std::exception {
public:
    SuspectBuggyUsage() {
    }

    ~SuspectBuggyUsage() {
    }
};

template<typename A, typename B> A range_check(B val, B low, B high) {
    if (val < low || val > high) {
        throw OverflowFailure();
    }
    return (A)val;
}

// TODO: split into DEF and IMPL so it can be moved into its own header/source files
#define SMARTHANDLECLASS(TYPE, HANDLE_TYPE, DEALLOC_CALL) \
    class TYPE { \
        private: \
        HANDLE_TYPE h; \
        public: \
        TYPE () { \
            h = NULL; \
        } \
        TYPE(const TYPE& other) = delete; \
        TYPE& operator=(TYPE& other) = delete; \
        TYPE& operator=(TYPE&& other) noexcept { \
            if (h != NULL) { \
                DEALLOC_CALL; \
            } \
            h = other.h; \
            other.h = NULL; \
            return *this; \
        } \
        TYPE(HANDLE_TYPE h) { \
            this->h = h; \
        } \
        HANDLE_TYPE* GetPointer() { \
            if (h != NULL) { \
                throw SuspectBuggyUsage(); \
            } \
            return &h; \
        } \
        HANDLE_TYPE GetHandle() { \
            return h; \
        } \
        ~TYPE() { \
            if (h != NULL) { \
                DEALLOC_CALL; \
            } \
        } \
    };

SMARTHANDLECLASS(BCryptKey, BCRYPT_KEY_HANDLE, BCryptDestroyKey(h))
SMARTHANDLECLASS(BCryptAlgProv, BCRYPT_ALG_HANDLE, BCryptCloseAlgorithmProvider(h, 0))
SMARTHANDLECLASS(CryptKey, HCRYPTKEY, CryptDestroyKey(h))
SMARTHANDLECLASS(CryptContext, HCRYPTPROV, CryptReleaseContext(h, 0))

template<typename T> class COMIFaceWrapper {
private:
    T* p;
public:
    COMIFaceWrapper() {
        p = NULL;
    }

    COMIFaceWrapper<T>(const COMIFaceWrapper<T>& other) = delete;
    COMIFaceWrapper<T>& operator=(COMIFaceWrapper<T>& other) = delete;

    COMIFaceWrapper<T>& operator=(COMIFaceWrapper<T>&& other) noexcept {
        p = other.p;
        other.p = NULL;
        return *this;
    }

    COMIFaceWrapper<T>(GUID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, const IID &riid) {
        p = NULL;

        if (FAILED(CoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, (LPVOID*)&p))) {
            std::ostringstream s;

            s << "COMIFaceWrapper<T> rclsid=" << rclsid.Data1 << "-"
                << rclsid.Data2 << "-" << rclsid.Data3 << "-" << rclsid.Data4
                << " pUnkOuter=" << (SIZE_T)pUnkOuter << " dwClsContext=" << dwClsContext
                << " riid=" << riid.Data1 << "-" << riid.Data2 << "-" << riid.Data3 << "-"
                << riid.Data4;

            throw ProcessFailure(
                s.str()
            );
        }
    }

    T* Object() {
        if (p == NULL) {
            throw ObjectNotInitialized();
        }
        return p;
    }

    T** Pointer() {
        if (p != NULL) {
            throw SuspectBuggyUsage();
        }
        return &p;
    }

    T* operator-> () {
        if (p == NULL) {
            throw ObjectNotInitialized();
        }
        return p;
    }

    ~COMIFaceWrapper() {
        if (p != NULL) {
            p->Release();
        }
    }
};

#define OPM_OMAC_SIZE 16

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

#define STR(x) #x
#define STR2(x) STR(x)
// TODO: replace everything with this nice macro to automate building the error message and help with errors across
//       different versions
#define THROW_MSG(exp) __FUNCTION__ ":" __FILE__ ":" STR2(__LINE__) ":" STR(exp)
#define HRESULT_THROW(exp) if (FAILED((exp))) { throw ProcessFailure(THROW_MSG(exp)); }
#define BOOL_THROW(exp) if ((exp) == FALSE) { throw ProcessFailure(THROW_MSG(exp)); }

const char* BASE64_DECODE = "=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

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

        int _a_i = (a_c - BASE64_DECODE);
        int _b_i = (b_c - BASE64_DECODE);
        int _c_i = (c_c - BASE64_DECODE);
        int _d_i = (d_c - BASE64_DECODE);

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

class HDCPHelper {
private:
    CryptContext            h_crypt_prov;
    CryptKey                m_h_aes_key;
    CryptKey                h_driver_public_key;
    std::vector<BYTE>       aes_key;
    UINT                    u_status_seq;
    UINT                    u_command_seq;

    COMIFaceWrapper<IBaseFilter>                    com_renderer;
    COMIFaceWrapper<IGraphBuilder>                  com_graph;
    COMIFaceWrapper<IAMCertifiedOutputProtection>   com_copp;
    COMIFaceWrapper<IBaseFilter>                    com_source;
    COMIFaceWrapper<ICaptureGraphBuilder2>          com_builder;

    GUID                    driver_guid_random;
    std::vector<BYTE>       driver_cert_chain;
    bool                    initialized;

    void Initialize() {
        BOOL_THROW(CryptAcquireContext(h_crypt_prov.GetPointer(), NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT));

        DWORD dw_flag = (0x80 << 16) | CRYPT_EXPORTABLE;

        BOOL_THROW(CryptGenKey(h_crypt_prov.GetHandle(), CALG_AES_128, dw_flag, m_h_aes_key.GetPointer()));

        DWORD cb_data = 0;

        BOOL_THROW(CryptExportKey(m_h_aes_key.GetHandle(), 0, PLAINTEXTKEYBLOB, 0, NULL, &cb_data));
        BOOL_THROW(cb_data == sizeof(BLOBHEADER) + 4 + 16);

        aes_key.resize(cb_data);

        BOOL_THROW(CryptExportKey(
            m_h_aes_key.GetHandle(),
            0,
            PLAINTEXTKEYBLOB,
            0,
            aes_key.data(),
            &cb_data
        ));

        CopyMemory(
            aes_key.data(),
            aes_key.data() + sizeof(BLOBHEADER) + sizeof(DWORD),
            16
        );

        aes_key.resize(16);

        BOOL_THROW(CryptGenRandom(h_crypt_prov.GetHandle(), sizeof(UINT), (BYTE*)&u_status_seq));
        BOOL_THROW(CryptGenRandom(h_crypt_prov.GetHandle(), sizeof(UINT), (BYTE*)&u_command_seq));
        HRESULT_THROW(CoInitialize(0));

        com_graph = COMIFaceWrapper<IGraphBuilder>(
            CLSID_FilterGraph,
            NULL,
            CLSCTX_INPROC_SERVER,
            IID_IGraphBuilder
        );

        com_renderer = COMIFaceWrapper<IBaseFilter>(
            CLSID_VideoMixingRenderer9,
            NULL,
            CLSCTX_INPROC_SERVER,
            IID_IBaseFilter
        );

        HRESULT_THROW(com_graph->AddFilter(com_renderer.Object(), L"VMR9"));

        std::ofstream trash_file("trash.avi");
        trash_file << "abc";
        trash_file.close();

        HRESULT_THROW(
            com_graph->AddSourceFilter(
                L"trash.avi",
                L"Source1",
                com_source.Pointer()
            )
        );

        HRESULT_THROW(com_renderer->QueryInterface(
            IID_IAMCertifiedOutputProtection,
            (void**)com_copp.Pointer())
        );

        com_builder = COMIFaceWrapper<ICaptureGraphBuilder2>(
            CLSID_CaptureGraphBuilder2,
            NULL,
            CLSCTX_INPROC_SERVER,
            IID_ICaptureGraphBuilder2
        );

        HRESULT_THROW(com_builder->SetFiltergraph(com_graph.Object()));

        if (FAILED(com_builder->RenderStream(
            0,
            0,
            com_source.Object(),
            0,
            com_renderer.Object()
        ))) {
            // TODO: This doesn't seem to require a success
            // but it might require at least an invocation;
            // however if Microsoft changes things in the 
            // future it might be required to finish out
            // this process of displaying protected content
            // so I am leaving this here.

            //throw ProcessFailure();
        }

        std::vector<BYTE> pubkey_bytes;

        {
            BYTE* p = NULL;
            DWORD sz = 0;

            HRESULT_THROW(com_copp->KeyExchange(&driver_guid_random, &p, &sz));

            BOOL_THROW(p != NULL);
            BOOL_THROW(sz != 0);

            {
                std::vector<BYTE> pubkey_str;
                //<Modulus>tQp6DeLDMuJAE4x0kFejpr/iE45QQ0sS90bDtXgjvT/CMq2lJtssx6kArcx9O2SrGIfQmSWQOzmA3FMeS6KmwCTs6y+wYD1iuSVdz7725UlKx0oL6pRnNgs+AzDZC9erspo/IeNHuEQ1sLeCM8qaKvi0XaLUlJeclXawWOi6r3d3p+PQndnwfXMRoXKcY0xgqi4Hjt0qbB4hq7J8BD2MiA0RFUQjc1jI7Hs5v7f3cZ6bEexBhyG/zRRbHtm8dXTGL1GRK+ApHRQgALT3NaEuRjfnSMeLQP/R+Jxug7pw4T18j+GV/HX0Ihr7QP2T3PtcgoCYY2agjTHehAG4TzRjAw==</Modulus>
                const char* start_delim = "<Modulus>";
                const char* end_delim = "</Modulus>";

                char* pubkey_start = strstr((char*)p, start_delim);
                const char* pubkey_end = strstr((char*)p, end_delim);

                BOOL_THROW(pubkey_start != NULL);
                BOOL_THROW(pubkey_end != NULL);

                pubkey_start += strlen(start_delim);

                size_t pubkey_len = pubkey_end - pubkey_start;

                pubkey_str = std::vector<BYTE>(pubkey_len + 1);
                memcpy(pubkey_str.data(), pubkey_start, pubkey_len);
                pubkey_bytes = decode_base64_str(pubkey_str);
            }

            driver_cert_chain.resize(sz);
            CopyMemory(driver_cert_chain.data(), p, sz);
            CoTaskMemFree(p);
        }

        auto copp_sig_buf = std::vector<BYTE>(sizeof(AMCOPPSignature));
        DWORD actual_data_sz = 0;

        {
            AMCOPPSignature copp_sig;
            ZeroMemory(&copp_sig, sizeof(copp_sig));
            struct S {
                GUID guid_random;
                BYTE aes_key[16];
                UINT u_status_seq;
                UINT u_command_seq;
            };

            S* s = (S*)&copp_sig;
            s->guid_random = driver_guid_random;
            CopyMemory(
                &s->aes_key,
                aes_key.data(),
                min(sizeof(s->aes_key), aes_key.capacity())
            );
            s->u_status_seq = u_status_seq;
            s->u_command_seq = u_command_seq;
            CopyMemoryReverse(copp_sig_buf.data(), &copp_sig, sizeof(S));
            actual_data_sz = sizeof(S);
        }

        {
            const DWORD pkstruct_sz = sizeof(BLOBHEADER) + sizeof(RSAPUBKEY) +
                pubkey_bytes.size();
            auto pkstruct = std::vector<BYTE>(pkstruct_sz);
            BLOBHEADER* hdr = (BLOBHEADER*)pkstruct.data();
            RSAPUBKEY* rsa = (RSAPUBKEY*)(pkstruct.data() + sizeof(BLOBHEADER));
            CopyMemoryReverse(
                pkstruct.data() + sizeof(BLOBHEADER) + sizeof(RSAPUBKEY),
                pubkey_bytes.data(),
                pubkey_bytes.size()
            );

            hdr->bType = PUBLICKEYBLOB;
            hdr->bVersion = CUR_BLOB_VERSION;
            hdr->aiKeyAlg = CALG_RSA_KEYX;
            rsa->magic = 0x31415352;
            rsa->pubexp = 0x010001;
            rsa->bitlen = pubkey_bytes.size() * 8;

            BOOL_THROW(CryptImportKey(
                h_crypt_prov.GetHandle(),
                pkstruct.data(),
                range_check<DWORD, size_t>(
                    pkstruct.capacity(),
                    sizeof(BLOBHEADER) + sizeof(RSAPUBKEY) + 8,
                    0xffffff
                ),
                0,
                0,
                h_driver_public_key.GetPointer()
            ));

            DWORD crypt_in_out_sz = actual_data_sz;

            BOOL_THROW(CryptEncrypt(
                h_driver_public_key.GetHandle(),
                NULL,
                TRUE,
                0,
                copp_sig_buf.data(),
                &crypt_in_out_sz,
                range_check<DWORD, size_t>(
                    copp_sig_buf.capacity(),
                    0,
                    0xffffff
                )
            ));
        }

        BOOL_THROW(copp_sig_buf.capacity() == sizeof(AMCOPPSignature));

        HRESULT_THROW(com_copp->SessionSequenceStart(
            (AMCOPPSignature*)copp_sig_buf.data()
        ));
    }

    void InitializeOrNoop() {
        if (!initialized) {
            initialized = true;
            Initialize();
        }
    }

public:
    HDCPHelper& operator=(HDCPHelper&& other) noexcept {
        return *this;
    }

    HDCPHelper() {
        initialized = false;
        memset(&driver_guid_random, 0, sizeof(driver_guid_random));
        u_command_seq = 0;
        u_status_seq = 0;
    }

    void RequestHDCPMaxLevel() {
        InitializeOrNoop();

        AMCOPPCommand copp_cmd;

        ZeroMemory(&copp_cmd, sizeof(copp_cmd));
        auto spl_cd = (DXVA_COPPSetProtectionLevelCmdData*)&copp_cmd.CommandData;
        spl_cd->ProtType = COPP_ProtectionType_HDCP;
        spl_cd->ProtLevel = COPP_HDCP_LevelMax;
        
        copp_cmd.guidCommandID = DXVA_COPPSetProtectionLevel;
        copp_cmd.dwSequence = u_command_seq++;
        copp_cmd.cbSizeData = sizeof(*spl_cd);

        BOOL_THROW(sizeof(copp_cmd.macKDI) == OPM_OMAC_SIZE);

        HRESULT_THROW(ComputeOMAC(
            aes_key.data(),
            (PUCHAR)&copp_cmd.macKDI + sizeof(copp_cmd.macKDI),
            sizeof(copp_cmd) - sizeof(copp_cmd.macKDI),
            (PUCHAR)&copp_cmd.macKDI
        ));

        HRESULT_THROW(com_copp->ProtectionCommand(&copp_cmd));
    }

    int GetLocalHDCPLevel() {
        InitializeOrNoop();

        AMCOPPStatusInput i;
        AMCOPPStatusOutput o;
        ZeroMemory(&i, sizeof(i));
        ZeroMemory(&o, sizeof(o));
        ((DWORD*)&i.StatusData)[0] = COPP_ProtectionType_HDCP;
        i.cbSizeData = 4;
        i.guidStatusRequestID = DXVA_COPPQueryLocalProtectionLevel;
        i.dwSequence = u_status_seq++;
        HRESULT_THROW(com_copp->ProtectionStatus(&i, &o));

        auto reply = (DXVA_COPPStatusData*)&o.COPPStatus[0];

        return reply->dwData;
    }

    int GetGlobalHDCPLevel() {
        InitializeOrNoop();

        AMCOPPStatusInput i;
        AMCOPPStatusOutput o;
        ZeroMemory(&i, sizeof(i));
        ZeroMemory(&o, sizeof(o));
        ((DWORD*)&i.StatusData)[0] = COPP_ProtectionType_HDCP;
        i.cbSizeData = 4;
        i.guidStatusRequestID = DXVA_COPPQueryGlobalProtectionLevel;
        //i.guidStatusRequestID = DXVA_COPPQueryLocalProtectionLevel;
        i.dwSequence = u_status_seq++;
        HRESULT_THROW(com_copp->ProtectionStatus(&i, &o));
        
        auto reply = (DXVA_COPPStatusData*)&o.COPPStatus[0];

        return reply->dwData;
    }

    ~HDCPHelper() {
    }
};

struct HDCPStatus {
    int global;
    int local;
};

class System {
private:
    std::ofstream log_stream;
    int hdcp_last_level;
public:
    std::unique_ptr<HDCPHelper> hdcp;

    System() : log_stream("hdcp_log.txt"), hdcp_last_level(-1) {
        try {
            hdcp = std::unique_ptr<HDCPHelper>(new HDCPHelper());
        }
        catch (ProcessFailure e) {
            auto mbuf = std::vector<CHAR>(1024);
            auto last_error = GetLastError();

            FormatMessageA(
                FORMAT_MESSAGE_FROM_SYSTEM,
                0,
                last_error,
                0,
                mbuf.data(),
                mbuf.capacity(),
                0
            );

            std::ostringstream s;
            s << "Constructor(System) Process Failure for HDCPHelper: "
                << e.GetMessage() << " [" << GetLastError() << "]"
                << "LastError [" << last_error << "]: " << mbuf.data();
            log_write(s.str());
            //throw ProcessFailure(s.str());
        }
    }

    ~System() {

    }

    void log_write(std::string msg) {
        log_stream << msg.data() << std::endl;
    }

    void hdcp_level_notify(int level) {
        if (hdcp_last_level != level) {
            std::ostringstream s;
            auto now = std::chrono::system_clock::now();
            std::time_t now_time = std::chrono::system_clock::to_time_t(now);
            auto time_buf = std::vector<char>(256);
            ctime_s(time_buf.data(), time_buf.capacity(), &now_time);
            s << time_buf.data() << " HDCP level is " << level << ".";
            log_write(s.str());
            hdcp_last_level = level;
        }
    }

    int hdcp_interval_work(HDCPStatus &status) {
        try {
            int hdcp_local_pre_level = hdcp->GetLocalHDCPLevel();
            int hdcp_local_post_level = hdcp_local_pre_level;

            hdcp_level_notify(hdcp_local_pre_level);

            if (hdcp_local_pre_level == 0) {
                hdcp->RequestHDCPMaxLevel();
                hdcp_local_post_level = hdcp->GetLocalHDCPLevel();
                hdcp_level_notify(hdcp_local_post_level);
            }

            status.local = hdcp_local_post_level;
            status.global = hdcp->GetGlobalHDCPLevel();
            return 1;
        }
        catch (ProcessFailure e) {
            std::ostringstream s;
            s << "HDCP Process Failure: " << e.GetMessage() << " [" << GetLastError() << "]";
            log_write(s.str());

            try {
                hdcp = std::unique_ptr<HDCPHelper>(new HDCPHelper());
            }
            catch (ProcessFailure e) {
                s = std::ostringstream();
                s << "HDCP Process Failure on Reinit: " << e.GetMessage();
                log_write(s.str());
            }

            status.local = -1;
            status.global = -1;
            return 0;
        }
    }
};

#define MAX_LOADSTRING 100

// Global Variables:
HINSTANCE hInst;                                // current instance
WCHAR szTitle[MAX_LOADSTRING];                  // The title bar text
WCHAR szWindowClass[MAX_LOADSTRING];            // the main window class name

std::unique_ptr<System> g_sys;

// Forward declarations of functions included in this code module:
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // Initialize global strings
    LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_TEST, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

    // Perform application initialization:
    if (!InitInstance (hInstance, nCmdShow))
    {
        return FALSE;
    }

    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_TEST));

    g_sys = std::unique_ptr<System>(new System());

    MSG msg;

    // Main message loop:
    while (GetMessage(&msg, nullptr, 0, 0))
    {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return (int) msg.wParam;
}

//
//  FUNCTION: MyRegisterClass()
//
//  PURPOSE: Registers the window class.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    wcex.hInstance      = hInstance;
    wcex.hIcon          = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_ICON1));
    wcex.hCursor        = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName   = MAKEINTRESOURCEW(IDC_TEST);
    wcex.lpszClassName  = szWindowClass;
    wcex.hIconSm        = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_ICON1));

    return RegisterClassExW(&wcex);
}

//
//   FUNCTION: InitInstance(HINSTANCE, int)
//
//   PURPOSE: Saves instance handle and creates main window
//
//   COMMENTS:
//
//        In this function, we save the instance handle in a global variable and
//        create and display the main program window.
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   hInst = hInstance; // Store instance handle in our global variable

   //HWND hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
   //   CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, nullptr, nullptr, hInstance, nullptr);

   HWND hWnd = CreateDialogW(NULL, MAKEINTRESOURCE(IDD_ABOUTBOX), NULL, WndProc);

   if (!hWnd)
   {
      return FALSE;
   }

   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);

   SetTimer(hWnd, IDT_TIMER1, 100, (TIMERPROC)NULL);

   return TRUE;
}

void DoTimerWork(HWND hWnd) {
    HDCPStatus hdcp_status;
    int ret = g_sys->hdcp_interval_work(hdcp_status);

    char status_msg[255];

    if (ret) {
        switch (hdcp_status.global) {
        case 0:
            sprintf_s(&status_msg[0], sizeof(status_msg), "HDCP Not Enabled");
            break;
        default:
            sprintf_s(&status_msg[0], sizeof(status_msg), "HDCP Enabled [%i]", hdcp_status.global);
            break;
        }

        SetDlgItemTextA(hWnd, IDC_STATUS_MSG_GLOBAL, &status_msg[0]);

        switch (hdcp_status.local) {
        case 0:
            sprintf_s(&status_msg[0], sizeof(status_msg), "HDCP Not Enabled");
            break;
        default:
            sprintf_s(&status_msg[0], sizeof(status_msg), "HDCP Enabled [%i]", hdcp_status.local);
            break;
        }

        SetDlgItemTextA(hWnd, IDC_STATUS_MSG_LOCAL, &status_msg[0]);
    }
    else {
        sprintf_s(&status_msg[0], sizeof(status_msg), "Initialization Failure");
        SetDlgItemTextA(hWnd, IDC_STATUS_MSG_GLOBAL, &status_msg[0]);
        SetDlgItemTextA(hWnd, IDC_STATUS_MSG_LOCAL, &status_msg[0]);
    }
}

//
//  FUNCTION: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  PURPOSE: Processes messages for the main window.
//
//  WM_COMMAND  - process the application menu
//  WM_PAINT    - Paint the main window
//  WM_DESTROY  - post a quit message and return
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_TIMER:
        switch (wParam) {
            case IDT_TIMER1:
                DoTimerWork(hWnd);
                break;
        }
        break;
    case WM_COMMAND:
        {
            int wmId = LOWORD(wParam);
            // Parse the menu selections:
            switch (wmId)
            {
            case IDM_ABOUT:
                DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
                break;
            case IDM_EXIT:
                DestroyWindow(hWnd);
                break;
            default:
                return DefWindowProc(hWnd, message, wParam, lParam);
            }
        }
        break;
    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);
            // TODO: Add any drawing code that uses hdc here...
            EndPaint(hWnd, &ps);
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

// Message handler for about box.
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}
