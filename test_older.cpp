// test.cpp : Defines the entry point for the application.
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

#define OPM_OMAC_SIZE 16

HRESULT ComputeOMAC(
    PUCHAR aes_key,
    PUCHAR pb,
    DWORD cb,
    PUCHAR p_tag
) {

    HRESULT hr = S_OK;
    BCRYPT_ALG_HANDLE h_alg = NULL;
    BCRYPT_KEY_HANDLE h_key = NULL;
    DWORD cb_key_obj = 0;
    DWORD cb_data = 0;
    PBYTE pb_key_obj = NULL;

    struct {
        BCRYPT_KEY_DATA_BLOB_HEADER header;
        UCHAR key[AES_128_KEYSIZE];
    } KeyBlob;

    KeyBlob.header.dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
    KeyBlob.header.dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
    KeyBlob.header.cbKeyData = AES_128_KEYSIZE;
    CopyMemory(KeyBlob.key, aes_key, sizeof(KeyBlob.key));

    BYTE rgb_lu[OPM_OMAC_SIZE];
    BYTE rgb_lu_1[OPM_OMAC_SIZE];
    BYTE rbuffer[OPM_OMAC_SIZE];

    hr = BCryptOpenAlgorithmProvider(
        &h_alg,
        BCRYPT_AES_ALGORITHM,
        MS_PRIMITIVE_PROVIDER,
        0
    );

    hr = BCryptGetProperty(
        h_alg,
        BCRYPT_OBJECT_LENGTH,
        (PBYTE)&cb_key_obj,
        sizeof(DWORD),
        &cb_data,
        0
    );

    pb_key_obj = new BYTE[cb_key_obj];

    hr = BCryptSetProperty(
        h_alg,
        BCRYPT_CHAINING_MODE,
        (PBYTE)BCRYPT_CHAIN_MODE_CBC,
        sizeof(BCRYPT_CHAIN_MODE_CBC),
        0
    );

    hr = BCryptImportKey(
        h_alg,
        NULL,
        BCRYPT_KEY_DATA_BLOB,
        &h_key,
        pb_key_obj,
        cb_key_obj,
        (PUCHAR)&KeyBlob,
        sizeof(KeyBlob),
        0
    );

    DWORD cb_buf = sizeof(rbuffer);
    ZeroMemory(rbuffer, sizeof(rbuffer));

    hr = BCryptEncrypt(
        h_key, rbuffer, cb_buf, NULL, NULL, 0,
        rbuffer, sizeof(rbuffer), &cb_buf, 0
    );

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

    hr = BCryptDestroyKey(h_key);

    h_key = NULL;

    hr = BCryptImportKey(
        h_alg, NULL, BCRYPT_KEY_DATA_BLOB, &h_key,
        pb_key_obj, cb_key_obj, (PUCHAR)&KeyBlob,
        sizeof(KeyBlob), 0
    );

    PUCHAR pb_data_in_cur = pb;
    cb_data = cb;

    do {
        DWORD cb_buffer = 0;

        if (cb_data > OPM_OMAC_SIZE) {
            CopyMemory(rbuffer, pb_data_in_cur, OPM_OMAC_SIZE);
            hr = BCryptEncrypt(
                h_key, rbuffer, sizeof(rbuffer), NULL,
                NULL, 0, rbuffer, sizeof(rbuffer), &cb_buffer, 0
            );

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
            hr = BCryptEncrypt(
                h_key, rbuffer, sizeof(rbuffer), NULL, NULL,
                0, p_tag, OPM_OMAC_SIZE, &cb_buffer, 0
            );

            cb_data = 0;
        }
    } while (S_OK == hr && cb_data > 0);

    return S_OK;
}

void CopyMemoryReverse(void* dst, const void* src, int size) {
    BYTE *_dst = (BYTE*)dst;
    BYTE *_src = (BYTE*)src;

    for (int x = 0; x < size; ++x) {
        _dst[size - 1 - x] = _src[x];
    }
}

class ProcessFailure : public std::exception {
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

class CryptKey {
private:
    HCRYPTKEY h;
public:
    CryptKey() {
        h = NULL;
    }

    CryptKey(HCRYPTKEY h) {
        this->h = h;
    }

    HCRYPTKEY* GetPointer() {
        return &h;
    }

    HCRYPTKEY GetHandle() {
        return h;
    }

    ~CryptKey() {
        CryptDestroyKey(h);
    }
};

class CryptContext {
private:
    HCRYPTPROV h;
public:
    CryptContext() {
        h = NULL;
    }

    CryptContext(HCRYPTPROV h) {
        this->h = h;
    }

    HCRYPTPROV GetHandle() {
        return h;
    }

    HCRYPTPROV* GetPointer() {
        return &h;
    }

    ~CryptContext() {
        CryptReleaseContext(h, 0);
    }
};

template<typename T> class COMIFaceWrapper {
private:
    T* p;
public:
    COMIFaceWrapper() {
        p = NULL;
    }

    COMIFaceWrapper<T>(GUID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, const IID &riid) {
        p = NULL;

        if (FAILED(CoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, (LPVOID*)&p))) {
            throw ProcessFailure();
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
public:
    HDCPHelper() {
        if (CryptAcquireContext(h_crypt_prov.GetPointer(), NULL, NULL, PROV_RSA_AES, 0) == FALSE) {
            throw ProcessFailure();
        }

        DWORD dw_flag = (0x80 << 16) | CRYPT_EXPORTABLE;

        if (CryptGenKey(h_crypt_prov.GetHandle(), CALG_AES_128, dw_flag, m_h_aes_key.GetPointer()) == FALSE) {
            throw ProcessFailure();
        }

        DWORD cb_data = 0;

        if (CryptExportKey(m_h_aes_key.GetHandle(), 0, PLAINTEXTKEYBLOB, 0, NULL, &cb_data) == FALSE) {
            throw ProcessFailure();
        }

        if (cb_data != sizeof(BLOBHEADER) + 4 + 16) {
            throw ProcessFailure();
        }

        aes_key.resize(cb_data);

        if (CryptExportKey(
            m_h_aes_key.GetHandle(), 
            0, 
            PLAINTEXTKEYBLOB, 
            0, 
            aes_key.data(),
            &cb_data
        ) == FALSE) {
            throw ProcessFailure();
        }

        CopyMemory(
            aes_key.data(), 
            aes_key.data() + sizeof(BLOBHEADER) + sizeof(DWORD), 
            16
        );

        aes_key.resize(16);

        if (CryptGenRandom(h_crypt_prov.GetHandle(), sizeof(UINT), (BYTE*)&u_status_seq) == FALSE) {
            throw ProcessFailure();
        }

        if (CryptGenRandom(h_crypt_prov.GetHandle(), sizeof(UINT), (BYTE*)&u_command_seq) == FALSE) {
            throw ProcessFailure();
        }

        if (FAILED(CoInitialize(0))) {
            throw ProcessFailure();
        }

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

        if (FAILED(com_graph->AddFilter(com_renderer.Object(), L"VMR9"))) {
            throw ProcessFailure();
        }

        if (FAILED(
            com_graph->AddSourceFilter(
                L"D:\\trash.avi",
                L"Source1",
                com_source.Pointer()
            ))) {
            throw ProcessFailure();
        }

        if (FAILED(com_renderer->QueryInterface(
            IID_IAMCertifiedOutputProtection,
            (void**)com_copp.Pointer()))) {
            throw ProcessFailure();
        }

        com_builder = COMIFaceWrapper<ICaptureGraphBuilder2>(
            CLSID_CaptureGraphBuilder2,
            NULL,
            CLSCTX_INPROC_SERVER,
            IID_ICaptureGraphBuilder2
        );

        if (FAILED(com_builder->SetFiltergraph(com_graph.Object()))) {
            throw ProcessFailure();
        }

        if (FAILED(com_builder->RenderStream(
            0, 
            0, 
            com_source.Object(), 
            0, 
            com_renderer.Object()
        ))) {
            throw ProcessFailure();
        }

        {
            BYTE *p;
            DWORD sz;
            com_copp->KeyExchange(&driver_guid_random, &p, &sz);
            if (p == NULL) {
                throw ProcessFailure();
            }
            driver_cert_chain.resize(sz);
            CopyMemory(driver_cert_chain.data(), p, sz);
            CoTaskMemFree(p);
        }

        // I shouldn't even be writing this in C++. I should be using
        // C#. I'm just enjoying reviewing C++. But, frankly, it is
        // about stupid to do this in C++ because its just not needed
        // and this isn't going to be platform neutral so you know I'm
        // just fucking around really. Fuck C++.
        
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
            const BYTE nvidia_pubkey[] = {
                164, 211, 33, 236, 168, 70, 180, 222, 217, 79, 254, 72, 149, 205,
                216, 98, 39, 12, 123, 22, 136, 22, 84, 104, 143, 3, 149, 37, 217,
                208, 39, 242, 194, 103, 238, 25, 135, 93, 84, 37, 179, 23, 168, 170,
                141, 228, 92, 176, 73, 107, 130, 251, 199, 32, 24, 81, 54, 182, 231,
                33, 200, 36, 95, 54, 254, 35, 213, 173, 109, 42, 7, 147, 189, 227,
                170, 141, 250, 169, 188, 29, 118, 163, 111, 70, 173, 105, 55, 205,
                1, 214, 106, 253, 44, 115, 180, 219, 172, 172, 111, 177, 108, 109,
                130, 68, 118, 189, 14, 229, 36, 188, 172, 236, 231, 232, 41, 7, 83,
                223, 227, 66, 40, 133, 83, 39, 10, 179, 45, 197, 158, 48, 123, 63,
                211, 114, 214, 184, 179, 20, 123, 206, 179, 174, 74, 230, 127, 3,
                134, 195, 44, 94, 122, 1, 68, 46, 192, 101, 72, 44, 18, 92, 63, 152,
                111, 83, 113, 66, 45, 170, 80, 15, 103, 162, 90, 169, 174, 177, 51,
                56, 69, 137, 43, 152, 78, 123, 216, 194, 85, 100, 159, 53, 237, 130,
                111, 167, 96, 101, 154, 90, 96, 16, 117, 61, 134, 138, 115, 78, 106,
                243, 63, 211, 244, 23, 243, 71, 21, 196, 161, 21, 203, 136, 116, 50,
                3, 129, 106, 90, 78, 7, 228, 197, 13, 237, 145, 208, 215, 34, 227,
                134, 250, 148, 99, 216, 17, 103, 203, 29, 231, 118, 29, 149, 204,
                137, 193, 36, 200, 133
            };

            const DWORD pkstruct_sz = sizeof(BLOBHEADER) + sizeof(RSAPUBKEY) +
                                      sizeof(nvidia_pubkey);
            auto pkstruct = std::vector<BYTE>(pkstruct_sz);
            BLOBHEADER* hdr = (BLOBHEADER*)pkstruct.data();
            RSAPUBKEY* rsa = (RSAPUBKEY*)(pkstruct.data() + sizeof(BLOBHEADER));
            CopyMemoryReverse(
                pkstruct.data() + sizeof(BLOBHEADER) + sizeof(RSAPUBKEY),
                nvidia_pubkey,
                sizeof(nvidia_pubkey)
            );

            hdr->bType = PUBLICKEYBLOB;
            hdr->bVersion = CUR_BLOB_VERSION;
            hdr->aiKeyAlg = CALG_RSA_KEYX;
            rsa->magic = 0x31415352;
            rsa->pubexp = 0x010001;
            rsa->bitlen = sizeof(nvidia_pubkey) * 8;

            if (CryptImportKey(
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
            ) == FALSE) {
                throw ProcessFailure();
            }

            DWORD crypt_in_out_sz = actual_data_sz;

            if (CryptEncrypt(
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
            ) == FALSE) {
                throw ProcessFailure();
            }
        }

        if (copp_sig_buf.capacity() != sizeof(AMCOPPSignature)) {
            throw ProcessFailure();
        }

        if (FAILED(com_copp->SessionSequenceStart(
            (AMCOPPSignature*)copp_sig_buf.data()
        ))) {
            throw ProcessFailure();
        }
    }

    void SetHDCPMaxLevel() {
        AMCOPPCommand copp_cmd;
        

        ZeroMemory(&copp_cmd, sizeof(copp_cmd));
        auto spl_cd = (DXVA_COPPSetProtectionLevelCmdData*)&copp_cmd.CommandData;
        spl_cd->ProtType = COPP_ProtectionType_HDCP;
        spl_cd->ProtLevel = COPP_HDCP_LevelMax;
        
        copp_cmd.guidCommandID = DXVA_COPPSetProtectionLevel;
        copp_cmd.dwSequence = u_command_seq++;
        copp_cmd.cbSizeData = sizeof(*spl_cd);

        if (sizeof(copp_cmd.macKDI) != OPM_OMAC_SIZE) {
            throw ProcessFailure();
        }

        ComputeOMAC(
            aes_key.data(),
            (PUCHAR)&copp_cmd.macKDI + sizeof(copp_cmd.macKDI),
            sizeof(copp_cmd) - sizeof(copp_cmd.macKDI),
            (PUCHAR)&copp_cmd.macKDI
        );

        if (FAILED(com_copp->ProtectionCommand(&copp_cmd))) {
            throw ProcessFailure();
        }
    }

    int GetHDCPLevel() {
        AMCOPPStatusInput i;
        AMCOPPStatusOutput o;
        ZeroMemory(&i, sizeof(i));
        ZeroMemory(&o, sizeof(o));
        ((DWORD*)&i.StatusData)[0] = COPP_ProtectionType_HDCP;
        i.cbSizeData = 4;
        i.guidStatusRequestID = DXVA_COPPQueryGlobalProtectionLevel;
        i.dwSequence = u_status_seq++;
        if (FAILED(com_copp->ProtectionStatus(&i, &o))) {
            throw ProcessFailure();
        }
        
        auto reply = (DXVA_COPPStatusData*)&o.COPPStatus[0];

        return range_check<int, ULONG>(
            reply->dwData,
            0,
            2
        );
    }

    ~HDCPHelper() {
    }
};

#define MAX_LOADSTRING 100

// Global Variables:
HINSTANCE hInst;                                // current instance
WCHAR szTitle[MAX_LOADSTRING];                  // The title bar text
WCHAR szWindowClass[MAX_LOADSTRING];            // the main window class name

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

    /*
    BYTE K[] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };

    BYTE M[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    };

    BYTE T[16];

    ZeroMemory(&T[0], sizeof(T));

    ComputeOMAC(
        &K[0],
        &M[0],
        sizeof(M),
        &T[0]
    );
    */

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

    HCRYPTPROV h_crypt_prov;
    HCRYPTKEY m_h_aes_key;
    DWORD dw_flag;
    BOOL b_res;

    b_res = CryptAcquireContext(&h_crypt_prov, NULL, NULL, PROV_RSA_AES, 0);

    dw_flag = (0x80 << 16) | CRYPT_EXPORTABLE;
    b_res = CryptGenKey(h_crypt_prov, CALG_AES_128, dw_flag, &m_h_aes_key);

    DWORD cb_data = 0;
    BYTE* p_data = NULL;

    b_res = CryptExportKey(m_h_aes_key, 0, PLAINTEXTKEYBLOB, 0, NULL, &cb_data);
    p_data = new BYTE[cb_data];
    b_res = CryptExportKey(m_h_aes_key, 0, PLAINTEXTKEYBLOB, 0, p_data, &cb_data);

    DWORD _sz932 = sizeof(BLOBHEADER);

    DWORD* pcb_key = (DWORD*)(p_data + sizeof(BLOBHEADER));

    if (*pcb_key != 16) {
        return -1;
    }

    BYTE* p_aes_128_key = p_data + sizeof(BLOBHEADER) + sizeof(DWORD);

    UINT u_status_seq = 0;
    UINT u_command_seq = 0;

    CryptGenRandom(h_crypt_prov, sizeof(UINT), (BYTE*)&u_status_seq);
    CryptGenRandom(h_crypt_prov, sizeof(UINT), (BYTE*)&u_command_seq);

    if (FAILED(CoInitialize(0))) {
        return -1;
    }

    IGraphBuilder* p_gb = NULL;

    if (FAILED(CoCreateInstance(
        CLSID_FilterGraph,
        NULL,
        CLSCTX_INPROC_SERVER,
        IID_IGraphBuilder,
        (void**)&p_gb
    ))) {
        return -1;
    }

    IBaseFilter* p_renderer = NULL;

    if (FAILED(CoCreateInstance(
        CLSID_VideoMixingRenderer9,
        NULL,
        CLSCTX_INPROC_SERVER,
        IID_IBaseFilter,
        (void**)&p_renderer
    ))) {
        return -1;
    }

    p_gb->AddFilter(p_renderer, L"VMR9");

    IBaseFilter* p_source;
    p_gb->AddSourceFilter(L"D:\\trash.avi", L"Source1", &p_source);

    IAMCertifiedOutputProtection* p_copp_device = NULL;

    p_renderer->QueryInterface(
        IID_IAMCertifiedOutputProtection,
        (void**)&p_copp_device
    );

    ICaptureGraphBuilder2* p_build = NULL;

    CoCreateInstance(
        CLSID_CaptureGraphBuilder2, NULL,
        CLSCTX_INPROC_SERVER, IID_ICaptureGraphBuilder2,
        (void**)&p_build 
    );

    HRESULT test;

    test = p_build->SetFiltergraph(p_gb);

    test = p_build->RenderStream(0, 0, p_source, 0, p_renderer);

    GUID guid_random;
    BYTE* pb_cert_chain = NULL;
    DWORD cb_cert_chain_sz = 0;
    test = p_copp_device->KeyExchange(&guid_random, &pb_cert_chain, &cb_cert_chain_sz);

    // CoTaskMemFree(pb_cert_chain)

    AMCOPPSignature copp_sig[2];
    ZeroMemory(&copp_sig, sizeof(copp_sig));

    struct Crap {
        GUID guid_random;
        BYTE aes_128_key[16];
        UINT u_status_seq;
        UINT u_command_seq;
    };

    Crap* crap = (Crap*)&copp_sig[0];
    crap->guid_random = guid_random;
    CopyMemory(&crap->aes_128_key, p_aes_128_key, sizeof(crap->aes_128_key));
    crap->u_status_seq = u_status_seq;
    crap->u_command_seq = u_command_seq;

    CopyMemoryReverse(
        &copp_sig[1].Signature,
        &copp_sig[0].Signature,
        sizeof(Crap)
    );

    const DWORD RSA_PADDING = 11;
    DWORD cb_data_out = sizeof(Crap);
    DWORD cb_data_in = sizeof(copp_sig[0]);
    
    BYTE* dbg = (BYTE*)&copp_sig[1].Signature[0];

    //b_res = CryptAcquireContext(&h_crypt_prov, NULL, NULL, PROV_RSA_FULL, 0);

    const BYTE nvidia_pubkey[] = {
        164, 211, 33, 236, 168, 70, 180, 222, 217, 79, 254, 72, 149, 205, 
        216, 98, 39, 12, 123, 22, 136, 22, 84, 104, 143, 3, 149, 37, 217, 
        208, 39, 242, 194, 103, 238, 25, 135, 93, 84, 37, 179, 23, 168, 170, 
        141, 228, 92, 176, 73, 107, 130, 251, 199, 32, 24, 81, 54, 182, 231,
        33, 200, 36, 95, 54, 254, 35, 213, 173, 109, 42, 7, 147, 189, 227,
        170, 141, 250, 169, 188, 29, 118, 163, 111, 70, 173, 105, 55, 205, 
        1, 214, 106, 253, 44, 115, 180, 219, 172, 172, 111, 177, 108, 109, 
        130, 68, 118, 189, 14, 229, 36, 188, 172, 236, 231, 232, 41, 7, 83, 
        223, 227, 66, 40, 133, 83, 39, 10, 179, 45, 197, 158, 48, 123, 63, 
        211, 114, 214, 184, 179, 20, 123, 206, 179, 174, 74, 230, 127, 3, 
        134, 195, 44, 94, 122, 1, 68, 46, 192, 101, 72, 44, 18, 92, 63, 152, 
        111, 83, 113, 66, 45, 170, 80, 15, 103, 162, 90, 169, 174, 177, 51, 
        56, 69, 137, 43, 152, 78, 123, 216, 194, 85, 100, 159, 53, 237, 130, 
        111, 167, 96, 101, 154, 90, 96, 16, 117, 61, 134, 138, 115, 78, 106, 
        243, 63, 211, 244, 23, 243, 71, 21, 196, 161, 21, 203, 136, 116, 50, 
        3, 129, 106, 90, 78, 7, 228, 197, 13, 237, 145, 208, 215, 34, 227, 
        134, 250, 148, 99, 216, 17, 103, 203, 29, 231, 118, 29, 149, 204, 
        137, 193, 36, 200, 133
    };

    DWORD pkstruct_sz = sizeof(BLOBHEADER) + sizeof(RSAPUBKEY) + sizeof(nvidia_pubkey);
    BYTE* pkstruct = new BYTE[pkstruct_sz];
    BLOBHEADER*pkstruct_hdr = (BLOBHEADER*)pkstruct;
    RSAPUBKEY* pkstruct_rsa = (RSAPUBKEY*)(pkstruct + sizeof(BLOBHEADER));

    ZeroMemory(pkstruct, pkstruct_sz);

    CopyMemoryReverse(
        pkstruct + sizeof(BLOBHEADER) + sizeof(RSAPUBKEY),
        nvidia_pubkey, 
        sizeof(nvidia_pubkey)
    );

    HCRYPTKEY h_nvidia_crypt_key = 0;

    pkstruct_hdr->bType = PUBLICKEYBLOB;
    pkstruct_hdr->bVersion = CUR_BLOB_VERSION;
    pkstruct_hdr->aiKeyAlg = CALG_RSA_KEYX;
    // CALG_NO_SIGN
    // CALG_RSA_KEYX
    pkstruct_rsa->magic = 0x31415352;
    pkstruct_rsa->pubexp = 0x010001;
    pkstruct_rsa->bitlen = sizeof(nvidia_pubkey) * 8;

    DWORD err = GetLastError();

    //MessageBox(NULL, L"Here3", L"Status", MB_OK);

    //b_res = CryptAcquireContext(&h_crypt_prov, NULL, NULL, PROV_RSA_FULL, 0);

    BOOL bb = CryptImportKey(
        h_crypt_prov,
        pkstruct,
        pkstruct_sz,
        0,
        0,
        &h_nvidia_crypt_key
    );

    if (bb == FALSE) {
        //MessageBox(NULL, L"It failed.", L"It Failed", MB_OK);
        //return 0;
    }

    //MessageBox(NULL, L"Here2", L"Status", MB_OK);

    err = GetLastError();
           
    bb = CryptEncrypt(
        h_nvidia_crypt_key,
        NULL,
        TRUE,
        0,
        dbg,
        &cb_data_out,
        cb_data_in
    );

    err = GetLastError();

    test = p_copp_device->SessionSequenceStart(&copp_sig[1]);

    if (FAILED(test)) {
        MessageBox(NULL, L"SessionSequenceStart", L"It Failed", MB_OK);
    }

    AMCOPPCommand copp_cmd;

    ZeroMemory(&copp_cmd, sizeof(copp_cmd));

    DXVA_COPPSetProtectionLevelCmdData* spl_cd;

    spl_cd = (DXVA_COPPSetProtectionLevelCmdData*)&copp_cmd.CommandData;
    spl_cd->ProtType = COPP_ProtectionType_HDCP;
    spl_cd->ProtLevel = COPP_HDCP_LevelMax;

    copp_cmd.guidCommandID = DXVA_COPPSetProtectionLevel;
    copp_cmd.dwSequence = u_command_seq++;
    copp_cmd.cbSizeData = sizeof(*spl_cd);

    DWORD guid_size = sizeof(GUID);

    DWORD copp_cmd_sz = sizeof(copp_cmd) - sizeof(copp_cmd.CommandData)
        - sizeof(copp_cmd.macKDI) + copp_cmd.cbSizeData;

    ComputeOMAC(
        p_aes_128_key,
        (PUCHAR)&copp_cmd.macKDI + sizeof(GUID),
        sizeof(copp_cmd) - sizeof(GUID),
        //copp_cmd.CommandData,
        //sizeof(*spl_cd),
        (PUCHAR)&copp_cmd.macKDI
    );

    // message authentication code (OMAC-1)


    // calculate OMAC-1 tag for the block of data
    // that appears after the macKDI member
    //copp_cmd.macKDI

    test = p_copp_device->ProtectionCommand(&copp_cmd);

    AMCOPPStatusInput copp_stat_in;
    AMCOPPStatusOutput copp_stat_out;

    ZeroMemory(&copp_stat_in, sizeof(copp_stat_in));
    ZeroMemory(&copp_stat_out, sizeof(copp_stat_out));

    ((DWORD*)&copp_stat_in.StatusData)[0] = COPP_ProtectionType_HDCP;

    copp_stat_in.cbSizeData = 4;

    copp_stat_in.guidStatusRequestID = DXVA_COPPQueryGlobalProtectionLevel;
    
    copp_stat_in.dwSequence = u_status_seq++;

    test = p_copp_device->ProtectionStatus(&copp_stat_in, &copp_stat_out);

    DXVA_COPPStatusData* ret = 
        (DXVA_COPPStatusData*)&copp_stat_out.COPPStatus[0];

    if (ret->dwData == 2) {
        MessageBox(NULL, L"HDCP Enabled", L"HDCP Enabled", MB_OK);
    } else {
        MessageBox(NULL, L"HDCP May _Not_ Be Enabled", L"HDCP Not May Be Enabled", MB_OK);
    }

    /*
    ZeroMemory(&copp_stat_in, sizeof(copp_stat_in));
    ZeroMemory(&copp_stat_out, sizeof(copp_stat_out));
    copp_stat_in.guidStatusRequestID = DXVA_COPPQuerySignaling;
    copp_stat_in.dwSequence = u_status_seq++;
    test = p_copp_device->ProtectionStatus(&copp_stat_in, &copp_stat_out);

    DXVA_COPPStatusSignalingCmdData* ret2 =
        (DXVA_COPPStatusSignalingCmdData*)&copp_stat_out.COPPStatus[0];
    */

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
    wcex.hIcon          = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_TEST));
    wcex.hCursor        = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName   = MAKEINTRESOURCEW(IDC_TEST);
    wcex.lpszClassName  = szWindowClass;
    wcex.hIconSm        = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

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

   HWND hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
      CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, nullptr, nullptr, hInstance, nullptr);

   if (!hWnd)
   {
      return FALSE;
   }

   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);

   return TRUE;
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
