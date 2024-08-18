#include "HDCPHelper.h"
#include "AppExceptions.h"

#include <iostream>
#include <fstream>
#include <d3d11.h>
#include <dxva.h>

#include "Utility.h"


void HDCPHelper::Initialize() {
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
        BOOL_THROW(pubkey_bytes.size() < 0xffffff);

        const DWORD pkstruct_sz = sizeof(BLOBHEADER) + sizeof(RSAPUBKEY) +
            (DWORD)pubkey_bytes.size();
        auto pkstruct = std::vector<BYTE>(pkstruct_sz);
        BLOBHEADER* hdr = (BLOBHEADER*)pkstruct.data();
        RSAPUBKEY* rsa = (RSAPUBKEY*)(pkstruct.data() + sizeof(BLOBHEADER));
        CopyMemoryReverse(
            pkstruct.data() + sizeof(BLOBHEADER) + sizeof(RSAPUBKEY),
            pubkey_bytes.data(),
            (int)pubkey_bytes.size()
        );

        hdr->bType = PUBLICKEYBLOB;
        hdr->bVersion = CUR_BLOB_VERSION;
        hdr->aiKeyAlg = CALG_RSA_KEYX;
        rsa->magic = 0x31415352;
        rsa->pubexp = 0x010001;
        rsa->bitlen = (DWORD)pubkey_bytes.size() * 8;

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

void HDCPHelper::InitializeOrNoop() {
    if (!initialized) {
        initialized = true;
        Initialize();
    }
}

//HDCPHelper& HDCPHelper::operator=(HDCPHelper&& other) noexcept {
//    return *this;
//}

HDCPHelper::HDCPHelper() {
    initialized = false;
    memset(&driver_guid_random, 0, sizeof(driver_guid_random));
    u_command_seq = 0;
    u_status_seq = 0;
}

void HDCPHelper::RequestHDCPMaxLevel() {
    InitializeOrNoop();
    
    //if (true) {
    //    return;
    //} 

    AMCOPPCommand copp_cmd;

    ZeroMemory(&copp_cmd, sizeof(copp_cmd));
    auto spl_cd = (DXVA_COPPSetProtectionLevelCmdData*)&copp_cmd.CommandData;
    spl_cd->ProtType = COPP_ProtectionType_HDCP;
    spl_cd->ProtLevel = COPP_HDCP_LevelMax;

    //spl_cd->ProtType = COPP_ProtectionType_DPCP;
    //spl_cd->ProtLevel = COPP_DPCP_LevelMax;

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

int HDCPHelper::GetLocalHDCPLevel() {
    InitializeOrNoop();

    AMCOPPStatusInput i;
    AMCOPPStatusOutput o;
    ZeroMemory(&i, sizeof(i));
    ZeroMemory(&o, sizeof(o));
    ((DWORD*)&i.StatusData)[0] = COPP_ProtectionType_HDCP;
    //((DWORD*)&i.StatusData)[0] = COPP_ProtectionType_DPCP;
    i.cbSizeData = 4;
    i.guidStatusRequestID = DXVA_COPPQueryLocalProtectionLevel;
    i.dwSequence = u_status_seq++;
    HRESULT_THROW(com_copp->ProtectionStatus(&i, &o));

    auto reply = (DXVA_COPPStatusData*)&o.COPPStatus[0];

    return reply->dwData;
}

int HDCPHelper::GetGlobalHDCPLevel() {
    InitializeOrNoop();

    AMCOPPStatusInput i;
    AMCOPPStatusOutput o;
    ZeroMemory(&i, sizeof(i));
    ZeroMemory(&o, sizeof(o));
    ((DWORD*)&i.StatusData)[0] = COPP_ProtectionType_HDCP;
    //((DWORD*)&i.StatusData)[0] = COPP_ProtectionType_DPCP;
    i.cbSizeData = 4;
    i.guidStatusRequestID = DXVA_COPPQueryGlobalProtectionLevel;
    i.guidStatusRequestID = DXVA_COPPQueryLocalProtectionLevel;
    i.dwSequence = u_status_seq++;
    HRESULT_THROW(com_copp->ProtectionStatus(&i, &o));

    auto reply = (DXVA_COPPStatusData*)&o.COPPStatus[0];

    return reply->dwData;
}

HDCPHelper::~HDCPHelper() {
}
