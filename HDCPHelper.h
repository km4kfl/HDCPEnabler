#pragma once
#include <vector>

#include "framework.h"
#include "SmartHandleClass.h"
#include "COMIFaceWrapper.h"

#include <dshow.h>
#include <strmif.h>
#include <wincrypt.h>
#include <initguid.h>
#include <bcrypt.h>

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

    void Initialize();
    void InitializeOrNoop();
public:
    HDCPHelper& operator=(HDCPHelper&& other) noexcept;
    HDCPHelper();
    void RequestHDCPMaxLevel();
    int GetLocalHDCPLevel();
    int GetGlobalHDCPLevel();
    ~HDCPHelper();
};
