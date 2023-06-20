#pragma once
#include "framework.h"
#include "AppExceptions.h"

#include <strmif.h>
#include <iostream>
#include <fstream>
#include <sstream>

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

    COMIFaceWrapper<T>(GUID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, const IID& riid) {
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
