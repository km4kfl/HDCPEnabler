#pragma once
#include "framework.h"
#include <wincrypt.h>
#include <bcrypt.h>

#define SMARTHANDLECLASS_DEF(TYPE, HANDLE_TYPE, DEALLOC_CALL) \
    class TYPE { \
        private: \
        HANDLE_TYPE h; \
        public: \
        TYPE (); \
        TYPE(const TYPE& other) = delete; \
        TYPE& operator=(TYPE& other) = delete; \
        TYPE& operator=(TYPE&& other) noexcept; \
        TYPE(HANDLE_TYPE h); \
        HANDLE_TYPE* GetPointer(); \
        HANDLE_TYPE GetHandle(); \
        ~TYPE(); \
    };

#define SMARTHANDLECLASS_IMPL(TYPE, HANDLE_TYPE, DEALLOC_CALL) \
    TYPE::TYPE() { \
        h = NULL; \
    } \
    TYPE& TYPE::operator=(TYPE&& other) noexcept { \
        if (h != NULL) { \
            DEALLOC_CALL; \
        } \
        h = other.h; \
        other.h = NULL; \
        return *this; \
    } \
    TYPE::TYPE(HANDLE_TYPE h) { \
        this->h = h; \
    } \
    HANDLE_TYPE* TYPE::GetPointer() { \
        if (h != NULL) { \
            throw SuspectBuggyUsage(); \
        } \
        return &h; \
    } \
    HANDLE_TYPE TYPE::GetHandle() { \
        return h; \
    } \
    TYPE::~TYPE() { \
        if (h != NULL) { \
            DEALLOC_CALL; \
        } \
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

SMARTHANDLECLASS_DEF(BCryptKey, BCRYPT_KEY_HANDLE, BCryptDestroyKey(h))
SMARTHANDLECLASS_DEF(BCryptAlgProv, BCRYPT_ALG_HANDLE, BCryptCloseAlgorithmProvider(h, 0))
SMARTHANDLECLASS_DEF(CryptKey, HCRYPTKEY, CryptDestroyKey(h))
SMARTHANDLECLASS_DEF(CryptContext, HCRYPTPROV, CryptReleaseContext(h, 0))