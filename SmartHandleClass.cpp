#include "SmartHandleClass.h"
#include "AppExceptions.h"

SMARTHANDLECLASS_IMPL(BCryptKey, BCRYPT_KEY_HANDLE, BCryptDestroyKey(h));
SMARTHANDLECLASS_IMPL(BCryptAlgProv, BCRYPT_ALG_HANDLE, BCryptCloseAlgorithmProvider(h, 0));
SMARTHANDLECLASS_IMPL(CryptKey, HCRYPTKEY, CryptDestroyKey(h));
SMARTHANDLECLASS_IMPL(CryptContext, HCRYPTPROV, CryptReleaseContext(h, 0));