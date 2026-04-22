#pragma once

#include <stdio.h>
#include <windows.h>

#include <NtDsAPI.h>
#include <ntsecapi.h>

#include "dcsync.h"

#include "dc_sync/rpc_dc.h"
#include "rpcdce.h"

#include <DsGetDC.h>

BOOL getCurrentDomainInfo(PPOLICY_DNS_DOMAIN_INFO *pDomainInfo) {
  LSA_HANDLE hLSA = NULL;
  LSA_OBJECT_ATTRIBUTES oaLsa = {0};
  NTSTATUS status;

  *pDomainInfo = NULL;

  status = LsaOpenPolicy(NULL, &oaLsa, POLICY_VIEW_LOCAL_INFORMATION, &hLSA);

  if (status != 0) {
    return FALSE;
  }

  status = LsaQueryInformationPolicy(hLSA, PolicyDnsDomainInformation,
                                     (PVOID *)pDomainInfo);

  LsaClose(hLSA);

  return 0 == status && (*pDomainInfo != NULL);
}

BOOL getDC(LPCWSTR fullDomainName, DWORD altFlags, LPWSTR *fullDCName) {
  if (!fullDCName)
    return FALSE;

  BOOL status = FALSE;
  DWORD ret;
  DWORD size;
  PDOMAIN_CONTROLLER_INFOW cInfo = NULL;

  ret = DsGetDcNameW(NULL, fullDomainName, NULL, NULL,
                     altFlags | DS_IS_DNS_NAME | DS_RETURN_DNS_NAME, &cInfo);

  if (ret == ERROR_SUCCESS && cInfo) {

    LPWSTR name = cInfo->DomainControllerName;
    if (name[0] == L'\\' && name[1] == L'\\') {
      name += 2;
    }

    size = (DWORD)(wcslen(name) + 1) * sizeof(WCHAR);

    *fullDCName = (LPWSTR)LocalAlloc(LPTR, size);
    if (*fullDCName) {
      RtlCopyMemory(*fullDCName, name, size);
      status = TRUE;
    }

    // NetApiBufferFree(cInfo);
  } else {
    wprintf(L"DsGetDcName: %u\n", ret);
  }

  return status;
}

BOOL InitializeBind() {}

void DCSync() {

  printf("fuck microsoft!!\n");
  RPC_BINDING_HANDLE hBinding;
  HMODULE ntdll = GetModuleHandleA("ntdll.dll");
  RtlGetNtVersionNumbers_t RtlGetNtVersionNumbers =
      (RtlGetNtVersionNumbers_t)GetProcAddress(ntdll, "RtlGetNtVersionNumbers");
  LPWSTR szDomain = NULL, szDc = NULL, szService = NULL;
  BOOL status;
  DWORD pMajor, pMinor, pBuild = {0};
  PPOLICY_DNS_DOMAIN_INFO pDomainInfo = NULL;
  status = getCurrentDomainInfo(&pDomainInfo);
  if (status == FALSE) {
    printf("failed to find DC\n");
    return;
  }
  wprintf(L"found Domain: %ls\n", pDomainInfo->DnsDomainName.Buffer);
  szDomain = pDomainInfo->DnsDomainName.Buffer;
  status = getDC(szDomain, DS_DIRECTORY_SERVICE_REQUIRED, &szDc);
  if (status != TRUE) {
    printf("failed to get DC 0x%lx\n", GetLastError());
    return;
  }
  wprintf(L"Got DC: %ls\n", szDc);
  RtlGetNtVersionNumbers(&pMajor, &pMinor, &pMinor);
  printf("got version numbers\n");
  szService = L"ldap";
  status =
      createBinding(NULL, L"ncacn_ip_tcp", szDc, NULL, szService, TRUE,
                    (pMajor < 6) ? RPC_C_AUTHN_GSS_KERBEROS : RPC_C_AUTHN_WINNT,
                    NULL, RPC_C_IMP_LEVEL_DEFAULT, &hBinding, NULL);
  if (status != TRUE) {
    printf("failed to make binding!\n");
    return;
  }
  printf("made binding!\n");
}
