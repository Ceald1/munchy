#include <wchar.h>
#include <windows.h>

#include <rpc.h>

#include "dc_sync/rpc_dc.h"

void __RPC_FAR *__RPC_USER midl_user_allocate(size_t cBytes) {
  return LocalAlloc(LPTR, cBytes);
}

void __RPC_USER midl_user_free(void __RPC_FAR *p) { LocalFree(p); }

void __RPC_USER ReadFcn(void *State, char **pBuffer, unsigned int *pSize) {
  *pBuffer = (char *)((PRPC_FCNSTRUCT)State)->addr;
  ((PRPC_FCNSTRUCT)State)->addr = *pBuffer + *pSize;
  ((PRPC_FCNSTRUCT)State)->size -= *pSize;
}

BOOL createBinding(LPCWSTR uuid, LPCWSTR ProtSeq, LPCWSTR NetworkAddr,
                   LPCWSTR Endpoint, LPCWSTR Service,
                   BOOL addServiceToNetworkAddr, DWORD AuthnSvc,
                   RPC_AUTH_IDENTITY_HANDLE hAuth, DWORD ImpersonationType,
                   RPC_BINDING_HANDLE *hBinding,
                   void(RPC_ENTRY *RpcSecurityCallback)(void *)) {
  BOOL status = FALSE;
  RPC_STATUS rpcStatus;
  RPC_WSTR StringBinding = NULL;
  RPC_SECURITY_QOS SecurityQOS = {RPC_C_SECURITY_QOS_VERSION,
                                  RPC_C_QOS_CAPABILITIES_MUTUAL_AUTH,
                                  RPC_C_QOS_IDENTITY_STATIC, ImpersonationType};
  DWORD szServer, szPrefix;
  LPWSTR fullServer = NULL;

  *hBinding = NULL;
  rpcStatus = RpcStringBindingComposeW(
      (RPC_WSTR)uuid, (RPC_WSTR)ProtSeq, (RPC_WSTR)NetworkAddr,
      (RPC_WSTR)Endpoint, NULL, &StringBinding);
  if (rpcStatus == RPC_S_OK) {
    rpcStatus = RpcBindingFromStringBindingW(StringBinding, hBinding);
    if (rpcStatus == RPC_S_OK) {
      if (*hBinding) {
        if (AuthnSvc != RPC_C_AUTHN_NONE) {
          if (addServiceToNetworkAddr) {
            if (NetworkAddr && Service) {
              szServer = lstrlenW(NetworkAddr) * sizeof(wchar_t);
              szPrefix = lstrlenW(Service) * sizeof(wchar_t);
              if (fullServer = (LPWSTR)LocalAlloc(
                      LPTR, szPrefix + sizeof(wchar_t) + szServer +
                                sizeof(wchar_t))) {
                RtlCopyMemory(fullServer, Service, szPrefix);
                RtlCopyMemory((PBYTE)fullServer + szPrefix + sizeof(wchar_t),
                              NetworkAddr, szServer);
                ((PBYTE)fullServer)[szPrefix] = L'/';
              }
            } else
              wprintf(L"Cannot add NetworkAddr & Service if NULL\n");
          }

          if (!addServiceToNetworkAddr || fullServer) {
            rpcStatus = RpcBindingSetAuthInfoExW(
                *hBinding, (RPC_WSTR)(fullServer ? fullServer : Service),
                RPC_C_AUTHN_LEVEL_PKT_PRIVACY, AuthnSvc, hAuth,
                RPC_C_AUTHZ_NONE, &SecurityQOS);
            if (rpcStatus == RPC_S_OK) {
              if (RpcSecurityCallback) {
                rpcStatus =
                    RpcBindingSetOption(*hBinding, RPC_C_OPT_SECURITY_CALLBACK,
                                        (ULONG_PTR)RpcSecurityCallback);
                status = (rpcStatus == RPC_S_OK);
                if (!status)
                  wprintf(L"RpcBindingSetOption: 0x%08x (%u)\n", rpcStatus,
                          rpcStatus);
              } else
                status = TRUE;
            } else
              wprintf(L"RpcBindingSetAuthInfoEx: 0x%08x (%u)\n", rpcStatus,
                      rpcStatus);
          }
        } else
          status = TRUE;

        if (!status) {
          rpcStatus = RpcBindingFree(hBinding);
          if (rpcStatus == RPC_S_OK)
            *hBinding = NULL;
          else
            wprintf(L"RpcBindingFree: 0x%08x (%u)\n", rpcStatus, rpcStatus);
        }
      } else
        wprintf(L"No Binding!\n");
    } else
      wprintf(L"RpcBindingFromStringBinding: 0x%08x (%u)\n", rpcStatus,
              rpcStatus);
    RpcStringFreeW(&StringBinding);
  } else
    wprintf(L"RpcStringBindingCompose: 0x%08x (%u)\n", rpcStatus, rpcStatus);
  return status;
}
