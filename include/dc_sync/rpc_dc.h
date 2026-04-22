#pragma once
#include <windows.h>

typedef struct RPC_FCNSTRUCT {
  PVOID addr;
  size_t size;
} RPC_FCNSTRUCT, *PRPC_FCNSTRUCT;

BOOL createBinding(LPCWSTR uuid, LPCWSTR ProtSeq, LPCWSTR NetworkAddr,
                   LPCWSTR Endpoint, LPCWSTR Service,
                   BOOL addServiceToNetworkAddr, DWORD AuthnSvc,
                   RPC_AUTH_IDENTITY_HANDLE hAuth, DWORD ImpersonationType,
                   RPC_BINDING_HANDLE *hBinding,
                   void(RPC_ENTRY *RpcSecurityCallback)(void *));
