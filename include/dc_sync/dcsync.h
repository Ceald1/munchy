#include <rpc.h>
#include <wincrypt.h>
#include <windows.h>

#include <ntdsapi.h>

DECLSPEC_IMPORT int __cdecl MSVCRT$_snprintf(char *buffer, size_t count,
                                             const char *format, ...);
DECLSPEC_IMPORT void *__cdecl MSVCRT$memset(void *dest, int c, size_t count);
DECLSPEC_IMPORT void *__cdecl MSVCRT$memcpy(void *dest, const void *src,
                                            size_t count);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$strlen(const char *str);
DECLSPEC_IMPORT char *__cdecl MSVCRT$strcat(char *dest, const char *src);
DECLSPEC_IMPORT void *__cdecl MSVCRT$malloc(size_t size);
DECLSPEC_IMPORT void __cdecl MSVCRT$free(void *ptr);

DECLSPEC_IMPORT void __cdecl KERNEL32$Sleep(unsigned int milliseconds);

// RPC Functions
DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY RPCRT4$RpcStringBindingComposeA(
    unsigned char *ObjUuid, unsigned char *ProtSeq, unsigned char *NetworkAddr,
    unsigned char *Endpoint, unsigned char *Options,
    unsigned char **StringBinding);

DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY RPCRT4$RpcBindingFromStringBindingA(
    unsigned char *StringBinding, RPC_BINDING_HANDLE *Binding);

DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY
RPCRT4$RpcStringFreeA(unsigned char **String);
DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY
RPCRT4$RpcBindingFree(RPC_BINDING_HANDLE *Binding);

DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY RPCRT4$RpcBindingSetAuthInfoA(
    RPC_BINDING_HANDLE Binding, unsigned char *ServerPrincName,
    unsigned long AuthnLevel, unsigned long AuthnSvc, void *AuthIdentity,
    unsigned long AuthzSvc);

DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY RPCRT4$RpcBindingSetOption(
    RPC_BINDING_HANDLE hBinding, unsigned long option, ULONG_PTR optionValue);

DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY RPCRT4$I_RpcBindingInqSecurityContext(
    RPC_BINDING_HANDLE Binding, void **SecurityContextHandle);

DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY RPCRT4$UuidCreate(UUID *Uuid);

DECLSPEC_IMPORT CLIENT_CALL_RETURN RPC_VAR_ENTRY
RPCRT4$NdrClientCall2(void *pStubDescriptor, void *pFormat, ...);

typedef struct {
  DWORD cb;
  DWORD dwFlags;
  GUID SiteObjGuid;
  DWORD Pid;
  DWORD dwReplEpoch;
} DRS_EXTENSIONS_INT;

// typedef void *DRS_HANDLE;

void DCSync(char *DN, char *objGuid);

// DRS Flags
#define DRS_INIT_SYNC 0x00000001
#define DRS_WRIT_REP 0x00000010
#define DRS_NEVER_SYNCED 0x00000020
#define DRS_FULL_SYNC_NOW 0x00000200
#define DRS_SYNC_URGENT 0x00008000
#define DRS_GET_ANC 0x00000008
#define DRS_GET_NC_SIZE 0x00001000
#define DRS_SPECIAL_SECRET_PROCESSING 0x00000004

// DRS Extended Operations
#define EXOP_REPL_OBJ 6
#define EXOP_REPL_SECRETS 3
