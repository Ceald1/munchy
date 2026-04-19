#include <windows.h>

#ifndef WINAPI
#define WINAPI __stdcall
#endif

#ifndef SEC_ENTRY
#define SEC_ENTRY __stdcall
#endif

#ifndef _In_
#define _In_
#define _Out_
#endif

typedef NTSTATUS(WINAPI *LsaCallAuthenticationPackage_t)(
    _In_ HANDLE LsaHandle, _In_ ULONG AuthenticationPackage,
    _In_reads_bytes_(SubmitBufferLength) PVOID ProtocolSubmitBuffer,
    _In_ ULONG SubmitBufferLength,
    _Outptr_opt_result_buffer_maybenull_(*ReturnBufferLength)
        PVOID *ProtocolReturnBuffer,
    _Out_opt_ PULONG ReturnBufferLength, _Out_opt_ PNTSTATUS ProtocolStatus);

typedef NTSTATUS(WINAPI *LsaConnectUntrusted_t)(PHANDLE LsaHandle);

typedef NTSTATUS(WINAPI *LsaFreeReturnBuffer_t)(_In_ PVOID Buffer);

#ifndef _NTDEF_
#ifndef _UNICODE_STRING
#define _UNICODE_STRING
/**
 * The UNICODE_STRING structure defines a counted string used for Unicode
 * strings.
 *
 * \sa
 * https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_unicode_string
 */
typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

#endif
#endif
#ifndef _NTLSA_

typedef struct _LSA_LAST_INTER_LOGON_INFO {
  LARGE_INTEGER LastSuccessfulLogon;
  LARGE_INTEGER LastFailedLogon;
  ULONG FailedAttemptCountSinceLastSuccessfulLogon;
} LSA_LAST_INTER_LOGON_INFO, *PLSA_LAST_INTER_LOGON_INFO;

#endif

typedef UNICODE_STRING LSA_UNICODE_STRING, *PLSA_UNICODE_STRING;

typedef struct _SECURITY_LOGON_SESSION_DATA {
  ULONG Size;
  LUID LogonId;
  LSA_UNICODE_STRING UserName;
  LSA_UNICODE_STRING LogonDomain;
  LSA_UNICODE_STRING AuthenticationPackage;
  ULONG LogonType;
  ULONG Session;
  PSID Sid;
  LARGE_INTEGER LogonTime;

  //
  // new for whistler:
  //

  LSA_UNICODE_STRING LogonServer;
  LSA_UNICODE_STRING DnsDomainName;
  LSA_UNICODE_STRING Upn;

  //
  // new for LH
  //

  ULONG UserFlags;

  LSA_LAST_INTER_LOGON_INFO LastLogonInfo;
  LSA_UNICODE_STRING LogonScript;
  LSA_UNICODE_STRING ProfilePath;
  LSA_UNICODE_STRING HomeDirectory;
  LSA_UNICODE_STRING HomeDirectoryDrive;

  LARGE_INTEGER LogoffTime;
  LARGE_INTEGER KickOffTime;
  LARGE_INTEGER PasswordLastSet;
  LARGE_INTEGER PasswordCanChange;
  LARGE_INTEGER PasswordMustChange;
} SECURITY_LOGON_SESSION_DATA, *PSECURITY_LOGON_SESSION_DATA;

typedef NTSTATUS(WINAPI *LsaGetLogonSessionData_t)(
    _In_ PLUID LogonId, _Out_ PSECURITY_LOGON_SESSION_DATA *ppLogonSessionData);

typedef struct _STRING {
  USHORT Length;
  USHORT MaximumLength;
  _Field_size_bytes_part_opt_(MaximumLength, Length) PCHAR Buffer;
} STRING, *PSTRING, ANSI_STRING, *PANSI_STRING, OEM_STRING, *POEM_STRING;

typedef STRING LSA_STRING, *PLSA_STRING;

typedef NTSTATUS(WINAPI *LsaLookupAuthenticationPackage_t)(
    _In_ HANDLE LsaHandle, _In_ PLSA_STRING PackageName,
    _Out_ PULONG AuthenticationPackage);

typedef void(WINAPI *RtlCopyMemory_t)(void *Destination, const void *Source,
                                      size_t Length);

typedef SECURITY_STATUS(SEC_ENTRY *SEC_GET_KEY_FN)(void *Arg, void *Principal,
                                                   void *KeyVer, void **Key,
                                                   unsigned long *Status);

typedef struct _SecHandle {
  ULONG_PTR dwLower;
  ULONG_PTR dwUpper;
} SecHandle, *PSecHandle;

typedef PSecHandle PCredHandle;
typedef struct _SECURITY_INTEGER {
  ULONG LowPart;
  LONG HighPart;
} SECURITY_INTEGER, *PSECURITY_INTEGER;

typedef SECURITY_INTEGER TimeStamp, *PTimeStamp;

typedef SECURITY_STATUS(WINAPI *AcquireCredentialsHandleA_t)(
    LPSTR pszPrincipal, LPSTR pszPackage, unsigned long fCredentialUse,
    void *pvLogonId, void *pAuthData, SEC_GET_KEY_FN pGetKeyFn,
    void *pvGetKeyArgument, PCredHandle phCredential, PTimeStamp ptsExpiry);

typedef struct _SecBuffer {
  ULONG cbBuffer;
  ULONG BufferType;
  PVOID pvBuffer;
} SecBuffer, *PSecBuffer;

typedef struct _SecBufferDesc {
  ULONG ulVersion;
  ULONG cBuffers;
  PSecBuffer pBuffers;
} SecBufferDesc, *PSecBufferDesc;
typedef CHAR SEC_CHAR;
typedef PSecHandle PCtxtHandle;

typedef SECURITY_STATUS(WINAPI *InitializeSecurityContextA_t)(
    PCredHandle phCredential, PCtxtHandle phContext, SEC_CHAR *pszTargetName,
    unsigned long fContextReq, unsigned long Reserved1,
    unsigned long TargetDataRep, PSecBufferDesc pInput, unsigned long Reserved2,
    PCtxtHandle phNewContext, PSecBufferDesc pOutput,
    unsigned long *pfContextAttr, PTimeStamp ptsExpiry);

// custom
//
HANDLE NewLsaCredentialHandle();
ULONG GetAuthPackage(HANDLE lsaHandle, char *PackageName);
NTSTATUS Kerberos_ask(PCWCHAR targetName, char *filename,
                      LPCWSTR EncryptionType, LPCWSTR CacheOption,
                      void *credHandle);

NTSTATUS
PreAuth(char *user, char *passwd, char *domain, char *spn,
        char *filename); // get a credential handle for passing to Kerberos_ask

#if (_WIN32_WINNT >= 0x0501)
#define KERB_USE_DEFAULT_TICKET_FLAGS 0x0

// CacheOptions
#define KERB_RETRIEVE_TICKET_DEFAULT 0x0
#endif
#define KERB_RETRIEVE_TICKET_DONT_USE_CACHE 0x1
#define KERB_RETRIEVE_TICKET_USE_CACHE_ONLY 0x2
#define KERB_RETRIEVE_TICKET_USE_CREDHANDLE 0x4
#if (_WIN32_WINNT >= 0x0501)
#define KERB_RETRIEVE_TICKET_AS_KERB_CRED 0x8
#define KERB_RETRIEVE_TICKET_WITH_SEC_CRED 0x10
#endif
#if (_WIN32_WINNT >= 0x0600)
#define KERB_RETRIEVE_TICKET_CACHE_TICKET 0x20
#endif

#if (_WIN32_WINNT >= 0x0601)
#define KERB_RETRIEVE_TICKET_MAX_LIFETIME 0x40
#endif
typedef enum _KERB_PROTOCOL_MESSAGE_TYPE {
  KerbDebugRequestMessage = 0,
  KerbQueryTicketCacheMessage,
  KerbChangeMachinePasswordMessage,
  KerbVerifyPacMessage,
  KerbRetrieveTicketMessage,
  KerbUpdateAddressesMessage,
  KerbPurgeTicketCacheMessage,
  KerbChangePasswordMessage,
  KerbRetrieveEncodedTicketMessage,
  KerbDecryptDataMessage,
  KerbAddBindingCacheEntryMessage,
  KerbSetPasswordMessage,
  KerbSetPasswordExMessage,
#if (_WIN32_WINNT == 0x0500)
  KerbAddExtraCredentialsMessage = 17
#endif
#if (_WIN32_WINNT >= 0x0501)
  KerbVerifyCredentialsMessage,
  KerbQueryTicketCacheExMessage,
  KerbPurgeTicketCacheExMessage,
#endif
#if (_WIN32_WINNT >= 0x0502)
  KerbRefreshSmartcardCredentialsMessage,
  KerbAddExtraCredentialsMessage,
  KerbQuerySupplementalCredentialsMessage,
#endif
#if (_WIN32_WINNT >= 0x0600)
  KerbTransferCredentialsMessage,
  KerbQueryTicketCacheEx2Message,
  KerbSubmitTicketMessage,
  KerbAddExtraCredentialsExMessage,
#endif
#if (_WIN32_WINNT >= 0x0602)
  KerbQueryKdcProxyCacheMessage,
  KerbPurgeKdcProxyCacheMessage,
  KerbQueryTicketCacheEx3Message,
  KerbCleanupMachinePkinitCredsMessage,
  KerbAddBindingCacheEntryExMessage,
  KerbQueryBindingCacheMessage,
  KerbPurgeBindingCacheMessage,
  KerbPinKdcMessage,
  KerbUnpinAllKdcsMessage,
  KerbQueryDomainExtendedPoliciesMessage,
  KerbQueryS4U2ProxyCacheMessage,
#endif
#if (_WIN32_WINNT >= 0x0A00)
  KerbRetrieveKeyTabMessage,
  KerbRefreshPolicyMessage,
  KerbPrintCloudKerberosDebugMessage,
  KerbNetworkTicketLogonMessage,
  KerbNlChangeMachinePasswordMessage,
#endif
} KERB_PROTOCOL_MESSAGE_TYPE,
    *PKERB_PROTOCOL_MESSAGE_TYPE;

typedef struct _KERB_EXTERNAL_NAME {
  SHORT NameType;
  USHORT NameCount;
  UNICODE_STRING Names[ANYSIZE_ARRAY];
} KERB_EXTERNAL_NAME, *PKERB_EXTERNAL_NAME;
typedef struct KERB_CRYPTO_KEY {
  LONG KeyType;
  ULONG Length;
  PUCHAR Value;
} KERB_CRYPTO_KEY, *PKERB_CRYPTO_KEY;

typedef struct _KERB_EXTERNAL_TICKET {
  PKERB_EXTERNAL_NAME ServiceName;
  PKERB_EXTERNAL_NAME TargetName;
  PKERB_EXTERNAL_NAME ClientName;
  UNICODE_STRING DomainName;
  UNICODE_STRING TargetDomainName;
  UNICODE_STRING AltTargetDomainName; // contains ClientDomainName
  KERB_CRYPTO_KEY SessionKey;
  ULONG TicketFlags;
  ULONG Flags;
  LARGE_INTEGER KeyExpirationTime;
  LARGE_INTEGER StartTime;
  LARGE_INTEGER EndTime;
  LARGE_INTEGER RenewUntil;
  LARGE_INTEGER TimeSkew;
  ULONG EncodedTicketSize;
  PUCHAR EncodedTicket;
} KERB_EXTERNAL_TICKET, *PKERB_EXTERNAL_TICKET;

typedef struct _KERB_RETRIEVE_TKT_REQUEST {
  KERB_PROTOCOL_MESSAGE_TYPE MessageType;
  LUID LogonId;
  UNICODE_STRING TargetName;
  ULONG TicketFlags;
  ULONG CacheOptions;
  LONG EncryptionType;
  SecHandle CredentialsHandle;
} KERB_RETRIEVE_TKT_REQUEST, *PKERB_RETRIEVE_TKT_REQUEST;

typedef struct _KERB_RETRIEVE_TKT_RESPONSE {
  KERB_EXTERNAL_TICKET Ticket;
} KERB_RETRIEVE_TKT_RESPONSE, *PKERB_RETRIEVE_TKT_RESPONSE;

typedef struct {
  long length;          /* Total count of octets (bytes) */
  unsigned char *value; /* Pointer to the memory buffer */
} OssBuf;
#define KERB_ETYPE_RC4_HMAC_NT 23
#define KERB_ETYPE_DES3_CBC_MD5 5
#define KERB_ETYPE_AES256_CTS_HMAC_SHA1_96 18
#define KERB_ETYPE_AES128_CTS_HMAC_SHA1_96 17
#define KERB_ETYPE_DEFAULT 0x0
#define SECPKG_CRED_OUTBOUND 2

typedef enum _KERB_LOGON_SUBMIT_TYPE {
  KerbInteractiveLogon = 2,
  KerbSmartCardLogon = 6,
  KerbWorkstationUnlockLogon = 7,
  KerbSmartCardUnlockLogon = 8,
  KerbProxyLogon = 9,
  KerbTicketLogon = 10,
  KerbTicketUnlockLogon = 11,
  KerbS4ULogon = 12,
  KerbCertificateLogon = 13,
  KerbCertificateS4ULogon = 14,
  KerbCertificateUnlockLogon = 15,
  KerbNoElevationLogon = 83,
  KerbLuidLogon = 84
} KERB_LOGON_SUBMIT_TYPE,
    *PKERB_LOGON_SUBMIT_TYPE;

typedef struct _KERB_INTERACTIVE_LOGON {
  KERB_LOGON_SUBMIT_TYPE MessageType;
  UNICODE_STRING LogonDomainName;
  UNICODE_STRING UserName;
  UNICODE_STRING Password;
} KERB_INTERACTIVE_LOGON, *PKERB_INTERACTIVE_LOGON;

typedef enum _SECURITY_LOGON_TYPE {
  UndefinedLogonType = 0,  // This is used to specify an undefied logon type
  Interactive = 2,         // Interactively logged on (locally or remotely)
  Network,                 // Accessing system via network
  Batch,                   // Started via a batch queue
  Service,                 // Service started by service controller
  Proxy,                   // Proxy logon
  Unlock,                  // Unlock workstation
  NetworkCleartext,        // Network logon with cleartext credentials
  NewCredentials,          // Clone caller, new default credentials
  RemoteInteractive,       // Remote, yet interactive. Terminal server
  CachedInteractive,       // Try cached credentials without hitting the net.
  CachedRemoteInteractive, // Same as RemoteInteractive, this is used internally
                           // for auditing purpose
  CachedUnlock             // Cached Unlock workstation
} SECURITY_LOGON_TYPE,
    *PSECURITY_LOGON_TYPE;

typedef NTSTATUS(WINAPI *LsaLogonUser_t)(
    _In_ HANDLE LsaHandle, _In_ PLSA_STRING OriginName,
    _In_ SECURITY_LOGON_TYPE LogonType, _In_ ULONG AuthenticationPackage,
    _In_reads_bytes_(AuthenticationInformationLength)
        PVOID AuthenticationInformation,
    _In_ ULONG AuthenticationInformationLength,
    _In_opt_ PTOKEN_GROUPS LocalGroups, _In_ PTOKEN_SOURCE SourceContext,
    _Out_ PVOID *ProfileBuffer, _Out_ PULONG ProfileBufferLength,
    _Inout_ PLUID LogonId, _Out_ PHANDLE Token, _Out_ PQUOTA_LIMITS Quotas,
    _Out_ PNTSTATUS SubStatus);

typedef struct {
  const LPCWSTR name;
  int value;
} map_entry;
