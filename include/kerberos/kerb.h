#include "asn1/kull_m_asn1.h"
#include "kull_m_crypto_system.h"
#include "lsa/lsa.h"

#include <windows.h>

#define AES_256_KEY_LENGTH 32
#define AES_128_KEY_LENGTH 16

typedef struct _KERB_SID_AND_ATTRIBUTES {
  PISID Sid;
  ULONG Attributes;
} KERB_SID_AND_ATTRIBUTES, *PKERB_SID_AND_ATTRIBUTES;

#define KRB_KEY_USAGE_AS_REP_TGS_REP 2

typedef struct _KUHL_M_KERBEROS_LIFETIME_DATA {
  FILETIME TicketStart;
  FILETIME TicketEnd;
  FILETIME TicketRenew;
} KUHL_M_KERBEROS_LIFETIME_DATA, *PKUHL_M_KERBEROS_LIFETIME_DATA;

// pac defs

typedef wchar_t *CLAIM_ID;
typedef wchar_t **PCLAIM_ID;

typedef enum _CLAIM_TYPE {
  CLAIM_TYPE_INT64 = 1,
  CLAIM_TYPE_UINT64 = 2,
  CLAIM_TYPE_STRING = 3,
  CLAIM_TYPE_BOOLEAN = 6
} CLAIM_TYPE,
    *PCLAIM_TYPE;

typedef enum _CLAIMS_SOURCE_TYPE {
  CLAIMS_SOURCE_TYPE_AD = 1,
  CLAIMS_SOURCE_TYPE_CERTIFICATE = (CLAIMS_SOURCE_TYPE_AD + 1)
} CLAIMS_SOURCE_TYPE;

typedef enum _CLAIMS_COMPRESSION_FORMAT {
  CLAIMS_COMPRESSION_FORMAT_NONE = 0,
  CLAIMS_COMPRESSION_FORMAT_LZNT1 = 2,
  CLAIMS_COMPRESSION_FORMAT_XPRESS = 3,
  CLAIMS_COMPRESSION_FORMAT_XPRESS_HUFF = 4
} CLAIMS_COMPRESSION_FORMAT;

typedef struct _CLAIM_ENTRY {
  CLAIM_ID Id;
  CLAIM_TYPE Type;
  union {
    struct _ci64 {
      ULONG ValueCount;
      LONG64 *Int64Values;
    } ci64;
    struct _cui64 {
      ULONG ValueCount;
      ULONG64 *Uint64Values;
    } cui64;
    struct _cs {
      ULONG ValueCount;
      LPWSTR *StringValues;
    } cs;
    struct _cb {
      ULONG ValueCount;
      ULONG64 *BooleanValues;
    } cb;
  } Values;
} CLAIM_ENTRY, *PCLAIM_ENTRY;

typedef struct _CLAIMS_ARRAY {
  CLAIMS_SOURCE_TYPE usClaimsSourceType;
  ULONG ulClaimsCount;
  PCLAIM_ENTRY ClaimEntries;
} CLAIMS_ARRAY, *PCLAIMS_ARRAY;

typedef struct _CLAIMS_SET {
  ULONG ulClaimsArrayCount;
  PCLAIMS_ARRAY ClaimsArrays;
  USHORT usReservedType;
  ULONG ulReservedFieldSize;
  BYTE *ReservedField;
} CLAIMS_SET, *PCLAIMS_SET;

typedef struct _CLAIMS_SET_METADATA {
  ULONG ulClaimsSetSize;
  BYTE *ClaimsSet;
  CLAIMS_COMPRESSION_FORMAT usCompressionFormat;
  ULONG ulUncompressedClaimsSetSize;
  USHORT usReservedType;
  ULONG ulReservedFieldSize;
  BYTE *ReservedField;
} CLAIMS_SET_METADATA, *PCLAIMS_SET_METADATA;

// end of pacs
//
// encryption types

#define KERB_ETYPE_AES128_CTS_HMAC_SHA1_96 17
#define KERB_ETYPE_AES256_CTS_HMAC_SHA1_96 18
#define KERB_ETYPE_AES128_CTS_HMAC_SHA256 19
#define KERB_ETYPE_AES256_CTS_HMAC_SHA384 20

#define KERB_ETYPE_RC4_MD4 -128 // FFFFFF80
#define KERB_ETYPE_RC4_PLAIN2 -129
#define KERB_ETYPE_RC4_LM -130
#define KERB_ETYPE_RC4_SHA -131
#define KERB_ETYPE_DES_PLAIN -132
#define KERB_ETYPE_RC4_HMAC_OLD -133 // FFFFFF7B
#define KERB_ETYPE_RC4_PLAIN_OLD -134
#define KERB_ETYPE_RC4_HMAC_OLD_EXP -135
#define KERB_ETYPE_RC4_PLAIN_OLD_EXP -136
#define KERB_ETYPE_RC4_PLAIN -140
#define KERB_ETYPE_RC4_PLAIN_EXP -141
#define KERB_ETYPE_RC4_HMAC_NT 23
#define KERB_ETYPE_NULL 0

#define KRB_NT_PRINCIPAL 1
#define KRB_NT_SRV_INST 2

// ticket flags
#define KERB_TICKET_FLAGS_reserved 0x80000000
#define KERB_TICKET_FLAGS_forwardable 0x40000000
#define KERB_TICKET_FLAGS_forwarded 0x20000000
#define KERB_TICKET_FLAGS_proxiable 0x10000000
#define KERB_TICKET_FLAGS_proxy 0x08000000
#define KERB_TICKET_FLAGS_may_postdate 0x04000000
#define KERB_TICKET_FLAGS_postdated 0x02000000
#define KERB_TICKET_FLAGS_invalid 0x01000000
#define KERB_TICKET_FLAGS_renewable 0x00800000
#define KERB_TICKET_FLAGS_initial 0x00400000
#define KERB_TICKET_FLAGS_pre_authent 0x00200000
#define KERB_TICKET_FLAGS_hw_authent 0x00100000
#define KERB_TICKET_FLAGS_ok_as_delegate 0x00040000
#define KERB_TICKET_FLAGS_name_canonicalize 0x00010000
#if (_WIN32_WINNT == 0x0501)
#define KERB_TICKET_FLAGS_cname_in_pa_data 0x00040000
#endif
#define KERB_TICKET_FLAGS_enc_pa_rep 0x00010000
#define KERB_TICKET_FLAGS_reserved1 0x00000001

// Checksum algorithms.
// These algorithms are keyed internally for our use.

#define KERB_CHECKSUM_NONE 0
#define KERB_CHECKSUM_CRC32 1
#define KERB_CHECKSUM_MD4 2
#define KERB_CHECKSUM_KRB_DES_MAC 4
#if (_WIN32_WINNT >= 0x0501)
#define KERB_CHECKSUM_KRB_DES_MAC_K 5
#endif
#define KERB_CHECKSUM_MD5 7
#define KERB_CHECKSUM_MD5_DES 8

#define KERB_CHECKSUM_SHA1_NEW 14 // defined in RFC3961
#define KERB_CHECKSUM_HMAC_SHA1_96_AES128 15
#define KERB_CHECKSUM_HMAC_SHA1_96_AES256 16

#define KERB_CHECKSUM_LM -130
#define KERB_CHECKSUM_SHA1 -131
#define KERB_CHECKSUM_REAL_CRC32 -132
#define KERB_CHECKSUM_DES_MAC -133
#define KERB_CHECKSUM_DES_MAC_MD5 -134
#define KERB_CHECKSUM_MD25 -135
#define KERB_CHECKSUM_RC4_MD5 -136
#define KERB_CHECKSUM_MD5_HMAC -137 // used by netlogon
#define KERB_CHECKSUM_HMAC_MD5 -138 // used by Kerberos
#define KERB_CHECKSUM_SHA256 -139
#define KERB_CHECKSUM_SHA384 -140
#define KERB_CHECKSUM_SHA512 -141

// context definitions
//
#define ID_APP_TICKET 1
#define ID_CTX_TICKET_TKT_VNO 0
#define ID_CTX_TICKET_REALM 1
#define ID_CTX_TICKET_SNAME 2
#define ID_CTX_TICKET_ENC_PART 3

#define ID_APP_ENCTICKETPART 3
#define ID_CTX_ENCTICKETPART_FLAGS 0
#define ID_CTX_ENCTICKETPART_KEY 1
#define ID_CTX_ENCTICKETPART_CREALM 2
#define ID_CTX_ENCTICKETPART_CNAME 3
#define ID_CTX_ENCTICKETPART_TRANSITED 4
#define ID_CTX_ENCTICKETPART_AUTHTIME 5
#define ID_CTX_ENCTICKETPART_STARTTIME 6
#define ID_CTX_ENCTICKETPART_ENDTIME 7
#define ID_CTX_ENCTICKETPART_RENEW_TILL 8
#define ID_CTX_ENCTICKETPART_CADDR 9
#define ID_CTX_ENCTICKETPART_AUTHORIZATION_DATA 10

#define ID_APP_KRB_CRED 22
#define ID_CTX_KRB_CRED_PVNO 0
#define ID_CTX_KRB_CRED_MSG_TYPE 1
#define ID_CTX_KRB_CRED_TICKETS 2
#define ID_CTX_KRB_CRED_ENC_PART 3

#define ID_APP_ENCKRBCREDPART 29
#define ID_CTX_ENCKRBCREDPART_TICKET_INFO 0
#define ID_CTX_ENCKRBCREDPART_NONCE 1
#define ID_CTX_ENCKRBCREDPART_TIMESTAMP 2
#define ID_CTX_ENCKRBCREDPART_USEC 3
#define ID_CTX_ENCKRBCREDPART_S_ADDRESS 4
#define ID_CTX_ENCKRBCREDPART_R_ADDRESS 5

#define ID_CTX_KRBCREDINFO_KEY 0
#define ID_CTX_KRBCREDINFO_PREALM 1
#define ID_CTX_KRBCREDINFO_PNAME 2
#define ID_CTX_KRBCREDINFO_FLAGS 3
#define ID_CTX_KRBCREDINFO_AUTHTIME 4
#define ID_CTX_KRBCREDINFO_STARTTIME 5
#define ID_CTX_KRBCREDINFO_ENDTIME 6
#define ID_CTX_KRBCREDINFO_RENEW_TILL 7
#define ID_CTX_KRBCREDINFO_SREAL 8
#define ID_CTX_KRBCREDINFO_SNAME 9
#define ID_CTX_KRBCREDINFO_CADDR 10

#define ID_CTX_PRINCIPALNAME_NAME_TYPE 0
#define ID_CTX_PRINCIPALNAME_NAME_STRING 1

#define ID_CTX_ENCRYPTIONKEY_KEYTYPE 0
#define ID_CTX_ENCRYPTIONKEY_KEYVALUE 1

#define ID_CTX_ENCRYPTEDDATA_ETYPE 0
#define ID_CTX_ENCRYPTEDDATA_KVNO 1
#define ID_CTX_ENCRYPTEDDATA_CIPHER 2

#define ID_CTX_TRANSITEDENCODING_TR_TYPE 0
#define ID_CTX_TRANSITEDENCODING_CONTENTS 1

#define ID_CTX_AUTHORIZATIONDATA_AD_TYPE 0
#define ID_CTX_AUTHORIZATIONDATA_AD_DATA 1

#define ID_AUTHDATA_AD_IF_RELEVANT 1
#define ID_AUTHDATA_AD_WIN2K_PAC 128

// versioning
#define KERBEROS_VERSION 5
#define KERBEROS_REVISION 6

// from mimikatz
//
typedef struct _KIWI_KERBEROS_BUFFER {
  ULONG Length;
  PUCHAR Value;
} KIWI_KERBEROS_BUFFER, *PKIWI_KERBEROS_BUFFER;

typedef struct _KIWI_KERBEROS_TICKET {
  PKERB_EXTERNAL_NAME ServiceName;
  LSA_UNICODE_STRING DomainName;
  PKERB_EXTERNAL_NAME TargetName;
  LSA_UNICODE_STRING TargetDomainName;
  PKERB_EXTERNAL_NAME ClientName;
  LSA_UNICODE_STRING AltTargetDomainName;

  LSA_UNICODE_STRING Description;

  FILETIME StartTime;
  FILETIME EndTime;
  FILETIME RenewUntil;

  LONG KeyType;
  KIWI_KERBEROS_BUFFER Key;

  ULONG TicketFlags;
  LONG TicketEncType;
  ULONG TicketKvno;
  KIWI_KERBEROS_BUFFER Ticket;
} KIWI_KERBEROS_TICKET, *PKIWI_KERBEROS_TICKET;

#define DEFAULT_GROUP_ATTRIBUTES                                               \
  (SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED)

#pragma pack(push, 4)
typedef struct _PAC_SIGNATURE_DATA {
  LONG SignatureType;
  UCHAR Signature[ANYSIZE_ARRAY]; // LM_NTLM_HASH_LENGTH];
                                  // USHORT RODCIdentifier;
  // USHORT  Reserverd;
} PAC_SIGNATURE_DATA, *PPAC_SIGNATURE_DATA;
#pragma pack(pop)

// exports
VOID Golden(const char *domain, const char *user, const char *rc4,
            const char *aes128, const char *aes256, const char *domainSID,
            const char *spn);

// pac validation crap
//

typedef UNICODE_STRING RPC_UNICODE_STRING;

typedef struct _GROUP_MEMBERSHIP {
  DWORD RelativeId;
  DWORD Attributes;
} GROUP_MEMBERSHIP, *PGROUP_MEMBERSHIP;

typedef struct _CYPHER_BLOCK {
  CHAR data[8];
} CYPHER_BLOCK, *PCYPHER_BLOCK;

typedef struct _NT_OWF_PASSWORD {
  CYPHER_BLOCK data[2];
} USER_SESSION_KEY;

typedef struct _KERB_VALIDATION_INFO {
  FILETIME LogonTime;
  FILETIME LogoffTime;
  FILETIME KickOffTime;
  FILETIME PasswordLastSet;
  FILETIME PasswordCanChange;
  FILETIME PasswordMustChange;
  RPC_UNICODE_STRING EffectiveName;
  RPC_UNICODE_STRING FullName;
  RPC_UNICODE_STRING LogonScript;
  RPC_UNICODE_STRING ProfilePath;
  RPC_UNICODE_STRING HomeDirectory;
  RPC_UNICODE_STRING HomeDirectoryDrive;
  USHORT LogonCount;
  USHORT BadPasswordCount;
  ULONG UserId;
  ULONG PrimaryGroupId;
  ULONG GroupCount;
  /* [size_is] */ PGROUP_MEMBERSHIP GroupIds;
  ULONG UserFlags;
  USER_SESSION_KEY UserSessionKey;
  RPC_UNICODE_STRING LogonServer;
  RPC_UNICODE_STRING LogonDomainName;
  PISID LogonDomainId;
  ULONG Reserved1[2];
  ULONG UserAccountControl;
  ULONG SubAuthStatus;
  FILETIME LastSuccessfulILogon;
  FILETIME LastFailedILogon;
  ULONG FailedILogonCount;
  ULONG Reserved3;
  ULONG SidCount;
  /* [size_is] */ PKERB_SID_AND_ATTRIBUTES ExtraSids;
  PISID ResourceGroupDomainSid;
  ULONG ResourceGroupCount;
  /* [size_is] */ PGROUP_MEMBERSHIP ResourceGroupIds;
} KERB_VALIDATION_INFO, *PKERB_VALIDATION_INFO;

typedef struct _PAC_CLIENT_INFO {
  FILETIME ClientId;
  USHORT NameLength;
  WCHAR Name[ANYSIZE_ARRAY];
} PAC_CLIENT_INFO, *PPAC_CLIENT_INFO;

typedef struct _PAC_INFO_BUFFER {
  ULONG ulType;
  ULONG cbBufferSize;
  ULONG64 Offset;
} PAC_INFO_BUFFER, *PPAC_INFO_BUFFER;

typedef struct _PACTYPE {
  ULONG cBuffers;
  ULONG Version;
  PAC_INFO_BUFFER Buffers[ANYSIZE_ARRAY];
} PACTYPE, *PPACTYPE;
#define SIZE_ALIGN(size, alignment)                                            \
  (size + ((size % alignment) ? (alignment - (size % alignment)) : 0))

BOOL kuhl_m_pac_validationInfo_to_PAC(PKERB_VALIDATION_INFO validationInfo,
                                      PFILETIME authtime, LPCWSTR clientname,
                                      LONG SignatureType,
                                      PCLAIMS_SET pClaimsSet, PPACTYPE *pacType,
                                      DWORD *pacLength);
BOOL kuhl_m_pac_validationInfo_to_CNAME_TINFO(PFILETIME authtime,
                                              LPCWSTR clientname,
                                              PPAC_CLIENT_INFO *pacClientInfo,
                                              DWORD *pacClientInfoLength);
NTSTATUS kuhl_m_pac_signature(PPACTYPE pacType, DWORD pacLenght,
                              LONG SignatureType, LPCVOID key, DWORD keySize);
PKERB_VALIDATION_INFO kuhl_m_pac_infoToValidationInfo(
    PFILETIME authtime, LPCWSTR username, LPCWSTR domainname,
    LPCWSTR LogonDomainName, PISID sid, ULONG rid, PGROUP_MEMBERSHIP groups,
    DWORD cbGroups, PKERB_SID_AND_ATTRIBUTES sids, DWORD cbSids);
BOOL kuhl_m_pac_stringToGroups(PCWSTR szGroups, PGROUP_MEMBERSHIP *groups,
                               DWORD *cbGroups);
BOOL kuhl_m_pac_stringToSids(PCWSTR szSids, PKERB_SID_AND_ATTRIBUTES *sids,
                             DWORD *cbSids);
// ticket stuff
PBERVAL kuhl_m_kerberos_ticket_createAppEncTicketPart(
    PKIWI_KERBEROS_TICKET ticket, LPCVOID PacAuthData, DWORD PacAuthDataSize);
PBERVAL kuhl_m_kerberos_ticket_createAppKrbCred(PKIWI_KERBEROS_TICKET ticket,
                                                BOOL valueIsTicket);

#define KIWI_NEVERTIME(filetime) (*(PLONGLONG)filetime = MAXLONGLONG)
#define USER_DONT_EXPIRE_PASSWORD (0x00000200)
#define USER_NORMAL_ACCOUNT (0x00000010)

#if defined(KERBEROS_TOOLS)
NTSTATUS kuhl_m_kerberos_pac_info(int argc, wchar_t *argv[]);
#endif
#define PACINFO_TYPE_LOGON_INFO 0x00000001
#define PACINFO_TYPE_CREDENTIALS_INFO 0x00000002
#define PACINFO_TYPE_CHECKSUM_SRV 0x00000006
#define PACINFO_TYPE_CHECKSUM_KDC 0x00000007
#define PACINFO_TYPE_CNAME_TINFO 0x0000000a
#define PACINFO_TYPE_DELEGATION_INFO 0x0000000b
#define PACINFO_TYPE_UPN_DNS 0x0000000c
#define PACINFO_TYPE_CLIENT_CLAIMS 0x0000000d
#define PACINFO_TYPE_DEVICE_INFO 0x0000000e
#define PACINFO_TYPE_DEVICE_CLAIMS 0x0000000f

typedef void (*PGENERIC_RPC_DECODE)(IN handle_t pHandle, IN PVOID pObject);
typedef void (*PGENERIC_RPC_ENCODE)(IN handle_t pHandle, IN PVOID pObject);
typedef void (*PGENERIC_RPC_FREE)(IN handle_t pHandle, IN PVOID pObject);
typedef size_t (*PGENERIC_RPC_ALIGNSIZE)(IN handle_t pHandle, IN PVOID pObject);

typedef struct _KULL_M_RPC_FCNSTRUCT {
  PVOID addr;
  size_t size;
} KULL_M_RPC_FCNSTRUCT, *PKULL_M_RPC_FCNSTRUCT;
typedef struct _SECPKG_SUPPLEMENTAL_CRED {
  RPC_UNICODE_STRING PackageName;
  ULONG CredentialSize;
  PUCHAR Credentials;
} SECPKG_SUPPLEMENTAL_CRED, *PSECPKG_SUPPLEMENTAL_CRED;

typedef struct _PAC_CREDENTIAL_DATA {
  ULONG CredentialCount;
  SECPKG_SUPPLEMENTAL_CRED Credentials[ANYSIZE_ARRAY];
} PAC_CREDENTIAL_DATA, *PPAC_CREDENTIAL_DATA;
BOOL kull_m_rpc_Generic_Decode(PVOID data, DWORD size, PVOID pObject,
                               PGENERIC_RPC_DECODE fDecode);
void kull_m_rpc_Generic_Free(PVOID data, PGENERIC_RPC_FREE fFree);
BOOL kull_m_rpc_Generic_Encode(PVOID pObject, PVOID *data, DWORD *size,
                               PGENERIC_RPC_ENCODE fEncode,
                               PGENERIC_RPC_ALIGNSIZE fAlignSize);

#define kull_m_pac_EncodeValidationInformation(                                \
    /*PKERB_VALIDATION_INFO **/ pObject, /*PVOID **/ data, /*DWORD **/ size)   \
  kull_m_rpc_Generic_Encode(                                                   \
      pObject, data, size, (PGENERIC_RPC_ENCODE)PKERB_VALIDATION_INFO_Encode,  \
      (PGENERIC_RPC_ALIGNSIZE)PKERB_VALIDATION_INFO_AlignSize)
#define kull_m_pac_DecodeValidationInformation(                                \
    /*PVOID */ data, /*DWORD */ size, /*PKERB_VALIDATION_INFO **/ pObject)     \
  kull_m_rpc_Generic_Decode(data, size, pObject,                               \
                            (PGENERIC_RPC_DECODE)PKERB_VALIDATION_INFO_Decode)
#define kull_m_pac_FreeValidationInformation(                                  \
    /*PKERB_VALIDATION_INFO **/ pObject)                                       \
  kull_m_rpc_Generic_Free(pObject,                                             \
                          (PGENERIC_RPC_FREE)PKERB_VALIDATION_INFO_Free)
#define kull_m_rpc_DecodeClaimsSetMetaData(data, size, pObject)                \
  kull_m_rpc_Generic_Decode(data, size, pObject,                               \
                            (PGENERIC_RPC_DECODE)PCLAIMS_SET_METADATA_Decode)
#define kull_m_rpc_FreeClaimsSetMetaData(pObject)                              \
  kull_m_rpc_Generic_Free(pObject, (PGENERIC_RPC_FREE)PCLAIMS_SET_METADATA_Free)
#define kull_m_rpc_EncodeClaimsSetMetaData(pObject, data, size)                \
  kull_m_rpc_Generic_Encode(                                                   \
      pObject, data, size, (PGENERIC_RPC_ENCODE)PCLAIMS_SET_METADATA_Encode,   \
      (PGENERIC_RPC_ALIGNSIZE)PCLAIMS_SET_METADATA_AlignSize)
#define kull_m_rpc_EncodeClaimsSet(pObject, data, size)                        \
  kull_m_rpc_Generic_Encode(pObject, data, size,                               \
                            (PGENERIC_RPC_ENCODE)PCLAIMS_SET_Encode,           \
                            (PGENERIC_RPC_ALIGNSIZE)PCLAIMS_SET_AlignSize)
size_t PCLAIMS_SET_AlignSize(handle_t _MidlEsHandle, PCLAIMS_SET *_pType);
void PCLAIMS_SET_Encode(handle_t _MidlEsHandle, PCLAIMS_SET *_pType);
void PCLAIMS_SET_Decode(handle_t _MidlEsHandle, PCLAIMS_SET *_pType);
void PCLAIMS_SET_Free(handle_t _MidlEsHandle, PCLAIMS_SET *_pType);

size_t PCLAIMS_SET_METADATA_AlignSize(handle_t _MidlEsHandle,
                                      PCLAIMS_SET_METADATA *_pType);
void PCLAIMS_SET_METADATA_Encode(handle_t _MidlEsHandle,
                                 PCLAIMS_SET_METADATA *_pType);
void PCLAIMS_SET_METADATA_Decode(handle_t _MidlEsHandle,
                                 PCLAIMS_SET_METADATA *_pType);
void PCLAIMS_SET_METADATA_Free(handle_t _MidlEsHandle,
                               PCLAIMS_SET_METADATA *_pType);

// kerberos functions
//
NTSTATUS kuhl_m_kerberos_encrypt(ULONG eType, ULONG keyUsage, LPCVOID key,
                                 DWORD keySize, LPCVOID data, DWORD dataSize,
                                 LPVOID *output, DWORD *outputSize,
                                 BOOL encrypt);
