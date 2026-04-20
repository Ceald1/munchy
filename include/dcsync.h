// #include "info.h"
#ifndef DCSYNC_H
#define DCSYNC_H
#include "ms-drsr.h"
#include <common.h>
#include <windows.h>

typedef LONGLONG DSTIME;
typedef LONGLONG USN;
typedef ULONG ATTRTYP;
typedef void *DRS_HANDLE;

// typedef struct _NT4SID {
//   UCHAR Data[28];
// } NT4SID;
//
// typedef struct _DSNAME {
//   ULONG structLen;
//   ULONG SidLen;
//   GUID Guid;
//   NT4SID Sid;
//   ULONG NameLen;
//   WCHAR StringName[ANYSIZE_ARRAY];
// } DSNAME;
//
// typedef struct _USN_VECTOR {
//   USN usnHighObjUpdate;
//   USN usnReserved;
//   USN usnHighPropUpdate;
// } USN_VECTOR;
//
// typedef struct _UPTODATE_CURSOR_V1 {
//   UUID uuidDsa;
//   USN usnHighPropUpdate;
// } UPTODATE_CURSOR_V1;
//
// typedef struct _UPTODATE_VECTOR_V1_EXT {
//   DWORD dwVersion;
//   DWORD dwReserved1;
//   DWORD cNumCursors;
//   DWORD dwReserved2;
//   UPTODATE_CURSOR_V1 rgCursors[ANYSIZE_ARRAY];
// } UPTODATE_VECTOR_V1_EXT;
//
// typedef struct _OID_t {
//   unsigned int length;
//   BYTE *elements;
// } OID_t;
//
// typedef struct _PrefixTableEntry {
//   ULONG ndx;
//   OID_t prefix;
// } PrefixTableEntry;
//
// typedef struct _SCHEMA_PREFIX_TABLE {
//   DWORD PrefixCount;
//   PrefixTableEntry *pPrefixEntry;
// } SCHEMA_PREFIX_TABLE;
//
// typedef struct _PARTIAL_ATTR_VECTOR_V1_EXT {
//   DWORD dwVersion;
//   DWORD dwReserved1;
//   DWORD cAttrs;
//   ATTRTYP rgPartialAttr[ANYSIZE_ARRAY];
// } PARTIAL_ATTR_VECTOR_V1_EXT;
//
// typedef struct _ATTRVAL {
//   ULONG valLen;
//   UCHAR *pVal;
// } ATTRVAL;
//
// typedef struct _ATTRVALBLOCK {
//   ULONG valCount;
//   ATTRVAL *pAVal;
// } ATTRVALBLOCK;
//
// typedef struct _ATTR {
//   ATTRTYP attrTyp;
//   ATTRVALBLOCK AttrVal;
// } ATTR;
//
// typedef struct _ATTRBLOCK {
//   ULONG attrCount;
//   ATTR *pAttr;
// } ATTRBLOCK;
//
// typedef struct _ENTINF {
//   DSNAME *pName;
//   ULONG ulFlags;
//   ATTRBLOCK AttrBlock;
// } ENTINF;
//
// typedef struct _PROPERTY_META_DATA_EXT {
//   DWORD dwVersion;
//   DSTIME timeChanged;
//   UUID uuidDsaOriginating;
//   USN usnOriginating;
// } PROPERTY_META_DATA_EXT;
//
// typedef struct _PROPERTY_META_DATA_EXT_VECTOR {
//   DWORD cNumProps;
//   PROPERTY_META_DATA_EXT rgMetaData[ANYSIZE_ARRAY];
// } PROPERTY_META_DATA_EXT_VECTOR;
//
// typedef struct _REPLENTINFLIST {
//   struct _REPLENTINFLIST *pNextEntInf;
//   ENTINF Entinf;
//   BOOL fIsNCPrefix;
//   UUID *pParentGuid;
//   PROPERTY_META_DATA_EXT_VECTOR *pMetaDataExt;
// } REPLENTINFLIST;
//
// typedef struct _UPTODATE_CURSOR_V2 {
//   UUID uuidDsa;
//   USN usnHighPropUpdate;
//   DSTIME timeLastSyncSuccess;
// } UPTODATE_CURSOR_V2;
//
// typedef struct _UPTODATE_VECTOR_V2_EXT {
//   DWORD dwVersion;
//   DWORD dwReserved1;
//   DWORD cNumCursors;
//   DWORD dwReserved2;
//   UPTODATE_CURSOR_V2 rgCursors[ANYSIZE_ARRAY];
// } UPTODATE_VECTOR_V2_EXT;

// typedef struct _VALUE_META_DATA_EXT_V1 {
//   DSTIME timeCreated;
//   PROPERTY_META_DATA_EXT MetaData;
// } VALUE_META_DATA_EXT_V1;
//
// typedef struct _REPLVALINF_V1 {
//   DSNAME *pObject;
//   ATTRTYP attrTyp;
//   ATTRVAL Aval;
//   BOOL fIsPresent;
//   VALUE_META_DATA_EXT_V1 MetaData;
// } REPLVALINF_V1;
//
// typedef struct _REPLTIMES {
//   UCHAR rgTimes[84];
// } REPLTIMES;
//
// typedef struct _DS_NAME_RESULT_ITEMW {
//   DWORD status;
//   WCHAR *pDomain;
//   WCHAR *pName;
// } DS_NAME_RESULT_ITEMW, *PDS_NAME_RESULT_ITEMW;
//
// typedef struct _DS_NAME_RESULTW {
//   DWORD cItems;
//   PDS_NAME_RESULT_ITEMW rItems;
// } DS_NAME_RESULTW, *PDS_NAME_RESULTW;
//
// typedef struct _DS_DOMAIN_CONTROLLER_INFO_2W {
//   WCHAR *NetbiosName;
//   WCHAR *DnsHostName;
//   WCHAR *SiteName;
//   WCHAR *SiteObjectName;
//   WCHAR *ComputerObjectName;
//   WCHAR *ServerObjectName;
//   WCHAR *NtdsDsaObjectName;
//   BOOL fIsPdc;
//   BOOL fDsEnabled;
//   BOOL fIsGc;
//   GUID SiteObjectGuid;
//   GUID ComputerObjectGuid;
//   GUID ServerObjectGuid;
//   GUID NtdsDsaObjectGuid;
// } DS_DOMAIN_CONTROLLER_INFO_2W;
//
// typedef struct _ENTINFLIST {
//   struct _ENTINFLIST *pNextEntInf;
//   ENTINF Entinf;
// } ENTINFLIST;
//
// typedef struct _DRS_EXTENSIONS {
//   DWORD cb;
//   BYTE rgb[ANYSIZE_ARRAY];
// } DRS_EXTENSIONS;
//
// typedef struct _DRS_MSG_GETCHGREPLY_V6 {
//   UUID uuidDsaObjSrc;
//   UUID uuidInvocIdSrc;
//   DSNAME *pNC;
//   USN_VECTOR usnvecFrom;
//   USN_VECTOR usnvecTo;
//   UPTODATE_VECTOR_V2_EXT *pUpToDateVecSrc;
//   SCHEMA_PREFIX_TABLE PrefixTableSrc;
//   ULONG ulExtendedRet;
//   ULONG cNumObjects;
//   ULONG cNumBytes;
//   REPLENTINFLIST *pObjects;
//   BOOL fMoreData;
//   ULONG cNumNcSizeObjects;
//   ULONG cNumNcSizeValues;
//   DWORD cNumValues;
//   REPLVALINF_V1 *rgValues;
//   DWORD dwDRSError;
// } DRS_MSG_GETCHGREPLY_V6;
//
// typedef union _DRS_MSG_GETCHGREPLY {
//   DRS_MSG_GETCHGREPLY_V6 V6;
// } DRS_MSG_GETCHGREPLY;
//
// typedef struct _DRS_MSG_GETCHGREQ_V8 {
//   UUID uuidDsaObjDest;
//   UUID uuidInvocIdSrc;
//   DSNAME *pNC;
//   USN_VECTOR usnvecFrom;
//   UPTODATE_VECTOR_V1_EXT *pUpToDateVecDest;
//   ULONG ulFlags;
//   ULONG cMaxObjects;
//   ULONG cMaxBytes;
//   ULONG ulExtendedOp;
//   ULARGE_INTEGER liFsmoInfo;
//   PARTIAL_ATTR_VECTOR_V1_EXT *pPartialAttrSet;
//   PARTIAL_ATTR_VECTOR_V1_EXT *pPartialAttrSetEx;
//   SCHEMA_PREFIX_TABLE PrefixTableDest;
// } DRS_MSG_GETCHGREQ_V8;
// typedef union _DRS_MSG_GETCHGREQ {
//   DRS_MSG_GETCHGREQ_V8 V8;
// } DRS_MSG_GETCHGREQ;
//
// typedef struct _DRS_MSG_DCINFOREQ_V1 {
//   WCHAR *Domain;
//   DWORD InfoLevel;
// } DRS_MSG_DCINFOREQ_V1;
//
// typedef union _DRS_MSG_DCINFOREQ {
//   DRS_MSG_DCINFOREQ_V1 V1;
// } DRS_MSG_DCINFOREQ, *PDRS_MSG_DCINFOREQ;
//
// typedef struct _DRS_MSG_DCINFOREPLY_V2 {
//   DWORD cItems;
//   DS_DOMAIN_CONTROLLER_INFO_2W *rItems;
// } DRS_MSG_DCINFOREPLY_V2;
//
// typedef union _DRS_MSG_DCINFOREPLY {
//   DRS_MSG_DCINFOREPLY_V2 V2;
// } DRS_MSG_DCINFOREPLY;

typedef struct _ms2Ddrsr_MIDL_TYPE_FORMAT_STRING {
  SHORT Pad;
  UCHAR Format[1757];
} ms2Ddrsr_MIDL_TYPE_FORMAT_STRING;

typedef struct _ms2Ddrsr_MIDL_PROC_FORMAT_STRING {
  SHORT Pad;
  UCHAR Format[853];
} ms2Ddrsr_MIDL_PROC_FORMAT_STRING;

ULONG IDL_DRSGetNCChanges(DRS_HANDLE hDrs, DWORD dwInVersion,
                          DRS_MSG_GETCHGREQ *pmsgIn, DWORD *pdwOutVersion,
                          DRS_MSG_GETCHGREPLY *pmsgOut);

typedef PVOID LSA_HANDLE, *PLSA_HANDLE;
typedef enum _POLICY_INFORMATION_CLASS {
  PolicyAuditLogInformation = 1,
  PolicyAuditEventsInformation,
  PolicyPrimaryDomainInformation,
  PolicyPdAccountInformation,
  PolicyAccountDomainInformation,
  PolicyLsaServerRoleInformation,
  PolicyReplicaSourceInformation,
  PolicyDefaultQuotaInformation,
  PolicyModificationInformation,
  PolicyAuditFullSetInformation,
  PolicyAuditFullQueryInformation,
  PolicyDnsDomainInformation,
  PolicyDnsDomainInformationInt,
  PolicyLocalAccountDomainInformation,
  PolicyMachineAccountInformation,
  PolicyMachineAccountInformation2,
  PolicyLastEntry
} POLICY_INFORMATION_CLASS,
    *PPOLICY_INFORMATION_CLASS;

typedef UNICODE_STRING LSA_UNICODE_STRING, *PLSA_UNICODE_STRING;
typedef struct _POLICY_DNS_DOMAIN_INFO {
  LSA_UNICODE_STRING Name;
  LSA_UNICODE_STRING DnsDomainName;
  LSA_UNICODE_STRING DnsForestName;
  GUID DomainGuid;
  PSID Sid;
} POLICY_DNS_DOMAIN_INFO, *PPOLICY_DNS_DOMAIN_INFO;

typedef NTSTATUS(WINAPI *LsaQueryInformationPolicy_t)(
    _In_ LSA_HANDLE PolicyHandle,
    _In_ POLICY_INFORMATION_CLASS InformationClass, _Out_ PVOID *Buffer);

typedef NTSTATUS(WINAPI *LsaOpenPolicy_t)(
    _In_opt_ PLSA_UNICODE_STRING SystemName,
    _In_ PLSA_OBJECT_ATTRIBUTES ObjectAttributes,
    _In_ ACCESS_MASK DesiredAccess, _Out_ PLSA_HANDLE PolicyHandle);

typedef struct _DOMAIN_CONTROLLER_INFOA {
  LPSTR DomainControllerName;
  LPSTR DomainControllerAddress;
  ULONG DomainControllerAddressType;
  GUID DomainGuid;
  LPSTR DomainName;
  LPSTR DnsForestName;
  ULONG Flags;
  LPSTR DcSiteName;
  LPSTR ClientSiteName;
} DOMAIN_CONTROLLER_INFOA, *PDOMAIN_CONTROLLER_INFOA;
typedef DWORD(WINAPI *DsGetDcNameA_t)(
    LPCSTR ComputerName, LPCSTR DomainName, GUID *DomainGuid, LPCSTR SiteName,
    ULONG Flags, PDOMAIN_CONTROLLER_INFOA *DomainControllerInfo);
typedef struct _DOMAIN_CONTROLLER_INFOW {
  LPWSTR DomainControllerName;
  LPWSTR DomainControllerAddress;
  ULONG DomainControllerAddressType;
  GUID DomainGuid;
  LPWSTR DomainName;
  LPWSTR DnsForestName;
  ULONG Flags;
  LPWSTR DcSiteName;
  LPWSTR ClientSiteName;
} DOMAIN_CONTROLLER_INFOW, *PDOMAIN_CONTROLLER_INFOW;

typedef struct _DRS_EXTENSIONS_INT {
  DWORD cb;
  DWORD dwFlags;
  GUID SiteObjGuid;
  DWORD Pid;
  DWORD dwReplEpoch;
  DWORD dwFlagsExt;
  GUID ConfigObjGUID;
  DWORD dwExtCaps;
} DRS_EXTENSIONS_INT, *PDRS_EXTENSIONS_INT;

typedef SecHandle CtxtHandle;
typedef PSecHandle PCtxtHandle;
typedef struct _SecPkgContext_SessionKey {
  unsigned long SessionKeyLength;
  unsigned char *SessionKey;
} SecPkgContext_SessionKey, *PSecPkgContext_SessionKey;

typedef DWORD(WINAPI *DsGetDcNameW_t)(
    LPCWSTR ComputerName, LPCWSTR DomainName, GUID *DomainGuid,
    LPCWSTR SiteName, ULONG Flags,
    PDOMAIN_CONTROLLER_INFOW *DomainControllerInfo);

typedef VOID(WINAPI *RtlGetNtVersionNumbers_t)(_Out_opt_ PULONG NtMajorVersion,
                                               _Out_opt_ PULONG NtMinorVersion,
                                               _Out_opt_ PULONG NtBuildNumber);

typedef SECURITY_STATUS(WINAPI *QueryContextAttributes_t)(
    _In_ PCtxtHandle phContext, _In_ ULONG ulAttribute, _Out_ PVOID pBuffer);
// constants
//
#define POLICY_VIEW_LOCAL_INFORMATION 0x00000001L
#define DS_DIRECTORY_SERVICE_REQUIRED 0x00000010
#define DS_IS_DNS_NAME 0x00020000
#define DS_RETURN_DNS_NAME 0x40000000
#define DS_RETURN_FLAT_NAME 0x80000000
#define DOMAIN_CONTROLLER_INFO DOMAIN_CONTROLLER_INFOA
#define PDOMAIN_CONTROLLER_INFO PDOMAIN_CONTROLLER_INFOA
#define DRS_EXT_GETCHGREPLY_V6 0x04000000
#define DRS_EXT_STRONG_ENCRYPTION 0x00008000
#define SECPKG_ATTR_SESSION_KEY 9
#define DRS_EXT_GETCHGREQ_V8 0x01000000
// exports
//
PPOLICY_DNS_DOMAIN_INFO GetCurrentDomain();
LPWSTR getDC(LPCWSTR fullDomainName);
void dcsync();

#endif
