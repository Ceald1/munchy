#include "lsa.h"
#include "gate.h"

#include "base64.h"
#include "info.h"
#include <errhandlingapi.h>
#include <libloaderapi.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>

map_entry EncryptionTypeTable[] = {
    {L"aes256", KERB_ETYPE_AES256_CTS_HMAC_SHA1_96},
    {L"aes128", KERB_ETYPE_AES128_CTS_HMAC_SHA1_96},
    {L"des", KERB_ETYPE_DES3_CBC_MD5},
    {L"rc4", KERB_ETYPE_RC4_HMAC_NT},
    {L"default", KERB_ETYPE_DEFAULT},
};
map_entry CacheOptions[] = {
    {L"cred", KERB_RETRIEVE_TICKET_AS_KERB_CRED},
    {L"cache_only", KERB_RETRIEVE_TICKET_USE_CREDHANDLE},
    {L"default", KERB_RETRIEVE_TICKET_DEFAULT},
};

HANDLE NewLsaCredentialHandle() {
  HMODULE secure32 = LoadLibraryA("secur32.dll");

  LsaConnectUntrusted_t LsaConnectUntrusted =
      (LsaConnectUntrusted_t)GetProcAddress(secure32, "LsaConnectUntrusted");
  HANDLE CredHandle;
  NTSTATUS status = LsaConnectUntrusted(&CredHandle);
  if (status != 0) {
    printf("0x%lX\n", status);
  }
  return CredHandle;
}

void InitLsaString(PLSA_STRING LsaStr, const char *str) {
  USHORT len = (USHORT)strlen(str);
  LsaStr->Buffer = (PCHAR)str;
  LsaStr->Length = len;
  LsaStr->MaximumLength = len + 1; // include null terminator
}

ULONG GetAuthPackage(HANDLE lsaHandle, char *PackageName) {
  LSA_STRING PackageNameStr;
  HMODULE secure32 = LoadLibraryA("secur32.dll");
  LsaLookupAuthenticationPackage_t LsaLookupAuthenticationPackage =
      (LsaLookupAuthenticationPackage_t)GetProcAddress(
          secure32, "LsaLookupAuthenticationPackage");
  InitLsaString(&PackageNameStr, PackageName);
  ULONG PackageNum;
  NTSTATUS status =
      LsaLookupAuthenticationPackage(lsaHandle, &PackageNameStr, &PackageNum);
  if (status != 0) {
    printf("0x%lX\n", status);
  }

  return PackageNum;
}

int LookupTableType(LPCWSTR input, map_entry table[]) {
  int defaultValue;
  for (int i = 0; i < sizeof(table) / sizeof(map_entry); i++) {
    if (_wcsicmp(L"default", table[i].name) == 0) {
      defaultValue = table[i].value;
    }
    if (_wcsicmp(input, table[i].name) == 0) {
      return table[i].value;
    }
  }
  return defaultValue;
}

// Requests a TGS NOT TGT.
NTSTATUS
Kerberos_ask(PCWCHAR targetName, char *filename, LPCWSTR EncryptionType,
             LPCWSTR CacheOption, void *credHandle) {
  wprintf(L"Requesting ticket for: %s\n", targetName);
  NTSTATUS status;
  size_t ntdll = get_mod_base("ntdll.dll");
  RtlCopyMemory_t RtlCopyMemory =
      (RtlCopyMemory_t)get_function_from_exports(ntdll, "RtlCopyMemory");
  HMODULE secure32 = LoadLibraryA("secur32.dll");
  LsaCallAuthenticationPackage_t LsaCallAuthenticationPackage =
      (LsaCallAuthenticationPackage_t)GetProcAddress(
          secure32, "LsaCallAuthenticationPackage");

  PKERB_RETRIEVE_TKT_REQUEST pKerbRetrieveReq;
  PKERB_RETRIEVE_TKT_RESPONSE pKerbRetrieveResp = NULL;
  ULONG szResponse = 0;
  USHORT dwTarget = (USHORT)((wcslen(targetName) + 1) * sizeof(wchar_t));
  DWORD szRequest = sizeof(KERB_RETRIEVE_TKT_REQUEST) + dwTarget;

  DWORD szData;
  // USHORT dwTarget;
  OssBuf buf = {0, NULL};
  dwTarget = (USHORT)((wcslen(targetName) + 1) * sizeof(wchar_t));

  szData = sizeof(KERB_RETRIEVE_TKT_REQUEST) + dwTarget;
  pKerbRetrieveReq = (PKERB_RETRIEVE_TKT_REQUEST)LocalAlloc(LPTR, szRequest);

  pKerbRetrieveReq->MessageType = KerbRetrieveEncodedTicketMessage;
  pKerbRetrieveReq->CacheOptions = KERB_RETRIEVE_TICKET_AS_KERB_CRED |
                                   LookupTableType(CacheOption, CacheOptions);
  if (LookupTableType(CacheOption, CacheOptions) ==
      KERB_RETRIEVE_TICKET_USE_CREDHANDLE) {

    pKerbRetrieveReq->CredentialsHandle = *(SecHandle *)credHandle;
  }

  pKerbRetrieveReq->EncryptionType = LookupTableType(
      EncryptionType,
      EncryptionTypeTable); // LookupEncryptionType(EncryptionType);
  pKerbRetrieveReq->TargetName.Length = dwTarget - sizeof(wchar_t);
  pKerbRetrieveReq->TargetName.MaximumLength = dwTarget;
  pKerbRetrieveReq->TargetName.Buffer =
      (PWSTR)((PBYTE)pKerbRetrieveReq + sizeof(KERB_RETRIEVE_TKT_REQUEST));
  RtlCopyMemory(pKerbRetrieveReq->TargetName.Buffer, targetName,
                pKerbRetrieveReq->TargetName.MaximumLength);

  HANDLE LsaHandle = NewLsaCredentialHandle();
  ULONG AuthPackageNum = GetAuthPackage(LsaHandle, "Kerberos");
  NTSTATUS protocolStatus;
  status = LsaCallAuthenticationPackage(
      LsaHandle, AuthPackageNum, pKerbRetrieveReq, szRequest,
      (PVOID *)&pKerbRetrieveResp, &szResponse, &protocolStatus);
  if (status != 0) {
    return status;
  }

  status = protocolStatus;
  if (status != 0) {
    return status;
  }
  buf.length = pKerbRetrieveResp->Ticket.EncodedTicketSize;
  buf.value = pKerbRetrieveResp->Ticket.EncodedTicket;
  printf("%s\n",
         base64_encode(pKerbRetrieveResp->Ticket.EncodedTicket, buf.length));
  HANDLE hfile;
  DWORD bytesWritten;
  hfile = CreateFile(filename, GENERIC_ALL, 0, NULL, CREATE_ALWAYS,
                     FILE_ATTRIBUTE_NORMAL, NULL);
  if (hfile == INVALID_HANDLE_VALUE) {
    return GetLastError();
  }
  BOOL result = WriteFile(hfile, buf.value, buf.length, &bytesWritten, NULL);
  if (!result) {
    return GetLastError();
  }
  CloseHandle(hfile);

  return status;
}
