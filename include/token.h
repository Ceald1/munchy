#include <windows.h>

typedef NTSTATUS(WINAPI *RtlAdjustPrivilege_t)(ULONG Privilege, BOOLEAN Enable,
                                               BOOLEAN Client,
                                               PBOOLEAN WasEnabled);

// token duplication stuff
typedef NTSTATUS(WINAPI *NtOpenProcessToken_t)(_In_ HANDLE ProcessHandle,
                                               _In_ ACCESS_MASK DesiredAccess,
                                               _Out_ PHANDLE TokenHandle);
typedef NTSTATUS(WINAPI *NtDuplicateToken_t)(
    _In_ HANDLE ExistingTokenHandle, _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes, _In_ BOOLEAN EffectiveOnly,
    _In_ TOKEN_TYPE Type, _Out_ PHANDLE NewTokenHandle);
typedef NTSTATUS(WINAPI *NtSetInformationThread_t)(
    _In_ HANDLE ThreadHandle, _In_ THREADINFOCLASS ThreadInformationClass,
    _In_reads_bytes_(ThreadInformationLength) PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength);
typedef NTSTATUS(WINAPI *NtOpenProcessToken_t)(_In_ HANDLE ProcessHandle,
                                               _In_ ACCESS_MASK DesiredAccess,
                                               _Out_ PHANDLE TokenHandle);

#define NtCurrentThread() ((HANDLE)(LONG_PTR) - 2)

typedef NTSTATUS(WINAPI *NtQueryInformationThread_t)(
    _In_ HANDLE ThreadHandle, _In_ THREADINFOCLASS ThreadInformationClass,
    _Out_writes_bytes_(ThreadInformationLength) PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength, _Out_opt_ PULONG ReturnLength);

NTSTATUS privilege(ULONG priv);

typedef enum {
  DEBUG,
  IMPERSONATE,
  BACKUP,
  TCB,
  TAKEOWNERSHIP,
  LOADDRIVER,
  CREATETOKEN,
  SECURITY,
  RELABEL,
  UNKNOWN_COMMAND,
} Command;

Command TokenCommand(const char *str);
NTSTATUS EnablePrivilege(char *privilegeStr);
NTSTATUS ImpersonateSystem();
