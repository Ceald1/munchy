#include <windows.h>

typedef NTSTATUS(WINAPI *RtlAdjustPrivilege_t)(ULONG Privilege, BOOLEAN Enable,
                                               BOOLEAN Client,
                                               PBOOLEAN WasEnabled);
