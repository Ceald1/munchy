#include <windows.h>

typedef NTSTATUS(WINAPI *RtlAdjustPrivilege_t)(ULONG Privilege, BOOLEAN Enable,
                                               BOOLEAN Client,
                                               PBOOLEAN WasEnabled);
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
