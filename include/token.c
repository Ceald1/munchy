#include "token.h"
// #include "gate.h"
#include "gate.h"
#include <stdbool.h>
#include <windows.h>

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
