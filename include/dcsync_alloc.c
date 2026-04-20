#include <rpc.h>
#include <windows.h>

void *__RPC_USER MIDL_user_allocate(SIZE_T len) {
  return HeapAlloc(GetProcessHeap(), 0, len);
}

void __RPC_USER MIDL_user_free(void *ptr) {
  HeapFree(GetProcessHeap(), 0, ptr);
}
