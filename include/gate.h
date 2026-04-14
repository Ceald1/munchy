#include <windows.h>

// typedef struct _PS_ATTRIBUTE {
//   ULONG Attribute;
//   SIZE_T Size;
//   union {
//     ULONG Value;
//     PVOID ValuePtr;
//   } u1;
//   PSIZE_T ReturnLength;
// } PS_ATTRIBUTE, *PPS_ATTRIBUTE;
//
// typedef struct _UNICODE_STRING {
//   USHORT Length;
//   USHORT MaximumLength;
//   PWSTR Buffer;
// } UNICODE_STRING, *PUNICODE_STRING;
//
// typedef struct _OBJECT_ATTRIBUTES {
//   ULONG Length;
//   HANDLE RootDirectory;
//   PUNICODE_STRING ObjectName;
//   ULONG Attributes;
//   PVOID SecurityDescriptor;
//   PVOID SecurityQualityOfService;
// } OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
//
// typedef struct _CLIENT_ID {
//   HANDLE UniqueProcess;
//   HANDLE UniqueThread;
// } CLIENT_ID, *PCLIENT_ID;
//
// typedef struct _PS_ATTRIBUTE_LIST {
//   SIZE_T TotalLength;
//   PS_ATTRIBUTE Attributes[1];
// } PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;
//
// typedef NTSTATUS(WINAPI *NtOpenProcess_t)(PHANDLE ProcessHandle,
//                                           ACCESS_MASK DesiredAccess,
//                                           POBJECT_ATTRIBUTES
//                                           ObjectAttributes, PCLIENT_ID
//                                           ClientId);
//
// typedef NTSTATUS(WINAPI *NtAllocateVirtualMemory)(
//     HANDLE ProcessHandle, PVOID *BaseAddress, ULONG ZeroBits,
//     PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
//
// typedef NTSTATUS(WINAPI *NtProtectVirtualMemory)(_In_ HANDLE ProcessHandle,
//                                                  _Inout_ PVOID *BaseAddress,
//                                                  _Inout_ PSIZE_T RegionSize,
//                                                  _In_ ULONG NewProtect,
//                                                  _Out_ PULONG OldProtect);
//
// typedef NTSTATUS(WINAPI *NtWriteVirtualMemory)(
//     IN HANDLE ProcessHandle, IN PVOID BaseAddress, IN PVOID Buffer,
//     IN SIZE_T NumberOfBytesToWrite, OUT PSIZE_T NumberOfBytesWritten
//     OPTIONAL);
//
// typedef NTSTATUS(WINAPI *NtCreateThreadEx)(
//     OUT PHANDLE ThreadHandle, IN ACCESS_MASK DesiredAccess,
//     IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN HANDLE ProcessHandle,
//     IN PVOID StartRoutine, IN PVOID Argument OPTIONAL, IN ULONG CreateFlags,
//     IN SIZE_T ZeroBits, IN SIZE_T StackSize, IN SIZE_T MaximumStackSize,
//     IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL);
//
// typedef NTSTATUS(WINAPI *NtWaitForSingleObject)(
//     _In_ HANDLE Handle, _In_ BOOLEAN Alertable,
//     _In_opt_ PLARGE_INTEGER Timeout);
//
// typedef NTSTATUS(WINAPI *NtFreeVirtualMemory)(_In_ HANDLE ProcessHandle,
//                                               _Inout_ PVOID *BaseAddress,
//                                               _Inout_ PSIZE_T RegionSize,
//                                               _In_ ULONG FreeType);
//
// typedef NTSTATUS(WINAPI *NtClose)(IN HANDLE Handle);
