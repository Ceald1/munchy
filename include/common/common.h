#pragma once
#define SECURITY_WIN32
#ifndef COMMON_H
#define COMMON_H
#include <windows.h>

#include <sspi.h>

#include <winternl.h>
/**
 * The UNICODE_STRING structure defines a counted string used for Unicode
 * strings.
 *
 * \sa
 * https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_unicode_string
 */
// typedef struct _UNICODE_STRING {
//   USHORT Length;
//   USHORT MaximumLength;
//   _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
// } UNICODE_STRING, *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

#ifndef _OBJECT_ATTRIBUTES_DEFINED
#define _OBJECT_ATTRIBUTES_DEFINED
// typedef struct _OBJECT_ATTRIBUTES {
//   ULONG Length;
//   HANDLE RootDirectory;
//   PUNICODE_STRING ObjectName;
//   ULONG Attributes;
//   PVOID SecurityDescriptor;
//   PVOID SecurityQualityOfService;
// } OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
#endif

// typedef struct _SecHandle {
//   ULONG_PTR dwLower;
//   ULONG_PTR dwUpper;
// } SecHandle, *PSecHandle;
typedef OBJECT_ATTRIBUTES LSA_OBJECT_ATTRIBUTES, *PLSA_OBJECT_ATTRIBUTES;
#endif
