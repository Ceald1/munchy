#pragma once

#include <windows.h>

typedef VOID(WINAPI *RtlGetNtVersionNumbers_t)(_Out_opt_ PULONG NtMajorVersion,
                                               _Out_opt_ PULONG NtMinorVersion,
                                               _Out_opt_ PULONG NtBuildNumber);

void DCSync();
