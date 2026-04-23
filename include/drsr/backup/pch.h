#pragma once

// Set macros BEFORE including windows.h
#define WIN32_LEAN_AND_MEAN
#define NOIME
#define NOSYSPARAMSINFO
#define NOWINABLE
#define NOKEYSTATES
#define NOGDI
#define NOUSER
#define NOSERVICE
#define NOHELP
#define NOMCX

#define SECURITY_WIN32
#include <windows.h>

#include <ntmsapi.h>
#include <rpc.h>
#include <sdkddkver.h>
#include <security.h>

// C++ libraries
#include <malloc.h>
#include <memory>
#include <msclr/marshal_cppstd.h>
#include <string>

// #pragma once
// #include <um/windows.h>
//// Inhibit definition of the indicated items:
// #define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
// #define NOIME               // Input Method Manager definitions
// #define NOSYSPARAMSINFO     // Parameters for SystemParametersInfo.
// #define NOWINABLE           // Active Accessibility hooks
// #define NOKEYSTATES         // MK_*
// #define NOGDI               // All GDI defines and routines
// #define NOUSER              // All USER defines and routines
// #define NOSERVICE // All Service Controller routines, SERVICE_ equates, etc.
// #define NOHELP    // Help engine interface.
// #define NOMCX     // Modem Configuration Extensions
//
// #define SECURITY_WIN32
//
//// Windows libraries
//
//// #include <ntdsapi.h>
// #include <security.h>
// #include <shared/rpc.h>
// #include <shared/sdkddkver.h>
//
// #include <NTMSAPI.h>
//// C++ libraries
// #include <malloc.h>
// #include <memory>
// #include <msclr\marshal_cppstd.h>
// #include <string>
