// The original C++/CLI code uses .NET assembly attributes and namespaces which
// have no direct equivalent in C. C does not support attributes or namespaces
// like .NET assemblies. The following C code includes the version header and
// defines string constants similar to the macros used in the original code.

#include "version.h"

// Define string constants for version information
const char *AssemblyTitle = VER_FILE_DESCRIPTION_STR;
const char *AssemblyVersion = VER_PRODUCT_VERSION_STR;
const char *AssemblyProduct = VER_PRODUCT_NAME_STR;
const char *AssemblyCopyright = VER_COPYRIGHT_STR;
const char *AssemblyDescription = VER_FILE_DESCRIPTION_STR;
const char *AssemblyConfiguration = "";
const char *AssemblyCompany = VER_COMPANY_STR;
const char *AssemblyTrademark = "";
const char *AssemblyCulture = "";

// Note: Attributes like ComVisible and CLSCompliant do not apply in C.
