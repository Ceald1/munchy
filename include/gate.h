#include <windows.h>

size_t get_mod_base(const char *module_name);

const void *get_function_from_exports(size_t dll_base_addr, const char *needle);
