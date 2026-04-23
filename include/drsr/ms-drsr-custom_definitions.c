

#include <stdlib.h>

void *MIDL_user_allocate(size_t size) { return malloc(size); }

void MIDL_user_free(void *ptr) { free(ptr); }
