
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winnt.h>

#include "gate.h"

size_t get_mod_base(const char *module_name) {
  uintptr_t peb = 0;
  uintptr_t ldr = 0;
  uintptr_t in_memory_order_module_list = 0;

  // Inline assembly to get PEB and module list
  __asm__ __volatile__("mov %%gs:0x60, %0\n\t" // get PEB
                       "mov 0x18(%0), %1\n\t"  // PEB->Ldr
                       "mov 0x10(%1), %2\n\t"  // InMemoryOrderModuleList
                       : "=r"(peb), "=r"(ldr), "=r"(in_memory_order_module_list)
                       :
                       : "memory");

  // printf("[+] Found the PEB and the InMemoryOrderModuleList at: %p\n",
  //        (void *)in_memory_order_module_list);
  // printf("[i] Iterating through modules loaded into the process, searching
  // for "
  //        "%s\n",
  //        module_name);

  uintptr_t head = in_memory_order_module_list;
  uintptr_t current_entry = head;

  do {
    uintptr_t dll_base = *(uintptr_t *)((char *)current_entry + 0x30);
    uintptr_t module_name_address =
        *(uintptr_t *)((char *)current_entry + 0x60);
    uint16_t module_length = *(uint16_t *)((char *)current_entry + 0x58);

    if (module_name_address != 0 && module_length > 0) {
      wchar_t *dll_name_w = (wchar_t *)module_name_address;
      size_t dll_name_len = module_length / 2; // number of wchar_t characters

      // Allocate buffer for converted ANSI string
      char *dll_name = malloc(dll_name_len * 4 + 1); // safe for multibyte
      if (!dll_name) {
        fprintf(stderr, "Memory allocation failed.\n");
        return 0;
      }

      // Convert wide string to ANSI
      WideCharToMultiByte(CP_ACP, 0, dll_name_w, (int)dll_name_len, dll_name,
                          (int)(dll_name_len * 4 + 1), NULL, NULL);
      dll_name[dll_name_len] = '\0';

      // printf("[i] Found module: %s\n", dll_name);

      // Compare case-insensitive
      if (_stricmp(dll_name, module_name) == 0) {
        // printf("[+] %s base address found: %p\n", dll_name, (void
        // *)dll_base);
        free(dll_name);
        return dll_base;
      }

      free(dll_name);
    } else {
      printf("Invalid module name address or length.\n");
    }

    // Move to next module (Flink at offset 0x0)
    current_entry = *(uintptr_t *)current_entry;

    // Break if we looped back to the start
  } while (current_entry != head && current_entry != 0);

  printf("Looped back to the start or no module found.\n");
  return 0; // None in Rust
}

const void *get_function_from_exports(size_t dll_base_addr,
                                      const char *needle) {

  // size_t dll_base_addr = get_mod_base(dll_name);
  if (dll_base_addr == 0) {
    printf("critical error\n");
    return NULL;
  }
  uint8_t *dll_base = (uint8_t *)dll_base_addr;
  // Check DOS header
  IMAGE_DOS_HEADER *dos_header = (IMAGE_DOS_HEADER *)dll_base;
  if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
    fprintf(stderr, "DOS header not matched from base address: %p\n", dll_base);
    return NULL;
  }
  // printf("[+] DOS header matched\n");

  // Check NT headers
  IMAGE_NT_HEADERS64 *nt_headers =
      (IMAGE_NT_HEADERS64 *)(dll_base + dos_header->e_lfanew);
  if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
    fprintf(stderr, "NT headers do not match signature from dll base: %p\n",
            dll_base);
    return NULL;
  }
  // printf("[+] NT headers matched\n");

  // Get the export directory
  IMAGE_DATA_DIRECTORY export_data_dir =
      nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  if (export_data_dir.VirtualAddress == 0) {
    fprintf(stderr, "No export directory found\n");
    return NULL;
  }

  IMAGE_EXPORT_DIRECTORY *export_dir =
      (IMAGE_EXPORT_DIRECTORY *)(dll_base + export_data_dir.VirtualAddress);

  // Get the addresses of functions, names, and ordinals
  uint32_t *functions = (uint32_t *)(dll_base + export_dir->AddressOfFunctions);
  uint32_t *names = (uint32_t *)(dll_base + export_dir->AddressOfNames);
  uint16_t *ordinals =
      (uint16_t *)(dll_base + export_dir->AddressOfNameOrdinals);

  DWORD number_of_names = export_dir->NumberOfNames;

  for (DWORD i = 0; i < number_of_names; i++) {
    const char *function_name = (const char *)(dll_base + names[i]);

    if (strcmp(function_name, needle) == 0) {
      // printf("[+] Function name found: %s\n", needle);

      // Get function RVA and calculate actual address
      uint16_t ordinal = ordinals[i];
      uint32_t fn_rva = functions[ordinal];
      const void *fn_addr = (const void *)(dll_base + fn_rva);

      // printf("[i] Function address: %p\n", fn_addr);
      return fn_addr;
    }
  }

  return NULL; // function not found
}
