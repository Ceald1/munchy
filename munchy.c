// #include <stdlib.h>

#include "./include/token.c"
#include <argtable3.h>
#include <wincrypt.h>
#include <windows.h>

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
struct command cmds[] = {
    {"token", cmd_token},

};

int main(int argc, char *argv[]) {

  if (argc < 2) {
    printf("usage: app <command>\n");
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
