#include "common.h"
#include "stdio.h"

void __attribute__((weak, visibility("default"))) almond_shell() {
    printf("almond_shell: no implementation, aborting.\n");
    _exit(-1);
}

int __attribute__((weak, visibility("default"))) main(int argc, char **argv) {
    if (libafl_main != NULL) {
        libafl_main();
        return 0;
    }
    if (argc > 0) {
      printf("%s: no libafl_main defined, aborting.\n", argv[0]);
      return 1;
    }
    return 0;
}
