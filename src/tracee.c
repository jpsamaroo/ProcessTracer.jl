#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/personality.h>

int main(int argc, char *argv[]) {
    int ret;
    /* Operation not permitted: Because of vfork()?
    if (ret = ptrace(PTRACE_TRACEME, 0, NULL, NULL)) {
        perror("PTRACE_TRACEME");
        return 1;
    }
    */
    personality(ADDR_NO_RANDOMIZE);
    raise(SIGSTOP);
    fprintf(stderr, "Program: %s\n", argv[0]);
    for (int i = 0; i < argc; i++) {
        fprintf(stderr, "Arg: %s\n", argv[i]);
    }
    execvp(argv[1], ((void *)argv)+sizeof(char *));
    return 0;
}
