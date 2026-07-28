#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <link.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>

void fuzz_target(const char *lib_path) {
    void *handle = dlopen(lib_path, RTLD_LAZY | RTLD_GLOBAL);
    if (!handle) {
        printf("FailMode: LoadError\n");
        exit(0);
    }

    // Actively exercise the input domain by extracting and probing the link map
    struct link_map *map = NULL;
    if (dlinfo(handle, RTLD_DI_LINKMAP, &map) == 0 && map != NULL) {
        // Safely probe the base load address and dynamic segments
        volatile unsigned char *base = (volatile unsigned char *)map->l_addr;
        if (base) {
            // Read headers to trigger structural validation within the runtime linker context
            volatile unsigned char val = *base;
            (void)val;
        }
    }

    // Attempt to resolve common baseline symbols to force symbol table parsing
    (void)dlsym(handle, "init");
    (void)dlsym(handle, "_init");
    (void)dlsym(handle, "fini");
    (void)dlsym(handle, "_fini");

    dlclose(handle);
    exit(0);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <library_path>\n", argv[0]);
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 2;
    }

    if (pid == 0) {
        fuzz_target(argv[1]);
    } else {
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            int exit_code = WEXITSTATUS(status);
            if (exit_code != 0) {
                // Child handled reporting
            } else {
                printf("FailMode: None\n");
            }
        } else if (WIFSIGNALED(status)) {
            int sig = WTERMSIG(status);
            if (sig == SIGSEGV) {
                printf("FailMode: SegmentationFault\n");
            } else if (sig == SIGABRT) {
                printf("FailMode: AbortSignal\n");
            } else {
                printf("FailMode: Signal_%d\n", sig);
            }
        }
    }
    return 0;
}