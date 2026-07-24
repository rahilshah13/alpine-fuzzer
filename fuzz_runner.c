#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>

void fuzz_target(const char *lib_path) {
    void *handle = dlopen(lib_path, RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "FailLoad: %s\n", dlerror());
        exit(10);
    }

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
            if (exit_code == 10) {
                printf("FailMode: LoadError\n");
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
