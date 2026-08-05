#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>

void fuzz_target(const char *lib_path) {
    // Timeout guard: prevent hanging if library constructors (.init) deadlock
    alarm(2);

    // Clear existing error state
    dlerror();

    // musl requires RTLD_NOW for immediate symbol resolution
    void *handle = dlopen(lib_path, RTLD_NOW | RTLD_GLOBAL);
    if (!handle) {
        char *err = dlerror();
        if (err) {
            // musl ldso string matching
            if (strstr(err, "symbol not found") || strstr(err, "Symbol not found") || strstr(err, "reloc")) {
                printf("FailMode: SymbolNotFound\n");
            } else if (strstr(err, "No such file") || strstr(err, "not found")) {
                printf("FailMode: LibraryNotFound\n");
            } else {
                printf("FailMode: LoadError\n");
            }
        } else {
            printf("FailMode: LoadError\n");
        }
        fflush(stdout);
        exit(1); // Non-zero exit signals child handled its own error reporting
    }

    // Successful load and clean teardown
    dlclose(handle);
    printf("FailMode: None\n");
    fflush(stdout);
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
            if (exit_code != 0 && exit_code != 1) {
                printf("FailMode: ExecutionFailed\n");
                fflush(stdout);
            }
        } else if (WIFSIGNALED(status)) {
            int sig = WTERMSIG(status);
            if (sig == SIGSEGV) {
                printf("FailMode: SegmentationFault\n");
            } else if (sig == SIGABRT) {
                printf("FailMode: AbortSignal\n");
            } else if (sig == SIGALRM) {
                printf("FailMode: Timeout\n");
            } else {
                printf("FailMode: Signal_%d\n", sig);
            }
            fflush(stdout);
        }
    }
    return 0;
}