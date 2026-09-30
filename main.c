#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <libgen.h>
#include <time.h>
#include <sys/wait.h>

static inline long long get_time_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000LL + (ts.tv_nsec / 1000);
}

void fuzz_target(const char *lib_path) {
    alarm(2);

    if (strstr(lib_path, "ld-musl") || strstr(lib_path, "libc.musl")) {
        printf("FailMode: SystemCoreLibrary\n");
        printf("ExecutionTimeUs: 0\n");
        fflush(stdout);
        exit(0);
    }

    char path_copy[1024];
    strncpy(path_copy, lib_path, sizeof(path_copy));
    char *dir = dirname(path_copy);
    
    char env_buf[2048];
    const char *old_ld = getenv("LD_LIBRARY_PATH");
    if (old_ld) {
        snprintf(env_buf, sizeof(env_buf), "%s:%s", dir, old_ld);
    } else {
        snprintf(env_buf, sizeof(env_buf), "%s", dir);
    }
    setenv("LD_LIBRARY_PATH", env_buf, 1);

    dlerror();

    void *handle = dlopen(lib_path, RTLD_NOW | RTLD_GLOBAL);
    if (!handle) {
        char *err = dlerror();
        if (err) {
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
        exit(1);
    }

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

    long long start_us = get_time_us();

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
        long long duration_us = get_time_us() - start_us;

        if (WIFEXITED(status)) {
            int exit_code = WEXITSTATUS(status);
            if (exit_code != 0 && exit_code != 1) {
                printf("FailMode: ExecutionFailed\n");
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
        }
        printf("ExecutionTimeUs: %lld\n", duration_us);
        fflush(stdout);
    }
    return 0;
}