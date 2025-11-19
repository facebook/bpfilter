#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#define _GNU_SOURCE
#include <dlfcn.h>
#include <unistd.h>

#include "mock.h"

int isatty(int fd)
{
    static int (*real)(int) = NULL;

    if (bft_mock_isatty_is_enabled()) {
        // Return 1 (true) to simulate being a TTY
        return 1;
    }

    if (!real) {
        real = dlsym(RTLD_NEXT, "isatty");
        if (!real) {
            (void)fprintf(stderr,
                          "failed to locate real function for isatty");
            exit(1);
        }
    }

    return real(fd);
}
