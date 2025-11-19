#!/usr/bin/env bash

set -eux
set -o pipefail

_ROOT_DIR=${ROOT_DIR:?}
_BUILD_DIR=${BUILD_DIR:?}
_GEN_INC_DIR=${GEN_INC_DIR:?}
LIB_INC_DIR=${_ROOT_DIR}/src/libbpfilter/include

HEADERS=$(find ${LIB_INC_DIR} -type f -name "*.h" -exec realpath --relative-to ${LIB_INC_DIR} {} \;)

# Start with version.h as it's not in the source folder
INCLUDES="#include <bpfilter/version.h>"

for header in $(find ${LIB_INC_DIR} -type f -name "*.h" -exec realpath --relative-to ${LIB_INC_DIR} {} \; | sort); do
    INCLUDES="${INCLUDES}\n#include <${header}>"
done

SRC="${INCLUDES}\nint main(void) { return 0; }"

echo -e ${SRC} | gcc -x c -I"${LIB_INC_DIR}" -I"${_GEN_INC_DIR}" -pedantic-errors -std=c17 -Werror -Wall -Wextra -c -o /dev/null -