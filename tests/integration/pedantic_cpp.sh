#!/usr/bin/env bash

set -eux
set -o pipefail

_BUILD_DIR=${BUILD_DIR:?}
_GEN_INC_DIR=${GEN_INC_DIR:?}
_LIB_INC_DIR=${LIB_INC_DIR:?}

# If GEN_INC_DIR points to a file, use its parent directory
if [ -f "${_GEN_INC_DIR}" ]; then
    _GEN_INC_DIR=$(dirname $(dirname "${_GEN_INC_DIR}"))
fi

HEADERS=$(find ${_LIB_INC_DIR} -type f -name "*.h" -exec realpath --relative-to ${_LIB_INC_DIR} {} \;)

# Start with version.h as it's not in the source folder
INCLUDES="extern \"C\" {\n#include <bpfilter/version.h>"

for header in $(find ${_LIB_INC_DIR} -type f -name "*.h" -exec realpath --relative-to ${_LIB_INC_DIR} {} \; | sort); do
    INCLUDES="${INCLUDES}\n#include <${header}>"
done

SRC="${INCLUDES}\n}\nint main(void) { return 0; }"

echo -e ${SRC} | gcc -x c++ -I"${_LIB_INC_DIR}" -I"${_GEN_INC_DIR}" -pedantic-errors -std=c++17 -Werror -Wall -Wextra -c -o /dev/null -
