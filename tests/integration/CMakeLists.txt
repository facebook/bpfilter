# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

include(ExternalProject)

#[[
set(BF_TOOLS_NFT_GIT_TAG v1.0.9)
set(BF_TOOLS_NFT_SOURCE_DIR ${CMAKE_BINARY_DIR}/tools/nftables)
set(BF_TOOLS_NFT_INSTALL_DIR ${CMAKE_BINARY_DIR}/tools/install)

ExternalProject_Add(nftables
    GIT_REPOSITORY https://git.netfilter.org/nftables
    GIT_TAG        ${BF_TOOLS_NFT_GIT_TAG}

    DEPENDS libbpfilter
    BUILD_IN_SOURCE true
    EXCLUDE_FROM_ALL true
    SOURCE_DIR  ${BF_TOOLS_NFT_SOURCE_DIR}
    INSTALL_DIR ${BF_TOOLS_NFT_INSTALL_DIR}

    PATCH_COMMAND git reset --hard ${BF_TOOLS_NFT_GIT_TAG}
        COMMAND git apply ${CMAKE_CURRENT_SOURCE_DIR}/nftables/0001-libnftables-add-support-for-bpfilter.patch
    CONFIGURE_COMMAND ./autogen.sh
        COMMAND
            ${CMAKE_COMMAND} -E env
                LDFLAGS=$<$<CONFIG:Debug>:-fsanitize=address\ -fsanitize=undefined>
                CFLAGS=$<$<CONFIG:Debug>:-fsanitize=address\ -fsanitize=undefined>
                BPFILTER_LIBS=-L${CMAKE_BINARY_DIR}/output/lib\ -lbpfilter\ -Wl,-rpath=${CMAKE_BINARY_DIR}/output/lib
                BPFILTER_CFLAGS=-I${CMAKE_BINARY_DIR}/output/include
                ./configure
                    --with-bpfilter
                    --disable-man-doc
                    --prefix=${BF_TOOLS_NFT_INSTALL_DIR}
)
]]

set(BF_TOOLS_IPT_GIT_TAG 8bf2bab8)
set(BF_TOOLS_IPT_SOURCE_DIR ${CMAKE_BINARY_DIR}/tools/iptables)
set(BF_TOOLS_IPT_INSTALL_DIR ${CMAKE_BINARY_DIR}/tools/install)

ExternalProject_Add(iptables
    GIT_REPOSITORY https://git.netfilter.org/iptables
    GIT_TAG        ${BF_TOOLS_IPT_GIT_TAG}

    DEPENDS libbpfilter
    BUILD_IN_SOURCE true
    EXCLUDE_FROM_ALL true
    SOURCE_DIR  ${BF_TOOLS_IPT_SOURCE_DIR}
    INSTALL_DIR ${BF_TOOLS_IPT_INSTALL_DIR}

    PATCH_COMMAND git reset --hard ${BF_TOOLS_IPT_GIT_TAG}
        COMMAND git apply ${CMAKE_CURRENT_SOURCE_DIR}/iptables/0001-iptables-add-support-for-bpfilter.patch
    CONFIGURE_COMMAND ./autogen.sh
        COMMAND
            ${CMAKE_COMMAND} -E env
                bpfilter_LIBS=-Wl,-rpath=${CMAKE_BINARY_DIR}/output/lib\ -L${CMAKE_BINARY_DIR}/output/lib\ -lbpfilter\ $<$<CONFIG:Debug>:-fsanitize=address\ -fsanitize=undefined>
                bpfilter_CFLAGS=-I${CMAKE_SOURCE_DIR}/src/libbpfilter/include\ -I${CMAKE_BINARY_DIR}/build/libbpfilter/include\ $<$<CONFIG:Debug>:-fsanitize=address\ -fsanitize=undefined>
                ./configure
                    --enable-bpfilter
                    --disable-ipv6
                    --disable-nftables
                    --disable-libipq
                    --prefix=${BF_TOOLS_IPT_INSTALL_DIR}
)

# add_custom_target(integration DEPENDS iptables nftables)

add_custom_target(integration DEPENDS iptables)
