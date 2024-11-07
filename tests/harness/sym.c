/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "harness/sym.h"

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core/helper.h"
#include "core/list.h"
#include "core/logger.h"

#define _clean_bf_test_elf_ __attribute__((cleanup(_bf_test_elf_cleanup)))

struct bf_test_elf
{
    int fd;
    Elf *elf;
};

static int _bf_test_elf_init(struct bf_test_elf *elf)
{
    bf_assert(elf);

    elf->fd = -1;
    elf->elf = NULL;

    return 0;
}

static int _bf_test_elf_cleanup(struct bf_test_elf *elf)
{
    bf_assert(elf);

    if (elf->fd >= 0)
        close(elf->fd);

    if (elf->elf)
        elf_end(elf->elf);

    return 0;
}

static int _bf_test_elf_get_section(const struct bf_test_elf *elf,
                                    const char *name, Elf_Scn **section)
{
    GElf_Ehdr ehdr;
    Elf_Scn *scn = NULL;

    bf_assert(elf && name && section);

    if (!gelf_getehdr(elf->elf, &ehdr))
        return bf_err_r(elf_errno(), "failed to get ELF header");

    for (; (scn = elf_nextscn(elf->elf, scn));) {
        GElf_Shdr shdr;
        const char *section_name;

        if (!gelf_getshdr(scn, &shdr))
            return bf_err_r(elf_errno(), "failed to get ELF section header");

        section_name = elf_strptr(elf->elf, ehdr.e_shstrndx, shdr.sh_name);

        if (strcmp(section_name, name) == 0) {
            *section = scn;
            return 0;
        }
    }

    return -ENOENT;
}

static int _bf_test_get_current_elf(struct bf_test_elf *elf)
{
    bf_assert(elf);

    elf->fd = open("/proc/self/exe", O_RDONLY);
    if (elf->fd < 0)
        return bf_err_r(errno, "failed to open '/proc/self/exe'");

    if (elf_version(EV_CURRENT) == EV_NONE)
        return bf_err_r(elf_errno(), "failed to initialize libelf");

    elf->elf = elf_begin(elf->fd, ELF_C_READ, NULL);
    if (!elf->elf)
        return bf_err_r(elf_errno(), "failed to open ELF file");

    return 0;
}

int bf_test_sym_new(struct bf_test_sym **sym, const char *name, void *cb)
{
    _free_bf_test_sym_ struct bf_test_sym *_sym = NULL;

    bf_assert(sym && name && cb);

    _sym = calloc(1, sizeof(*_sym));
    if (!_sym)
        return -ENOMEM;

    _sym->name = strdup(name);
    if (!_sym->name)
        return -ENOMEM;

    _sym->cb = cb;

    *sym = TAKE_PTR(_sym);

    return 0;
}

void bf_test_sym_free(struct bf_test_sym **sym)
{
    bf_assert(sym);

    if (!*sym)
        return;

    free((char *)(*sym)->name);
    freep((void *)sym);
}

void bf_test_sym_dump(struct bf_test_sym *sym)
{
    bf_assert(sym);

    printf("bf_elf_sym: '%s' @ %p\n", sym->name, sym->cb);
}

int bf_test_get_symbols(bf_list *symbols)
{
    _clean_bf_test_elf_ struct bf_test_elf elf;
    Elf_Scn *bf_scn;
    Elf_Scn *sym_scn;
    GElf_Shdr shdr;
    Elf_Data *data;
    size_t sym_shdr_entries_count;
    int r;

    bf_assert(symbols);

    r = _bf_test_elf_init(&elf);
    if (r)
        return r;

    r = _bf_test_get_current_elf(&elf);
    if (r)
        return r;

    r = _bf_test_elf_get_section(&elf, ".bf_test", &bf_scn);
    if (r)
        return bf_err_r(r, "could not find section '.bf_test' in ELF");

    r = _bf_test_elf_get_section(&elf, ".symtab", &sym_scn);
    if (r)
        return bf_err_r(r, "could not find section '.symtab' in ELF");

    if (!gelf_getshdr(sym_scn, &shdr))
        return bf_err_r(elf_errno(), "failed to get section header");

    data = elf_getdata(sym_scn, NULL);
    if (!data)
        return bf_err_r(elf_errno(), "failed to get ELF section data");

    sym_shdr_entries_count = shdr.sh_size / shdr.sh_entsize;
    for (size_t i = 0; i < sym_shdr_entries_count; ++i) {
        GElf_Sym sym;
        const char *sym_name;
        _free_bf_test_sym_ struct bf_test_sym *bf_sym = NULL;

        if (!gelf_getsym(data, (int)i, &sym))
            return bf_err_r(elf_errno(), "failed to get ELF symbol");

        sym_name = elf_strptr(elf.elf, shdr.sh_link, sym.st_name);

        if (sym.st_shndx != elf_ndxscn(bf_scn))
            continue;

        if (GELF_ST_TYPE(sym.st_info) != STT_FUNC)
            continue;

        r = bf_test_sym_new(&bf_sym, sym_name, (void *)sym.st_value);
        if (r) {
            bf_warn("failed to create bf_test_sym for '%s', skipping",
                    sym_name);
            continue;
        }

        r = bf_list_add_tail(symbols, bf_sym);
        if (r) {
            bf_warn("failed to add bf_test_sym to list, skipping");
            continue;
        }

        TAKE_PTR(bf_sym);
    }

    return 0;
}
