/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "harness/elf.h"

#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "shared/helper.h"

#define _cleanup_bf_elf_ __attribute__((cleanup(_bf_elf_cleanup)))

struct bf_elf
{
    int fd;
    Elf *elf;
};

static int _bf_elf_init(struct bf_elf *elf)
{
    bf_assert(elf);

    elf->fd = -1;
    elf->elf = NULL;

    return 0;
}

static int _bf_elf_cleanup(struct bf_elf *elf)
{
    bf_assert(elf);

    if (elf->fd >= 0)
        close(elf->fd);

    if (elf->elf)
        elf_end(elf->elf);

    return 0;
}

static int _bf_elf_get_section(const struct bf_elf *elf, const char *name,
                               Elf_Scn **section)
{
    GElf_Ehdr ehdr;
    Elf_Scn *scn = NULL;

    bf_assert(elf);
    bf_assert(name);
    bf_assert(section);

    if (!gelf_getehdr(elf->elf, &ehdr)) {
        fprintf(stderr, "ERROR: failed to get ELF header: %s\n",
                elf_errmsg(elf_errno()));
        return -elf_errno();
    }

    for (; (scn = elf_nextscn(elf->elf, scn));) {
        GElf_Shdr shdr;
        const char *section_name;

        if (!gelf_getshdr(scn, &shdr)) {
            fprintf(stderr, "ERROR: failed to get section header: %s\n",
                    elf_errmsg(elf_errno()));
            return -elf_errno();
        }

        section_name = elf_strptr(elf->elf, ehdr.e_shstrndx, shdr.sh_name);

        if (strcmp(section_name, name) == 0) {
            *section = scn;
            return 0;
        }
    }

    return -ENOENT;
}

static int _get_current_elf(struct bf_elf *elf)
{
    bf_assert(elf);

    elf->fd = open("/proc/self/exe", O_RDONLY);
    if (elf->fd < 0) {
        fprintf(stderr, "ERROR: failed to open /proc/self/exe: %s\n",
                strerror(errno));
        return -errno;
    }

    if (elf_version(EV_CURRENT) == EV_NONE) {
        fprintf(stderr, "ERROR: failed to initialize ELF library: %s\n",
                elf_errmsg(elf_errno()));
        return -elf_errno();
    }

    elf->elf = elf_begin(elf->fd, ELF_C_READ, NULL);
    if (!elf->elf) {
        fprintf(stderr, "ERROR: failed to open elf: %s\n",
                elf_errmsg(elf_errno()));
        return -elf_errno();
    }

    return 0;
}

int bf_elf_sym_new(struct bf_elf_sym **sym, const char *name, void *fn)
{
    _cleanup_bf_elf_sym_ struct bf_elf_sym *_sym = NULL;

    bf_assert(sym);
    bf_assert(name);
    bf_assert(fn);

    _sym = calloc(1, sizeof(*_sym));
    if (!_sym)
        return -ENOMEM;

    _sym->name = strdup(name);
    if (!_sym->name)
        return -ENOMEM;

    _sym->fn = fn;

    *sym = TAKE_PTR(_sym);

    return 0;
}

void bf_elf_sym_free(struct bf_elf_sym **sym)
{
    bf_assert(sym);

    if (!*sym)
        return;

    free((char *)(*sym)->name);
    free(*sym);
    *sym = NULL;
}

void bf_elf_sym_dump(struct bf_elf_sym *sym)
{
    bf_assert(sym);

    printf("bf_elf_sym: '%s' @ %p\n", sym->name, sym->fn);
}

int bf_test_get_symbols(bf_list *symbols)
{
    _cleanup_bf_elf_ struct bf_elf elf;
    Elf_Scn *bf_scn;
    Elf_Scn *sym_scn;
    GElf_Shdr shdr;
    Elf_Data *data;
    size_t sym_shdr_entries_count;
    int r;

    bf_assert(symbols);

    r = _bf_elf_init(&elf);
    if (r)
        return r;

    r = _get_current_elf(&elf);
    if (r)
        return r;

    r = _bf_elf_get_section(&elf, ".bf_test", &bf_scn);
    if (r) {
        fprintf(stderr, "ERROR: could not find section '.bf_test'\n");
        return r;
    }

    r = _bf_elf_get_section(&elf, ".symtab", &sym_scn);
    if (r) {
        fprintf(stderr, "ERROR: could not find section '.symtab'\n");
        return r;
    }

    if (!gelf_getshdr(sym_scn, &shdr)) {
        fprintf(stderr, "ERROR: failed to get section header: %s\n",
                elf_errmsg(elf_errno()));
        return -elf_errno();
    }

    data = elf_getdata(sym_scn, NULL);
    if (!data) {
        fprintf(stderr, "ERROR: failed to get section data: %s\n",
                elf_errmsg(elf_errno()));
        return -elf_errno();
    }

    sym_shdr_entries_count = shdr.sh_size / shdr.sh_entsize;
    for (size_t i = 0; i < sym_shdr_entries_count; ++i) {
        GElf_Sym sym;
        const char *sym_name;
        _cleanup_bf_elf_sym_ struct bf_elf_sym *bf_sym = NULL;

        if (!gelf_getsym(data, i, &sym)) {
            fprintf(stderr, "ERROR: failed to get symbol: %s\n",
                    elf_errmsg(elf_errno()));
            return -elf_errno();
        }

        sym_name = elf_strptr(elf.elf, shdr.sh_link, sym.st_name);

        if (sym.st_shndx != elf_ndxscn(bf_scn))
            continue;

        if (GELF_ST_TYPE(sym.st_info) != STT_FUNC)
            continue;

        r = bf_elf_sym_new(&bf_sym, sym_name, (void *)sym.st_value);
        if (r) {
            fprintf(stderr, "WARNING: failed to create bf_elf_sym for '%s'\n",
                    sym_name);
            continue;
        }

        r = bf_list_add_tail(symbols, bf_sym);
        if (r) {
            fprintf(stderr, "ERROR: failed to add bf_elf_sym to list: %s\n",
                    strerror(-r));
            return r;
        }

        TAKE_PTR(bf_sym);
    }

    return 0;
}
