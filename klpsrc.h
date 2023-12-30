/*
 * Copyright (c) 2023 laokz <zhangkai@iscas.ac.cn>
 * Klpmake is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of
 * the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
#ifndef _KLPMAKE_H
#define _KLPMAKE_H

#include <stdio.h>
#include "config.h"

#define KERNEL_DEV_ROOT "/lib/modules/%s/build/"
/* klp main source */
#define KLP_MAIN_SRC "livepatch.c"
/* patch info file */
#define KLPSRC_CONF "./_klpsrc.conf"
#define KLPSRC_SUFFIX ".klp"
#define PATCHED_FUNC_PREFIX "livepatch_"

#define MAX_PATCHED_FUNCS_PER_SRC 4
#define MAX_ROOT_PATH 256
#define MAX_MODS 4
#define MAX_SRCS 4
#define MAX_MOD_NAME 56
#define MAX_FILE_NAME 256
#define MAX_FUNC_NAME 64

struct src_t {
    char src_name[MAX_FILE_NAME];
    int func_count;
    char funcs[MAX_PATCHED_FUNCS_PER_SRC][MAX_FUNC_NAME];
    int pos[MAX_PATCHED_FUNCS_PER_SRC];
};

struct patch_t {
    char objm[MAX_MOD_NAME];
    char src_root[MAX_ROOT_PATH];
    char debug_root[MAX_ROOT_PATH];
    int mod_count;
    struct mod_t {
        char mod_name[MAX_MOD_NAME];
        int src_count;
        struct src_t srcs[MAX_SRCS];
    } mods[MAX_MODS];
};

struct para_t {
    /* for every patched source */
    char *src_root;
    char *debug_root;
    char *mod;
    char *src;
    int src_idx;
    int func_count;
    char *funcs[MAX_PATCHED_FUNCS_PER_SRC];
    int *pos;    /* save funcs position */
    FILE *fout;    /* write klp source */
    CXIndex old_idx;
    CXTranslationUnit old_tu;   /* to precisely locate a static symbol */

    /* for every patched module */
    unsigned long koffset;  /* KASLR offset or module base */
    Dwarf_Debug dbg;
    Dwarf_Die cu[MAX_SRCS]; /* Libdwarf only support one pass CUs searching.
                               When begin_mod_sympos, find them all once. */
    Dwarf_Arange *arange;   /* When the targeted module has no .debug_ranges
                               section, we cannot use CU to query address.
                               Instead, fallback to .debug_aranges section
                               using this member, and it also act as a flag
                               to this scenario. */
    Dwarf_Signed a_count;

    /* for all */
    FILE *fp;       /* /proc/kallsyms */
    FILE *fmain;    /* write klp main source */
};

extern int g_debug;
#define log_debug(fmt, ...) do { \
    if (g_debug) \
        printf(fmt, ##__VA_ARGS__); \
} while (0)

/* called when new module come in/out */
int begin_mod_sympos(struct para_t *para, struct src_t *srcs, int src_count);
void end_mod_sympos(struct para_t *para, int src_count, int end_all);

#define KLPSYM_NON_EXPORTED  1
#define KLPSYM_EXPORTED      0
#define KLPSYM_ERROR        -1
/* Weak symbol in kallsyms. They have no prototype. */
#define KLPSYM_WEAK         -2
/*
 * Not-found symbols in kallsyms.
 * For globals, means they are new.
 * For locals(static), means they are inlined functions.
 */
#define KLPSYM_NOT_FOUND -42
int non_exported(struct para_t *para, const char *name);
/*
 * 'scope', where 'name' defined. For function and file scope variable,
 * scope is NULL. For static variable defined in function, scope is the
 * function's name.
 * 'orig_lineno', line number where 'name' defined in the original source.
 */
int non_included(struct para_t *para, const char *name, int is_var,
                                const char *scope, int orig_lineno);

int parse_arg_and_patch(int argc, char *argv[], struct patch_t *patch);
void write_main_src_head(FILE *fp);
void write_main_src_tail(FILE *fp, struct patch_t *patch);
void gen_makefile(struct patch_t *patch);

#endif
