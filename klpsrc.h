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
/*
 * OSes might have different directories. This is of openEuler.
 * It seems that we need some configure scripts.
 */
#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>
// Debian
//#include <libdwarf/dwarf.h>
//#include <libdwarf/libdwarf.h>

#define PATCHED_FUNC_PREFIX "livepatch_"
#define ERROR_MSG_PREFIX "KLPSRC ERROR: "
#define MAX_PATCHED_FUNCS_PER_SRC 4
#define MAX_NEW_ITEMS_PER_SRC 8
#define MAX_ROOT_PATH 256
#define MAX_MODS 4
#define MAX_SRCS 4
#define MAX_MOD_NAME 56
#define MAX_FILE_NAME 128
#define MAX_FUNC_NAME 64

/* klp main source */
#define KLP_MAIN_SRC "livepatch.c"
#define KLPSRC_SUFFIX "klp"
/* manual generated klpsrc arguments */
#define KLPSRC_CONF "./klpsrc.conf"

struct src_t {
	char src_name[MAX_FILE_NAME];
	int func_count;
	char funcs[MAX_PATCHED_FUNCS_PER_SRC][MAX_FUNC_NAME];
	int pos[MAX_PATCHED_FUNCS_PER_SRC];
	int new_count;
	char news[MAX_NEW_ITEMS_PER_SRC][MAX_FUNC_NAME];
};

struct patch_t {
	char src_root[MAX_ROOT_PATH];
	char dev_root[MAX_ROOT_PATH];
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
	int new_count;
	char *news[MAX_NEW_ITEMS_PER_SRC];

	int *pos;	/* save funcs position */
	FILE *fout;	/* write klp source */

	/* for every patched module */
	unsigned long koffset;	/* KASLR offset or module base */
	Dwarf_Debug dbg;

	Dwarf_Die cu[MAX_SRCS];	/* Libdwarf only support one pass CUs searching.
								When begin_mod_ksympos, find them all once. */

	/* for all */
	FILE *fp;		/* /proc/kallsyms */

	FILE *fmain;	/* write klp main source */
};

/* called when new module come in/out */
int begin_mod_ksympos(struct para_t *para, struct src_t *srcs, int src_count);
void end_mod_ksympos(struct para_t *para, struct src_t *srcs, int src_count, int end_all);

/* return: 1 yes, 0 no(exported), -1 error */
int non_exported(struct para_t *para, const char *name);
/* return: >=0 yes and it is position, -1 no(inlined), -2 error */
int non_included(struct para_t *para, const char *name, int is_func);

int parse_arguments(struct patch_t *patch);
void begin_main_src(FILE *fp);
void end_main_src(FILE *fp, struct patch_t *patch);
void gen_makefile(struct patch_t *patch, const char *mod);

#endif
