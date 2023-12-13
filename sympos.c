/*
 * Part of klpsrc. It gives functions to verify livepatch symbols'
 * existence in /proc/kallsyms, and acquire their positions via
 * /proc/kallsyms, /proc/modules and module DWARF info.
 *
 * It seems that libdwarf would allocate some memory on actions or
 * errors. For simplicity, leave all these cleanup to dwarf_finish
 * when do end_mod_ksympos().
 *
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
#define _XOPEN_SOURCE 500
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ftw.h>
#include "klpsrc.h"

/* default Kconfig */
#if defined(__aarch64__)
#define KERNEL_TEXT_REF "_text"
#define KERNEL_REF_BASE 0xffff800008000000UL
#elif defined(__riscv) && (__riscv_xlen == 64)
#define KERNEL_TEXT_REF "_start"
#define KERNEL_REF_BASE 0xffffffff80000000UL
#elif defined(__x86_64__)
#define KERNEL_TEXT_REF "_text"
#define KERNEL_REF_BASE 0xffffffff81000000UL
#else
#error "unsupported architecture"
#endif

#define EXPORTED_SYM_PREFIX "__ksymtab_"
#define EXPORTED_SYM_PREFIX_LEN 10
/* seems the length can be very large? */
#define KALLSYMS_LINE_LEN 256

/* only dwarf call, hn ..., need predefined 'mod' 'err' variable */
#define E(statement, fmt, ...) do {									\
	int ret_ = statement;											\
	if (ret_ == DW_DLV_NO_ENTRY) {									\
		/* unexpected, DWARF info might corrupted */				\
		fprintf(stderr, ERROR_MSG_PREFIX"%s:%d no entry: "fmt, 		\
						__func__, __LINE__, ## __VA_ARGS__);		\
		return -2;													\
	} else if (ret_ == DW_DLV_ERROR) {								\
		fprintf(stderr, ERROR_MSG_PREFIX"%s:%d %s %s\n", mod, 		\
						__func__, __LINE__, dwarf_errmsg(err));		\
		return -2;													\
	}																\
} while (0)

int non_exported(struct para_t *para, const char *name)
{
	char buf[KALLSYMS_LINE_LEN], sym[KALLSYMS_LINE_LEN];
	int found = -1;

	rewind(para->fp);	/* anyway not to rewind? */
	while (fgets(buf, KALLSYMS_LINE_LEN, para->fp)) {
		sscanf(buf, "%*lx %*c %s", sym);
		if (!strcmp(sym, name))	/* the symbol must be unique in all scope */
			found = 1;
		if (!strncmp(sym, EXPORTED_SYM_PREFIX, EXPORTED_SYM_PREFIX_LEN) &&
				!strcmp(sym + EXPORTED_SYM_PREFIX_LEN, name))
			return 0;
	}

	if (found == -1)
		fprintf(stderr, ERROR_MSG_PREFIX
					"not found global symbol: %s in kallsyms\n", name);
	return found;
}

static Dwarf_Addr get_location_addr(struct para_t *para, Dwarf_Attribute attr)
{
    Dwarf_Unsigned lcount = 0;
    Dwarf_Loc_Head_c loclist_head = 0;
	Dwarf_Error err;
	char *mod = para->mod;

    E(dwarf_get_loclist_c(attr, &loclist_head, &lcount, &err), "");

    Dwarf_Small loclist_lkind = 0;
    Dwarf_Small lle_value = 0;
    Dwarf_Unsigned rawval1 = 0;
    Dwarf_Unsigned rawval2 = 0;
    Dwarf_Bool debug_addr_unavailable = 0;
    Dwarf_Addr lopc = 0;
    Dwarf_Addr hipc = 0;
    Dwarf_Unsigned loclist_expr_op_count = 0;
    Dwarf_Locdesc_c locdesc_entry = 0;
    Dwarf_Unsigned expression_offset = 0;
    Dwarf_Unsigned locdesc_offset = 0;
    E(dwarf_get_locdesc_entry_d(loclist_head, 0, &lle_value, &rawval1, &rawval2,
                &debug_addr_unavailable, &lopc, &hipc, &loclist_expr_op_count,
                &locdesc_entry, &loclist_lkind, &expression_offset,
                &locdesc_offset, &err), "");

    Dwarf_Small op = 0;
    Dwarf_Unsigned opd1 = 0;
    Dwarf_Unsigned opd2 = 0;
    Dwarf_Unsigned opd3 = 0;
    Dwarf_Unsigned offsetforbranch = 0;
    E(dwarf_get_location_op_value_c(locdesc_entry, 0, &op, &opd1, &opd2, &opd3,
                        &offsetforbranch, &err), "");

    dwarf_dealloc_loc_head_c(loclist_head);
    return opd1;
}

static Dwarf_Addr get_var_addr(struct para_t *para, const char *var)
{
    Dwarf_Die kid, d;
    Dwarf_Error err = NULL;
	Dwarf_Addr addr;
	char *mod = para->mod;

    E(dwarf_child(para->cu[para->src_idx], &kid, &err), "");
	while(dwarf_siblingof_b(para->dbg, kid, 1, &d, &err) == DW_DLV_OK){
		Dwarf_Half tag;
		char *diename;
		E(dwarf_tag(d, &tag, &err), "");
		if (tag != DW_TAG_variable) {
			dwarf_dealloc_die(kid);
			kid = d;
			continue;
		}
		E(dwarf_diename(d, &diename, &err), "");
		if (strcmp(diename, var)) {
			dwarf_dealloc_die(kid);
			kid = d;
			continue;
		}

	    Dwarf_Signed atcount;
	    Dwarf_Attribute *atlist;
	    E(dwarf_attrlist(d, &atlist, &atcount, &err), "");
		for (int i = 0; i < atcount; ++i) {
	        Dwarf_Half attrnum = 0;
    	    const char *attrname = 0;
        	E(dwarf_whatattr(atlist[i], &attrnum, &err), "");
			if (attrnum == DW_AT_location)
				addr = get_location_addr(para, atlist[i]);
	        dwarf_dealloc_attribute(atlist[i]);
	    }
	    dwarf_dealloc(para->dbg, atlist, DW_DLA_LIST);
		dwarf_dealloc_die(d);
		break;
    }

	dwarf_dealloc_die(kid);
	return addr;
}

/* current compile unit .text address ranges */
static struct {
	Dwarf_Addr lo;
	Dwarf_Addr hi;
} g_ranges[20];
static Dwarf_Signed g_ranges_count;

static int update_code_range(struct para_t *para)
{
    Dwarf_Signed atcount;
    Dwarf_Attribute *atlist;
    Dwarf_Half attrnum = 0;
	Dwarf_Error err;
	char *mod = para->mod;

	E(dwarf_attrlist(para->cu[para->src_idx], &atlist, &atcount, &err), "");
	for (int i = 0; i < atcount; ++i) {
        E(dwarf_whatattr(atlist[i], &attrnum, &err), "");
		if (attrnum == DW_AT_ranges) {
			Dwarf_Ranges *r;
			Dwarf_Off off;
			/* here not check FORM and RANGE kind */
			E(dwarf_global_formref(atlist[i], &off, &err), "");
			E(dwarf_get_ranges_b(para->dbg, off, para->cu[para->src_idx], NULL, &r, &g_ranges_count, NULL, &err),"");
			if (g_ranges_count > 20) {
				fprintf(stderr, ERROR_MSG_PREFIX"range count larger than 20\n");
				return -1;
			}
			for(int k = 0; k < g_ranges_count; k++) {
				g_ranges[k].lo = r[k].dwr_addr1;
				g_ranges[k].hi = r[k].dwr_addr2;
			}
			dwarf_dealloc_ranges(para->dbg, r, g_ranges_count);
			break;
		} else if (attrnum == DW_AT_low_pc) {
			Dwarf_Half form = 0;
			enum Dwarf_Form_Class formclass = DW_FORM_CLASS_UNKNOWN;
			g_ranges_count = 1;
			E(dwarf_lowpc(para->cu[para->src_idx], &g_ranges[0].lo, &err), "");
			E(dwarf_highpc_b(para->cu[para->src_idx],&g_ranges[0].hi, &form, &formclass, &err), "");
			if (form != DW_FORM_addr &&	!dwarf_addr_form_is_indexed(form)) {
				g_ranges[0].hi += g_ranges[0].lo;
			}
			break;
		}
	    dwarf_dealloc_attribute(atlist[i]);
    }
	dwarf_dealloc(para->dbg, atlist, DW_DLA_LIST);
	return 0;
}

int non_included(struct para_t *para, const char *name, int is_func)
{
	/* recognize and update current compile unit .text address aranges */
	static char *module = NULL, *source = NULL;
	if (is_func && (!module || !source || strcmp(module, para->mod) || strcmp(source, para->src))) {
		if (update_code_range(para) < 0)
			return -2;
		module = para->mod;
		source = para->src;
	}

	char buf[KALLSYMS_LINE_LEN], sym[KALLSYMS_LINE_LEN], mod[KALLSYMS_LINE_LEN];
	unsigned long addr;
	int count, pos;

	pos = -1;
	count = 0;
	rewind(para->fp);
	while (fgets(buf, KALLSYMS_LINE_LEN, para->fp)) {
		mod[0] = '\0';
		sscanf(buf, "%lx %*c %s [%[^]]]\n", &addr, sym, mod);
		if ((mod[0] == '\0') && strcmp(para->mod, "vmlinux") ||
			(mod[0] != '\0') && strcmp(mod, para->mod) || strcmp(sym, name))
			continue;

		/* already matched, just count duplicate names */
		if (pos != -1) {
			count++;
			continue;
		}

		addr -= para->koffset;
		if (is_func) {
			for (int i = 0; i < g_ranges_count; i++) {
				if ((addr >= g_ranges[i].lo) && (addr < g_ranges[i].hi))
					pos = count;
			}
		} else {
			unsigned long var_addr = get_var_addr(para, name);
			if (var_addr == -2)
				return -2;
			if (addr == var_addr)
				pos = count;
		}
		count++;
	}

	if ((pos != -1) && (count > 1))
		pos++;	/* duplicate symbol is 1-indexed */
	return pos;
}

static int update_mod_base(struct para_t *para)
{
	char buf[256];
	char *p, *q;
	int found = 0;
	FILE *fp = fopen("/proc/modules", "r");
	if (fp == NULL) {
		perror(ERROR_MSG_PREFIX"open /proc/modules");
		return -1;
	}

	while (fgets(buf, 256, fp)) {
		p = strchr(buf, ' ');
		q = strrchr(buf, ' ');
		*p = '\0';
		if (!strcmp(buf, para->mod)) {
			para->koffset = strtoul(q, NULL, 16);
			found = 1;
			break;
		}
	}
	fclose(fp);

	if (!found) {
		fprintf(stderr, ERROR_MSG_PREFIX
				"not found %s in /proc/modules\n", para->mod);
		return -1;
	}
	return 0;
}

static void calc_kaslr_offset(struct para_t *para)
{
	char buf[KALLSYMS_LINE_LEN], sym[KALLSYMS_LINE_LEN];
	unsigned long addr;

	rewind(para->fp);
	while (fgets(buf, KALLSYMS_LINE_LEN, para->fp)) {
		sscanf(buf, "%lx %*c %s", &addr, sym);
		if (!strcmp(sym, KERNEL_TEXT_REF)) {
			para->koffset = addr - KERNEL_REF_BASE;
			return;
		}
	}
}

/*
 * Within debug-root, we believe there is only one module-name.ko*.
 * For out-of-tree module, that might be module-name.ko. For in-tree
 * module, that might be module-name.ko-`uname -r`.debug.
 */
static char *module_name;
static int filter(const char *fpath, const struct stat *sb,
                         int typeflag, struct FTW *ftwbuf)
{
	if ((typeflag == FTW_F) &&
		!strncmp(fpath + ftwbuf->base, module_name, strlen(module_name))) {
		strcpy(module_name, fpath);
		return 1;
	}
	return 0;
}
static int find_mod_path(const char *root)
{
    int n = nftw(root, filter, 20, 0);

    if (n <= 0) {
		fprintf(stderr, ERROR_MSG_PREFIX
					"failed found %s in %s\n", module_name, root);
		return -1;
    }
	return 0;
}

static int find_cus(struct para_t *para, struct src_t *srcs, int src_count)
{
	char *mod = para->mod;
	char *diename;
    Dwarf_Die cu_die;
	Dwarf_Error err;
	int count = 0;
	int i;

    do {
        E(dwarf_next_cu_header_d(para->dbg, 1, NULL, NULL, NULL, NULL, NULL,
								NULL, NULL, NULL, NULL, NULL, &err), "");

        E(dwarf_siblingof_b(para->dbg, NULL, 1, &cu_die,&err), "");
		E(dwarf_diename(cu_die, &diename, &err), "");
		for (i = 0; i < src_count; i++) {
			if (!strcmp(diename, srcs[i].src_name)) {
				para->cu[i] = cu_die;
				count++;
				break;
			}
		}
		if (i == src_count)
			dwarf_dealloc_die(cu_die);
    } while (count < src_count);
    return 0;
}

int begin_mod_ksympos(struct para_t *para, struct src_t *srcs, int src_count)
{
    Dwarf_Error err = NULL;
	char mod[256];

	/* open /proc/kallsyms once */
	if (!para->fp) {
		para->fp = fopen("/proc/kallsyms", "r");
		if (para->fp == NULL) {
			perror(ERROR_MSG_PREFIX"open /proc/kallsyms");
			return -2;
		}
	}

	/* open DWARF file */
	if (strcmp(para->mod, "vmlinux")) {
		strcpy(mod, para->mod);
		module_name = mod;
		if (find_mod_path(para->debug_root) == -1)
			return -1;
	} else {
		sprintf(mod, "%s/vmlinux", para->debug_root);
	}
	E(dwarf_init_path(mod, NULL, 0, DW_GROUPNUMBER_ANY, NULL, NULL,
			&para->dbg, &err), "not found DWARF info in %s\n", mod);

	if (find_cus(para, srcs, src_count) < 0)
		return -2;

	if (strcmp(para->mod, "vmlinux"))
		return update_mod_base(para);
	else
		calc_kaslr_offset(para);
    return 0;
}

void end_mod_ksympos(struct para_t *para, struct src_t *srcs, int src_count, int end_all)
{
	for (int i = 0; i < src_count; i++)
		if (para->cu[i]) {
			dwarf_dealloc_die(para->cu[i]);
			para->cu[i] = NULL;
		}
	if (para->dbg) {
   		(void)dwarf_finish(para->dbg);
		para->dbg = NULL;
	}
	if (end_all && para->fp) {
		fclose(para->fp);
		para->fp = NULL;
	}
}
