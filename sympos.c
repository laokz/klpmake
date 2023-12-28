/*
 * Part of klpsrc. It provides functions to verify livepatch symbols'
 * existence in /proc/kallsyms, and acquire their positions via
 * /proc/kallsyms, /proc/modules and module DWARF info.
 *
 * It seems that libdwarf would allocate some memory on actions or
 * errors. For simplicity, leave nearly all these cleanup to
 * dwarf_finish when doing end_mod_sympos().
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
#include <unistd.h>
#include <fcntl.h>
#include "klpsrc.h"

/* default kernel Kconfig value */
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

/* only dwarf call, hnn ..., need predefined 'err' variable */
#define E(statement, fmt, ...) do {                                 \
    int ret_ = statement;                                           \
    if (ret_ == DW_DLV_NO_ENTRY) {                                  \
        /* unexpected, DWARF info might corrupted */                \
        fprintf(stderr, "ERROR: %s:%d no entry: "fmt, __func__, __LINE__,\
                                            ## __VA_ARGS__);        \
        return KLPSYM_ERROR;                                        \
    } else if (ret_ == DW_DLV_ERROR) {                              \
        fprintf(stderr, "ERROR: %s:%d %s\n", __func__, __LINE__,    \
                                            dwarf_errmsg(err));     \
        return KLPSYM_ERROR;                                        \
    }                                                               \
} while (0)

int non_exported(struct para_t *para, const char *name)
{
    char buf[KALLSYMS_LINE_LEN], sym[KALLSYMS_LINE_LEN];
    int found = KLPSYM_NOT_FOUND;
    char t;

    rewind(para->fp);    /* anyway not to rewind? */
    while (fgets(buf, KALLSYMS_LINE_LEN, para->fp)) {
        sscanf(buf, "%*lx %c %s", &t, sym);
        /* global symbol must be unique in all scope, maybe not? */
        if (!strcmp(sym, name)) {
            if ((t == 'v') || (t == 'V') || (t == 'w') || (t == 'W'))
                found = KLPSYM_WEAK;
            else if ((t >= 'A') && (t <= 'Z'))
                found = KLPSYM_NON_EXPORTED;
            else
                /* ever saw two same name in kallsyms, one is T, another is t */
                log_debug("WARNING: found '%c' typed global: %s in kallsyms\n", t, name);
        }
        /* exported one must has a buddy __ksymtab_SYMBOL */
        if (!strncmp(sym, EXPORTED_SYM_PREFIX, EXPORTED_SYM_PREFIX_LEN) &&
                !strcmp(sym + EXPORTED_SYM_PREFIX_LEN, name))
            return KLPSYM_EXPORTED;
    }

    if (found == KLPSYM_NOT_FOUND)
        log_debug("not found global symbol: %s in kallsyms\n", name);
    else if (found == KLPSYM_WEAK)
        log_debug("found weak symbol: %s in kallsyms\n", name);
    return found;
}

static Dwarf_Addr get_location_addr(Dwarf_Attribute attr)
{
    Dwarf_Unsigned lcount = 0;
    Dwarf_Loc_Head_c loclist_head = 0;
    Dwarf_Error err;

    E(dwarf_get_loclist_c(attr, &loclist_head, &lcount, &err), "");

    /* don't care so many args, but that would fail if miss them */
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
    /* location has only one entry */
    E(dwarf_get_location_op_value_c(locdesc_entry, 0, &op, &opd1, &opd2, &opd3,
                        &offsetforbranch, &err), "");

    dwarf_dealloc_loc_head_c(loclist_head);
    /* opd1 is this location's address */
    return opd1;
}

static Dwarf_Addr get_addr(struct para_t *para, const char *name, int is_var)
{
    Dwarf_Die kid, d;
    Dwarf_Error err;
    Dwarf_Addr addr = KLPSYM_ERROR;
    int ret;

    /* walkthrough current compile unit's all direct children */
    E(dwarf_child(para->cu[para->src_idx], &kid, &err), "");
    while(dwarf_siblingof_b(para->dbg, kid, 1, &d, &err) == DW_DLV_OK){
        Dwarf_Half tag;
        char *diename;
        E(dwarf_tag(d, &tag, &err), "");
        if ((is_var && (tag != DW_TAG_variable)) ||
           (!is_var && (tag != DW_TAG_subprogram))) {
            dwarf_dealloc_die(kid);
            kid = d;
            continue;
        }
        ret = dwarf_diename(d, &diename, &err);
        if (ret == DW_DLV_ERROR) {
            fprintf(stderr, "ERROR: %s:%d %s\n", __func__, __LINE__,
                                                dwarf_errmsg(err));
            goto out;
        /*
         * DW_TAG_variable not always has DW_AT_name attribute, its
         * name might be at another tag's DW_AT_specification.
         * Mostly this is a global variable???
         *
         * DW_TAG_subprogram always has a DW_AT_name.
         */
        } else if ((ret == DW_DLV_NO_ENTRY) || strcmp(diename, name)) {
            dwarf_dealloc_die(kid);
            kid = d;
            continue;
        }

        if (is_var) {
            Dwarf_Signed atcount;
            Dwarf_Attribute *atlist;
            E(dwarf_attrlist(d, &atlist, &atcount, &err), "");
            for (int i = 0; i < atcount; ++i) {
                Dwarf_Half attrnum = 0;
                const char *attrname = 0;
                E(dwarf_whatattr(atlist[i], &attrnum, &err), "");
                if (attrnum == DW_AT_location)
                    addr = get_location_addr(atlist[i]);
                    /* without break to allow dealloc all attrs? */
                dwarf_dealloc_attribute(atlist[i]);
            }
            dwarf_dealloc(para->dbg, atlist, DW_DLA_LIST);
        } else {
            ret = dwarf_lowpc(d, &addr, &err);
            if (ret == DW_DLV_ERROR) {
                fprintf(stderr, "ERROR: %s:%d %s\n", __func__, __LINE__,
                                                dwarf_errmsg(err));
                goto out;
            } if (ret == DW_DLV_NO_ENTRY) {
                /*
                 * The name is matched, but there is no lowpc, that means
                 * this is an inlined function from header not found,
                 * give an illegal address.
                 */
                addr = (Dwarf_Addr)NULL;
            }
        }

        dwarf_dealloc_die(d);
        break;
    }

    log_debug("search CU %s %s's addr=0x%lx\n",
                is_var ? "variable" : "function", name, addr);

out:
    dwarf_dealloc_die(kid);
    return addr;
}

int non_included(struct para_t *para, const char *name, int is_var)
{
    char buf[KALLSYMS_LINE_LEN], sym[KALLSYMS_LINE_LEN], mod[KALLSYMS_LINE_LEN];
    unsigned long addr;
    int count, pos, found;
    char t;

    pos = KLPSYM_NOT_FOUND;
    count = 0;
    rewind(para->fp);
    while (fgets(buf, KALLSYMS_LINE_LEN, para->fp)) {
        mod[0] = '\0';
        sscanf(buf, "%lx %c %s [%[^]]]\n", &addr, &t, sym, mod);
        if ((mod[0] == '\0') && strcmp(para->mod, "vmlinux") ||
            (mod[0] != '\0') && strcmp(mod, para->mod) ||
                            strcmp(sym, name) || (t < 'a'))
            continue;

        /* already matched, just count duplicate */
        if (pos != KLPSYM_NOT_FOUND) {
            count++;
            continue;
        }

        addr -= para->koffset;
        unsigned long _addr = get_addr(para, name, is_var);
        if (_addr == KLPSYM_ERROR)
            return KLPSYM_ERROR;
        /*
         * Found non-consistent function address between DWARF
         * and kallsyms. Function is a block, variable is a
         * point. Loose the function compare condition!?
         */
        if ((is_var && (addr == _addr)) || (!is_var && _addr))
            pos = count;
        count++;
    }

    if ((pos != KLPSYM_NOT_FOUND) && (count > 1))
        pos++;    /* duplicate symbol is 1-indexed */
    return pos;
}

static int update_mod_base(struct para_t *para)
{
    char buf[KALLSYMS_LINE_LEN];
    char *p, *q;
    int found = 0;
    FILE *fp = fopen("/proc/modules", "r");
    if (fp == NULL) {
        perror("open /proc/modules");
        return -1;
    }

    while (fgets(buf, KALLSYMS_LINE_LEN, fp)) {
        p = strchr(buf, ' ');
        *p = '\0';
        if (!strcmp(buf, para->mod)) {
            q = strrchr(p + 1, ' ');
            para->koffset = strtoul(q, NULL, 16);
            found = 1;
            log_debug("module %s base=0x%lx\n", para->mod, para->koffset);
            break;
        }
    }
    fclose(fp);

    if (!found) {
        fprintf(stderr, "ERROR: not found module %s in /proc/modules\n", para->mod);
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
            log_debug("KASLR offset=0x%lx\n", para->koffset);
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
        strncpy(module_name, fpath, KALLSYMS_LINE_LEN);
        return 1;
    }
    return 0;
}
static int find_mod_path(const char *root)
{
    int n = nftw(root, filter, 20, 0);

    if (n <= 0) {
        fprintf(stderr, "ERROR: failed found %s* in %s\n", module_name, root);
        return -1;
    }
    return 0;
}

static int find_cus(struct para_t *para, struct src_t *srcs, int src_count)
{
    char *diename;
    Dwarf_Die cu_die;
    Dwarf_Error err;
    int count = 0;
    int i;

    /* from libdwarf document, CUs can only walkthrough once */
    do {
        E(dwarf_next_cu_header_d(para->dbg, 1, NULL, NULL, NULL, NULL, NULL,
                                NULL, NULL, NULL, NULL, NULL, &err), "");

        E(dwarf_siblingof_b(para->dbg, NULL, 1, &cu_die,&err), "");
        E(dwarf_diename(cu_die, &diename, &err), "");
        for (i = 0; i < src_count; i++) {
            if (!strcmp(diename, srcs[i].src_name)) {
                para->cu[i] = cu_die;
                count++;
                log_debug("found %s's compile unit\n", diename);
                break;
            }
        }
        /* free no used CU */
        if (i == src_count)
            dwarf_dealloc_die(cu_die);
    } while (count < src_count);
    return 0;
}

int begin_mod_sympos(struct para_t *para, struct src_t *srcs, int src_count)
{
    Dwarf_Error err;
    char mod[KALLSYMS_LINE_LEN];
    int ret;

    /* open /proc/kallsyms once */
    if (!para->fp) {
        para->fp = fopen("/proc/kallsyms", "r");
        if (para->fp == NULL) {
            perror("open /proc/kallsyms");
            return KLPSYM_ERROR;
        }
        log_debug("/proc/kallsyms opened for reading\n");
    }

    /* open DWARF file */
    if (strcmp(para->mod, "vmlinux")) {
        sprintf(mod, "%s.ko", para->mod);
        module_name = mod;
        if (find_mod_path(para->debug_root) == -1)
            return -1;
    } else {
        snprintf(mod, KALLSYMS_LINE_LEN, "%s/vmlinux", para->debug_root);
    }
    E(dwarf_init_path(mod, NULL, 0, DW_GROUPNUMBER_ANY, NULL, NULL,
            &para->dbg, &err), "not found DWARF info in %s\n", mod);
    log_debug("%s opened for querying\n", mod);

    if (find_cus(para, srcs, src_count) < 0)
        return KLPSYM_ERROR;

    if (strcmp(para->mod, "vmlinux"))
        return update_mod_base(para);
    else
        calc_kaslr_offset(para);
    return 0;
}

/*
 * When end_all, src_count should set to 0 as we don't know
 * if there any error out and which CUs alive. Leave the final
 * cleanup to dwarf_finish.
 */
void end_mod_sympos(struct para_t *para, int src_count, int end_all)
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

