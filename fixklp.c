/*
 * Fixklp is part of klpmake. It converts Linux "partial linked" kernel
 * module which include references to livepatch symbols -- non-exported
 * globals, non-included locals(KLPSYM), to normal module per the
 * Livepatch module ELF format.
 *
 * No dynamic memory free here, all been left to OS.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <gelf.h>
#include <err.h>

/* KSYM_NAME_LEN is 512, not support yet */
#define NAME_LEN 200
#define MODULE_NAME_LEN 56
#define SHF_RELA_LIVEPATCH  0x00100000
#define SHN_LIVEPATCH       0xff20

#define E(statement, err_value) do { \
    if ((statement) == (err_value))  \
        err(EXIT_FAILURE, "ERROR: %s:%d %s", __func__, \
           __LINE__, elf_errmsg(0)); \
} while (0)

/* one rela to an KLPSYM */
struct rela_klpsym_t {
    struct rela_klpsym_t *next;
    size_t relasec_index;
    size_t entry_index;
    char *relasec_name;
    GElf_Rela rela;
};

/* one KLPSYM */
struct klpsym_t {
    char name[NAME_LEN];
    char mod[MODULE_NAME_LEN];
    struct rela_klpsym_t *head;
    size_t symindex;
    size_t pos;
};

/* rela sections which must split to new .klp.rela */
struct klp_rela_t {
    char *sec_name;
    char mod[MODULE_NAME_LEN];
    size_t sec_index;
    GElf_Shdr sh;
    Elf_Data data;
};

/* original object KLPSYM info */
struct klpsyms_t {
    int klpsym_count;
    int newsec_count;
    struct klpsym_t *u;
    struct klp_rela_t *secs;
};

struct orig_elf_t {
    Elf *relf;
    size_t sections_nr;
    size_t symtab_index;
    size_t strtab_index;
    size_t strtab_size;
    size_t shstrtab_index;
    size_t shstrtab_size;
    GElf_Half arch;
    size_t current_sec_index;    /* working section cursor */
};

/* get original .symtab .strtab .shstrtab paras */
static void get_orig_paras(Elf *relf, struct orig_elf_t *para)
{
    Elf_Scn *scn;
    GElf_Shdr sh;

    scn = NULL;
    while (1) {    /* .symtab must be one and only one */
        E(scn = elf_nextscn(relf, scn), NULL);
        E(gelf_getshdr(scn, &sh), NULL);
        if (sh.sh_type == SHT_SYMTAB) {
            E(para->symtab_index = elf_ndxscn(scn), SHN_UNDEF);
            break;
        }
    }

    para->strtab_index = sh.sh_link;
    E(scn = elf_getscn(relf, para->strtab_index), NULL);
    E(gelf_getshdr(scn, &sh), NULL);
    para->strtab_size = sh.sh_size;

    E(elf_getshdrstrndx(relf, &para->shstrtab_index), -1);
    E(scn = elf_getscn(relf, para->shstrtab_index), NULL);
    E(gelf_getshdr(scn, &sh), NULL);
    para->shstrtab_size = sh.sh_size;

    para->relf = relf;
}

static void scan_symtab(struct orig_elf_t *para, struct klpsyms_t *klpsyms)
{
    Elf_Scn *scn;
    GElf_Shdr sh;
    Elf_Data *data;
    GElf_Sym sym;
    char *name;

    E(scn = elf_getscn(para->relf, para->symtab_index), NULL);
    E(gelf_getshdr(scn, &sh), NULL);
    E(data = elf_getdata(scn, NULL), NULL);
    /*
     * Begin after the last local symbol. Non-included local symbols already
     * been set to GLOBAL bindings in the "partial linked" ko .symtab.
     */
    for (size_t i = sh.sh_info; i < sh.sh_size / sh.sh_entsize; i++) {
        E(gelf_getsym(data, i, &sym), NULL);
        name = elf_strptr(para->relf, sh.sh_link, sym.st_name);
        for (int j = 0; j < klpsyms->klpsym_count; j++) {
            if (!strcmp(name, klpsyms->u[j].name)) {
                klpsyms->u[j].symindex = i;
                break;
            }
        }
    }
}

/* rela input as hi20_rela, output as corresponding lo12_rela */
static size_t rv_search_lo12(Elf_Data *reladata, GElf_Rela *rela,
                        size_t rela_count, struct orig_elf_t *para)
{
    GElf_Rela lo12_rela;
    size_t idx;
    Elf_Scn *scn;
    Elf_Data *symdata;
    GElf_Sym lo12_sym;
    GElf_Addr hi20_offset = rela->r_offset;

    E(scn = elf_getscn(para->relf, para->symtab_index), NULL);
    E(symdata = elf_getdata(scn, NULL), NULL);

    for (idx = 0; idx < rela_count; idx++) {
        E(gelf_getrela (reladata, idx, &lo12_rela), NULL);
        if (GELF_R_TYPE(lo12_rela.r_info) == R_RISCV_PCREL_LO12_I ||
            GELF_R_TYPE(lo12_rela.r_info) ==  R_RISCV_PCREL_LO12_S) {
            E(gelf_getsym(symdata, GELF_R_SYM(lo12_rela.r_info), &lo12_sym), NULL);
            if (hi20_offset == lo12_sym.st_value) {
                *rela = lo12_rela;
                break;
            }
        }
    }
    return idx;
}

static size_t scan_relasec(struct orig_elf_t *para, struct klpsyms_t *klpsyms)
{
    GElf_Shdr sh;
    char *name;
    Elf_Data *data;
    GElf_Rela rela;
    Elf_Scn *scn = NULL;
    struct rela_klpsym_t *p;
    size_t lastsec = 0;
    size_t newsecs = 0;

    for (size_t i = 1; i < para->sections_nr; i++) {
        E(scn = elf_nextscn(para->relf, scn), NULL);
        E(gelf_getshdr(scn, &sh), NULL);
        if (sh.sh_type != SHT_RELA)
            continue;

        E(name = elf_strptr(para->relf, para->shstrtab_index, sh.sh_name), NULL);
        E(data = elf_getdata(scn, NULL), NULL);

        for (int j = sh.sh_size / sh.sh_entsize - 1; j >= 0; j--) {
            E(gelf_getrela (data, j, &rela), NULL);
            for (int m = klpsyms->klpsym_count - 1; m >= 0; m--) {
                if (GELF_R_SYM(rela.r_info) != klpsyms->u[m].symindex)
                    continue;

                E(p = malloc(sizeof(struct rela_klpsym_t)), NULL);
                p->relasec_index = i;
                p->entry_index = j;
                p->relasec_name = name;
                p->rela = rela;
                p->next = klpsyms->u[m].head;
                klpsyms->u[m].head = p;
                if (i != lastsec) {
                    lastsec = i;
                    newsecs++;
                }
                /*
                 * RISC-V has the special case that PCREL_LO12 must
                 * sit in the same section with PCREL_HI20.
                 */
                if (para->arch == EM_RISCV && (
                    GELF_R_TYPE(rela.r_info) == R_RISCV_PCREL_HI20 ||
                    GELF_R_TYPE(rela.r_info) == R_RISCV_GOT_HI20)) {
                    E(p = malloc(sizeof(struct rela_klpsym_t)), NULL);
                    p->relasec_index = i;
                    p->entry_index = rv_search_lo12(data, &rela,
                                    sh.sh_size / sh.sh_entsize, para);
                    p->relasec_name = name;
                    p->rela = rela;
                    p->next = klpsyms->u[m].head;
                    klpsyms->u[m].head = p;
                }
            }
        }
    }
    return newsecs;
}

/* scan distinct "new section" info from KLPSYMs */
static void scan_newsecs(Elf *relf, struct klpsyms_t *klpsyms)
{
    struct rela_klpsym_t *p;
    int count = 0;
    Elf_Scn *scn;
    Elf_Data *data;

    E(klpsyms->secs = malloc(sizeof(struct klp_rela_t) *
                                    klpsyms->newsec_count), NULL);

    for (int j = 0; j < klpsyms->klpsym_count; j++) {
        p = klpsyms->u[j].head;
        while (p) {
            /* see if already known KLPSYM rela section */
            for (int i = 0; i < count; i++) {
                if (klpsyms->secs[i].sec_index == p->relasec_index)
                    goto outer;
            }

            klpsyms->secs[count].sec_index = p->relasec_index;
            klpsyms->secs[count].sec_name = p->relasec_name;
            sprintf(klpsyms->secs[count].mod, "%s", klpsyms->u[j].mod);
            E(scn = elf_getscn(relf, p->relasec_index), NULL);
            E(gelf_getshdr(scn, &klpsyms->secs[count].sh), NULL);
            E(data = elf_getdata(scn, NULL), NULL);
            klpsyms->secs[count].data = *data;
            count++;
outer:
            p = p->next;
        }
    }
}

/* append a new section using the given arguments */
static void write_sec_common(Elf *welf, GElf_Shdr *sh, Elf_Data *data)
{
    Elf_Scn *wscn;
    Elf_Data *wdata;

    E(wscn = elf_newscn(welf), NULL);
    E(wdata = elf_newdata(wscn), NULL);
    wdata->d_type = data->d_type;
    wdata->d_buf = data->d_buf;
    wdata->d_size = data->d_size;
    E(gelf_update_shdr(wscn, sh), 0);
}

/* .klp.sym.MOD.ORIG-NAME,0, including '\0' */
static size_t klp_sym_strlen(struct klpsym_t *u)
{   /* could POS been so large? */
    return strlen(u->name) + strlen(u->mod) + (u->pos > 9 ? 2 : 1) + 11 + 1;
}

/* .klp.rela.MOD.ORIG-NAME, including '\0', without original ".rela" */
static size_t klp_rela_strlen(struct klp_rela_t *r)
{
    return strlen(r->sec_name) - 5 + strlen(r->mod) + 11 + 1;
}

/* copy original section header and data meta, new_buflen must >= the old */
static void copy_sec_data_meta(GElf_Shdr *oldsh, GElf_Shdr *newsh,
                    Elf_Data *olddata, Elf_Data *newdata, size_t new_buflen)
{
    char *buf;
    E(buf = malloc(new_buflen), NULL);

    *newdata = *olddata;
    newdata->d_buf = buf;
    newdata->d_size = new_buflen;
    *newsh = *oldsh;

    /* We can't free buffer because ELF library need it until elf_update. */
}

/*
 * Append ELF a .strtab section with new names appending at the tail.
 * Leave original names untouched.
 */
static void modify_strtab(Elf *welf, GElf_Shdr *sh, Elf_Data *data,
                        struct klpsyms_t *klpsyms, struct orig_elf_t *para)
{
    GElf_Shdr newsh;
    Elf_Data newdata;

    /* get total KLPSYM new names length */
    size_t newname_len = 0;
    for (int j = 0; j < klpsyms->klpsym_count; j++) {
        newname_len += klp_sym_strlen(&klpsyms->u[j]);
    }

    copy_sec_data_meta(sh, &newsh, data, &newdata, data->d_size + newname_len);
    memcpy(newdata.d_buf, data->d_buf, data->d_size);

    char *buf = newdata.d_buf + data->d_size;
    int len;
    for (int j = 0; j < klpsyms->klpsym_count; j++) {
        len = sprintf(buf, ".klp.sym.%s.%s,%d", klpsyms->u[j].mod,
                                    klpsyms->u[j].name, klpsyms->u[j].pos);
        buf += len + 1;
    }

    newsh.sh_size += newname_len;
    write_sec_common(welf, &newsh, &newdata);
}

/* same as modify_strtab, except this is for .shstrtab */
static void modify_shstrtab(Elf *welf, GElf_Shdr *sh, Elf_Data *data,
                        struct klpsyms_t *klpsyms, struct orig_elf_t *para)
{
    GElf_Shdr newsh;
    Elf_Data newdata;

    size_t newname_len = 0;
    for (int j = 0; j < klpsyms->newsec_count; j++) {
        newname_len += klp_rela_strlen(&klpsyms->secs[j]);
    }

    copy_sec_data_meta(sh, &newsh, data, &newdata, data->d_size + newname_len);
    memcpy(newdata.d_buf, data->d_buf, data->d_size);

    char *buf = newdata.d_buf + data->d_size;
    int len;
    for (int j = 0; j < klpsyms->newsec_count; j++) {
        len = sprintf(buf, ".klp.rela.%s.%s", klpsyms->secs[j].mod,
                                        klpsyms->secs[j].sec_name + 5);
        buf += len + 1;
    }

    newsh.sh_size += newname_len;
    write_sec_common(welf, &newsh, &newdata);
}

/* append ELF a .symtab section with KLPSYMs name and flag modified */
static void modify_symtab(Elf *welf, GElf_Shdr *sh, Elf_Data *data,
                    struct klpsyms_t *klpsyms, struct orig_elf_t *para)
{
    GElf_Sym sym;

    /* new name begin at the tail of original .strtab */
    size_t offset = para->strtab_size;

    for (int j = 0; j < klpsyms->klpsym_count; j++) {
        E(gelf_getsym(data, klpsyms->u[j].symindex, &sym), NULL);
        sym.st_shndx = SHN_LIVEPATCH;
        sym.st_name = offset;
        offset += klp_sym_strlen(&klpsyms->u[j]);
        E(gelf_update_sym(data, klpsyms->u[j].symindex, &sym), 0);
    }

    write_sec_common(welf, sh, data);
}

/* append ELF a .rela section with KLPSYMs reference entries removed */
static void modify_relasec(Elf *welf, GElf_Shdr *sh, Elf_Data *data,
                    struct klpsyms_t *klpsyms, struct orig_elf_t *para)
{
    GElf_Rela rela;
    struct rela_klpsym_t *p;
    size_t new_entries = 0;

    for (int i = 0; i < sh->sh_size / sh->sh_entsize; i++) {
        for (int j = 0; j < klpsyms->klpsym_count; j++) {
            p = klpsyms->u[j].head;
            while (p) {
                /* bypass KLPSYM reference rela */
                if (p->relasec_index == para->current_sec_index &&
                                                p->entry_index == i)
                    goto outer;
                p = p->next;
            }
        }
        /* in-place move rela */
        E(gelf_getrela(data, i, &rela), NULL);
        E(gelf_update_rela(data, new_entries, &rela), 0);
        new_entries++;
outer:
    }

    data->d_size = new_entries * sh->sh_entsize;
    sh->sh_size = new_entries * sh->sh_entsize;
    write_sec_common(welf, sh, data);
}

/* whether the rela section referred to an KLPSYM */
static int is_klpsym_relasec(size_t relasec_index, struct klpsyms_t *klpsyms)
{
    struct rela_klpsym_t *p;

    for (size_t i = 0; i < klpsyms->klpsym_count; i++) {
        p = klpsyms->u[i].head;
        while (p) {
            if (relasec_index == p->relasec_index)
                return 1;
            p = p->next;
        }
    }
    return 0;
}

static void create_klp_rela_sec(Elf *welf, struct klpsyms_t *klpsyms,
                                                struct orig_elf_t *para)
{
    Elf_Scn *wscn;
    GElf_Shdr newsh;
    Elf_Data *wdata;
    struct rela_klpsym_t *p;
    size_t new_entries;

    /* new name begin at the tail of original .shstrtab */
    size_t offset = para->shstrtab_size;

    for (int i = 0; i < klpsyms->newsec_count; i++) {
        E(wscn = elf_newscn(welf), NULL);
        E(wdata = elf_newdata(wscn), NULL);
        /* the buffer is too large now */
        copy_sec_data_meta(&klpsyms->secs[i].sh, &newsh,
                &klpsyms->secs[i].data, wdata, klpsyms->secs[i].data.d_size);

        new_entries = 0;
        for (int m = 0; m < klpsyms->klpsym_count; m++) {
            p = klpsyms->u[m].head;
            while (p) {
                if (p->relasec_index == klpsyms->secs[i].sec_index) {
                    E(gelf_update_rela(wdata, new_entries, &p->rela), 0);
                    new_entries++;
                }
                p = p->next;
            }
        }

        wdata->d_size = new_entries * newsh.sh_entsize;
        newsh.sh_name = offset;
        offset += klp_rela_strlen(&klpsyms->secs[i]);
        newsh.sh_size = newsh.sh_entsize * new_entries;
        newsh.sh_flags = SHF_RELA_LIVEPATCH | SHF_INFO_LINK | SHF_ALLOC;
        /* the library will take care .sh_offset */
        E(gelf_update_shdr(wscn, &newsh), 0);
    }
}

static void modify_obj(const char *obj, const char *newobj,
                                    struct klpsyms_t *klpsyms)
{
    Elf *relf, *welf;
    int rfd, wfd;
    Elf_Data *rdata;
    Elf_Scn *rscn;
    GElf_Ehdr ehdr;
    GElf_Shdr sh;
    struct orig_elf_t para;

    /* open ELF */
    E(rfd = open(obj, O_RDONLY), -1);
    E(wfd = creat(newobj, 0644), -1);
    E(elf_version(EV_CURRENT), EV_NONE);
    E(relf = elf_begin(rfd, ELF_C_READ_MMAP_PRIVATE, NULL), NULL);
    E(welf = elf_begin(wfd, ELF_C_WRITE, NULL), NULL);

    /* get various useful variables */
    E(gelf_getehdr(relf, &ehdr), NULL);
    para.arch = ehdr.e_machine;
    E(elf_getshdrnum(relf, &para.sections_nr), -1);
    get_orig_paras(relf, &para);
    scan_symtab(&para, klpsyms);
    klpsyms->newsec_count = scan_relasec(&para, klpsyms);
    scan_newsecs(relf, klpsyms);

    /* actually do the dirty */
    E(gelf_newehdr(welf, gelf_getclass(relf)), 0);
    rscn = NULL;
    for (size_t i = 1; i < para.sections_nr; i++) {
        E(rscn = elf_nextscn(relf, rscn), NULL);
        E(gelf_getshdr(rscn, &sh), NULL);
        E(rdata = elf_getdata(rscn, NULL), NULL);

        para.current_sec_index = i;

        if (sh.sh_type == SHT_SYMTAB)
            modify_symtab(welf, &sh, rdata, klpsyms, &para);
        else if (i == para.strtab_index)
            modify_strtab(welf, &sh, rdata, klpsyms, &para);
        else if (i == para.shstrtab_index)
            modify_shstrtab(welf, &sh, rdata, klpsyms, &para);
        else if (is_klpsym_relasec(i, klpsyms))
            modify_relasec(welf, &sh, rdata, klpsyms, &para);
        else {
            write_sec_common(welf, &sh, rdata);
        }
    }
    create_klp_rela_sec(welf, klpsyms, &para);
    ehdr.e_shnum += klpsyms->newsec_count;
    E(gelf_update_ehdr(welf, &ehdr), 0);
    E(elf_update(welf, ELF_C_WRITE), -1);

    elf_end(relf);
    elf_end(welf);
    close(rfd);
    close(wfd);
}

int main(int argc, char *argv[])
{
    char *obj, *newobj, *p;
    struct klpsyms_t klpsyms = {0};
    FILE *f;
    char buf[NAME_LEN + MODULE_NAME_LEN + 10];
    int i, count;

    if (argc != 3) {
        fprintf(stderr, "Usage: $0 partial-linked-ko klpsym-list\n");
        exit(EXIT_FAILURE);
    }

    obj = argv[1];
    E(newobj = strdup(obj), NULL);
    E(p = strrchr(newobj, '.'), NULL);
    *p = '\0';

    count = 0;
    E(f = fopen(argv[2], "r"), NULL);
    while(fgets(buf, NAME_LEN + MODULE_NAME_LEN + 10, f))
        count++;
    E(fseek(f, 0, SEEK_SET), -1);

    i = 0;
    E(klpsyms.u = malloc(count * sizeof(struct klpsym_t)), NULL);
    while(fgets(buf, NAME_LEN + MODULE_NAME_LEN + 10, f)) {
        sscanf(buf, " %s %zu %s\n", klpsyms.u[i].name, &klpsyms.u[i].pos,
                                                        klpsyms.u[i].mod);
        if (klpsyms.u[i].mod[0] == '\0')
            sprintf(klpsyms.u[i].mod, "vmlinux");
        klpsyms.u[i].head = NULL;
        i++;
    }
    klpsyms.klpsym_count = i;

    modify_obj(obj, newobj, &klpsyms);
}
