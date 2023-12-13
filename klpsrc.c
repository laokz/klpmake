/*
 * TOP level elements:
 * include                  keep
 * macro                    keep
 * type def, forward        keep used
 * const                    unsupported
 * var                      unsupported          netlink的例子引用了全局数据nl_table
 * func                     keep used, remove attribute
 */
/*
 * Klpsrc is part of klpmake. It generates livepatch source code from
 * patch.
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
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <clang-c/Index.h>
#include "klpsrc.h"

#if defined(__aarch64__)
#define ARCH_PATH "arch/arm64"
#elif defined(__riscv) && (__riscv_xlen == 64)
#define ARCH_PATH "arch/riscv"
#elif defined(__x86_64__)
#define ARCH_PATH "arch/x86"
#else
#error "unsupported architecture"
#endif

#define KLPSYM_LIST "_klpmake.syms"
#define SYSCALL_PREFIX "__do_sys_"
#define SYSCALL_PREFIX_LEN 9

/* These CXCursorSets are disjoint. */
/*
 * Non-included local funcs called by patch.
 * Keep declaration as extern.
 */
CXCursorSet g_non_included;
/*
 * Inlined local funcs called by patch.
 * Keep all the body.
 */
CXCursorSet g_func_inlined;
/*
 * Type def, forward type, func prototype used by
 * the functions in the above sets.
 */
CXCursorSet g_type_def;
/*
 * New func/var definitions.
 */
CXCursorSet g_new_items;

/*
 * Non-exported global funcs called by patch.
 * Only for avoiding duplicate in KLPSYM_LIST.
 */
CXCursorSet g_non_exported;

/* Original source file buffer, for output */
const char *g_srcbuf;

static int is_in_main_src(CXCursor cusr)
{
	if (clang_Cursor_isNull(cusr))
		return 0;

	CXSourceLocation loc = clang_getCursorLocation(cusr);
	return clang_Location_isFromMainFile(loc);
}

static void D(CXCursor cusr,char *s)////////////////////////////////////////////
{
// 	if (!is_in_main_src(cusr))
//		return;
CXType  ct = clang_getCursorType(cusr);
enum  CXCursorKind k = clang_getCursorKind(cusr);
CXCursor tc = clang_getTypeDeclaration(ct);
	printf("%s type=%s typekind=%s(%d) kind=%s(%d) is_def=%d is_decl=%d is_ref=%d ref_cusr=%s",s,
			clang_getCString(clang_getTypeSpelling(ct)),
			clang_getCString(clang_getTypeKindSpelling(ct.kind)),ct.kind,
			clang_getCString(clang_getCursorKindSpelling(k)),k,
			clang_isCursorDefinition(cusr),
			clang_isDeclaration(k),
			clang_isReference(k),
			clang_getCString(clang_getCursorDisplayName(clang_getCursorReferenced(cusr))));
	if (!clang_Cursor_isNull(tc))
		printf("is_equ=%d decl_type=%s ",clang_equalCursors(cusr,tc),clang_getCString(clang_getTypeSpelling(clang_getCursorType(tc))));
	unsigned line;
	CXSourceRange r = clang_getCursorExtent(cusr);
	clang_getSpellingLocation(clang_getRangeStart(r), NULL, &line, NULL, NULL);
	printf("%d \"%s\"\n", line, clang_getCString(clang_getCursorDisplayName(cusr)));
/*
变量定义时		kind == TypeRef  clang_getCursorDefinition(cusr)得到的是类型cursor，可能！is_in_orig_src
变量引用时		kind == DeclRefExpr  clang_getTypeDeclaration(CXType)得到的可能是类型cursor（可能NULL，也可能是CXType_Pointer需要再解引用clang_getPointeeType/clang_getNonReferenceType
clang_getUnqualifiedType去除CXType可能的限定， */
}

static void output_klpsym_list(const char *func_name, int pos, char *mod)
{
	char buf[256];
	sprintf(buf, "echo %s %d %s >>"KLPSYM_LIST, func_name, pos, mod);
	system(buf);
}

static int is_found(CXCursor cusr)
{
	return  clang_CXCursorSet_contains(g_non_included, cusr) ||
			clang_CXCursorSet_contains(g_func_inlined, cusr) ||
			clang_CXCursorSet_contains(g_type_def, cusr) ||
			clang_CXCursorSet_contains(g_new_items, cusr) ||
			clang_CXCursorSet_contains(g_non_exported, cusr);
}

/*
 * A global func outside the main source, or an inside global.
 * We shouldn't keep their definitions or declarations(?).
 * But we do need to test if they were non-exported.
 */
static int check_global_func(CXCursor cusr, struct para_t *para)
{
	CXCursor def = clang_getCursorDefinition(cusr);
	if (clang_Cursor_isNull(def))
		def = cusr;

	if (clang_Cursor_isFunctionInlined(def) || is_found(def))
		return 0;

	const char *func_name = clang_getCString(clang_getCursorSpelling(def));
	switch (non_exported(para, func_name)) {
	case 1:
		output_klpsym_list(func_name, 0, para->mod);
		clang_CXCursorSet_insert(g_non_exported, def);
		break;
	case -1:
		return -1;
	default:
		break;
	}
	return 0;
}

/*
 * Determine a static function included or not.
 * Included means it is inlined, all code here, no KLP special.
 * Non-included means we need keep its prototype and access its
 * definition in the running kernel.
 *
 * If different compile units had same named non-included func,
 * we did can distinguish them, but compiling tool could not.
 * For now, leave this to klpmake to error out.
 */
static int check_local_func(CXCursor cusr, struct para_t *para, int is_func)
{
	const char *func_name = clang_getCString(clang_getCursorSpelling(cusr));

	if (is_found(cusr))
		return 0;

	int pos = non_included(para, func_name, is_func);
	switch (pos) {
	case -2:
		return -2;
	case -1:
		clang_CXCursorSet_insert(g_func_inlined, cusr);
		break;
	default:
		output_klpsym_list(func_name, pos, para->mod);
		if (is_func)
			clang_CXCursorSet_insert(g_non_included, cusr);
		else	/* put non-included static variable here */
			clang_CXCursorSet_insert(g_type_def, cusr);
		break;
	}
	return 0;
}

static int is_new_item(CXCursor cusr, struct para_t *para)
{
	const char *name = clang_getCString(clang_getCursorSpelling(cusr));
	int i;
	for (i = 0; i < para->new_count; i++)
		if (!strcmp(name, para->news[i]))
			break;
	return i != para->new_count;
}

static enum CXChildVisitResult find_used_recursive(CXCursor cusr,
                        CXCursor parent, CXClientData data)
{
    if (!is_in_main_src(cusr) || is_found(cusr))
        return CXChildVisit_Recurse;

    struct para_t *para = data;
    CXCursor def, decl;
    enum CXCursorKind kind = clang_getCursorKind(cusr);
    switch (kind) {
    case CXCursor_TypeRef:
        def = clang_getCursorDefinition(cusr);
        if (is_in_main_src(def)) {
	        clang_CXCursorSet_insert(g_type_def, def);
			if (clang_visitChildren(def, find_used_recursive, para))
				return CXChildVisit_Break;
        }
        break;
    case CXCursor_DeclRefExpr:
        decl = clang_getCursorReferenced(cusr);
        enum CXCursorKind refkind = clang_getCursorKind(decl);
		if ((clang_getCursorLinkage(decl) >= CXLinkage_Internal) && is_new_item(decl, para)) {
			clang_CXCursorSet_insert(g_new_items, decl);
			if (clang_visitChildren(decl, find_used_recursive, para))
				return CXChildVisit_Break;
        } else if (refkind == CXCursor_EnumConstantDecl) {
            decl = clang_getCursorSemanticParent(decl);
            def = clang_getCursorDefinition(decl);
    	    if (is_in_main_src(def)) {
        	    clang_CXCursorSet_insert(g_type_def, def);
            }
        } else if ((refkind == CXCursor_FunctionDecl) || (refkind==CXCursor_VarDecl)) {
            if (clang_Cursor_isNull(clang_getCursorDefinition(decl))) {	/* extern prototype */
                if (is_in_main_src(decl)) {
                    clang_CXCursorSet_insert(g_type_def, decl);
                }
                if (check_global_func(decl, para) == -1)
                    return CXChildVisit_Break;
					if (clang_visitChildren(decl, find_used_recursive, para))
						return CXChildVisit_Break;
            } else {        /* definition */
                def = clang_getCursorDefinition(decl);
				if (!clang_equalCursors(decl, def))	/* forward declaration */
					clang_CXCursorSet_insert(g_type_def, decl);
				if (clang_getCursorLinkage(def) == CXLinkage_External) {
                    if (check_global_func(def, para) == -1)
                        return CXChildVisit_Break;
                } else if (clang_getCursorLinkage(def) == CXLinkage_Internal) {
                    if (check_local_func(def, para, refkind == CXCursor_FunctionDecl) == -2)
                        return CXChildVisit_Break;
                }
				if (clang_visitChildren(def, find_used_recursive, para))
					return CXChildVisit_Break;
            }
        }
        break;
    default:
        break;
    }
    return CXChildVisit_Recurse;
}

/*
 * Find patched function definition on the top level of source,
 * then do recursive searching for used elements.
 */
static enum CXChildVisitResult find_used(CXCursor cusr,
			CXCursor parent, CXClientData data)
{
	struct para_t *para = data;

	if ((clang_getCursorKind(cusr) != CXCursor_FunctionDecl) ||
									!clang_isCursorDefinition(cusr))
		return CXChildVisit_Continue;

	const char *p = clang_getCString(clang_getCursorSpelling(cusr));
	for (int i = 0; i < para->func_count; i++) {
		if (strcmp(p, para->funcs[i]))
			continue;

		if(clang_visitChildren(cusr, find_used_recursive, para))
			return CXChildVisit_Break;
		/* save the patched func in 'inlined' set */
		clang_CXCursorSet_insert(g_func_inlined, cusr);
		/* verify the patched func and its position */
		if (clang_Cursor_getStorageClass(cusr) == CX_SC_Static) {
			para->pos[i] = non_included(para, p, 1);
			if (para->pos[i] < 0) {
				fprintf(stderr, ERROR_MSG_PREFIX"%s:%s inlined?\n", para->src, p);
				return CXChildVisit_Break;
			}
		} else {
			if (non_exported(para, p) < 0) {
				return CXChildVisit_Break;
			}
			para->pos[i] = 0;
		}
	}
	return CXChildVisit_Continue;
}

static void get_cursor_extent(CXCursor cusr, unsigned *start, unsigned *end)
{
	CXSourceRange r = clang_getCursorExtent(cusr);
	clang_getSpellingLocation(clang_getRangeStart(r), NULL, NULL, NULL, start);
	clang_getSpellingLocation(clang_getRangeEnd(r), NULL, NULL, NULL, end);
}

static void output_include(CXCursor cusr, struct para_t *para)
{
	unsigned start, end;
	char *s;
	get_cursor_extent(cusr, &start, &end);

	/* internal include replaced with absolute path */
	if ((s = memchr(g_srcbuf + start, '"', end - start))) {
		char *p, *q, *dir;
		dir = strdup(para->src);
		if ((p = strrchr(dir, '/')) == NULL)
			p = dir;
		*p = '\0';
		q = memrchr(g_srcbuf + start, '"', end - start);
		fprintf(para->fout, "#include \"%s/%s/", para->src_root, dir);
		fwrite(s + 1, 1, q - s, para->fout);
		free(dir);
	} else {
		fwrite(g_srcbuf + start, 1, end - start, para->fout);
	}
	fprintf(para->fout, "\n");
}

static void output_macro(CXCursor cusr, struct para_t *para)
{
	unsigned start, end;
	get_cursor_extent(cusr, &start, &end);

	fprintf(para->fout, "#define ");
	fwrite(g_srcbuf + start, 1, end - start, para->fout);
	fprintf(para->fout, "\n");
}

static void output_type_def(CXCursor cusr, struct para_t *para)
{
	unsigned start, end;
	get_cursor_extent(cusr, &start, &end);

	if (clang_getCursorKind(cusr) == CXCursor_VarDecl) {
		fprintf(para->fout, "extern %s %s;\n\n", clang_getCString(
			clang_getTypeSpelling(clang_getCursorType(cusr))),
			clang_getCString(clang_getCursorSpelling(cusr)));
	} else {
		fwrite(g_srcbuf + start, 1, end - start, para->fout);
		fprintf(para->fout, ";\n\n");
	}
}

static void output_new_items(CXCursor cusr, struct para_t *para)
{
	unsigned start, end;
	get_cursor_extent(cusr, &start, &end);

	fwrite(g_srcbuf + start, 1, end - start, para->fout);
	if (clang_getCursorKind(cusr) == CXCursor_VarDecl) {
		fprintf(para->fout, ";\n\n");
	} else {
		fprintf(para->fout, "\n\n");
	}
}

/*
 * Except the patched func, all others are local(static).
 * Remove all attributes to avoid side-effect.
 * The patched original func might be static, here let it
 * be extern as we separate sources to different compile
 * unit. If namespace conflict concerned, maybe could
 * mangle its name?
 *
 * Here also output patched func prototype to klp main src.
 */
static void output_func_prototype(CXCursor cusr, int is_patched, struct para_t *para)
{
	unsigned start, end;
	const char *name = clang_getCString(clang_getCursorSpelling(cusr));
	const char *ret_type = clang_getCString(clang_getTypeSpelling(
									clang_getCursorResultType(cusr)));
	get_cursor_extent(cusr, &start, &end);

	/* For patch module, the non-include static function is really an extern. */
	if (is_patched) {
		fprintf(para->fout, "%s %s%s", ret_type, PATCHED_FUNC_PREFIX, name);
		fprintf(para->fmain, "extern %s %s%s", ret_type, is_patched ? PATCHED_FUNC_PREFIX : "", name);
	} else {
		fprintf(para->fout, "static %s %s", ret_type, name);
	}

	char *p, *q;
	q = strstr(g_srcbuf + start, name);
	p = memchr(q, '(', end - start);	/* must succeed, size is trivial */
	q = memchr(p, ')', end - start);
	fwrite(p, 1, q - p + 1, para->fout);
	if (is_patched) {
		fwrite(p, 1, q - p + 1, para->fmain);
		fprintf(para->fmain, ";\n");
	}
}

static void output_func_body(CXCursor cusr, struct para_t *para)
{
	unsigned start, end;
	get_cursor_extent(cusr, &start, &end);

	int is_patched = 0;
	const char *func_name = clang_getCString(clang_getCursorSpelling(cusr));
	for (int i = 0; i < para->func_count; i++)
		if (!strcmp(func_name, para->funcs[i])) {
			is_patched = 1;
			break;
		}

	output_func_prototype(cusr, is_patched, para);
	while (*(g_srcbuf + start) != '{')
		start++;
	fprintf(para->fout, "\n");
	fwrite(g_srcbuf + start, 1, end - start, para->fout);
	fprintf(para->fout, "\n\n");
}

static void output_syscall(CXCursor cusr, struct para_t *para)
{
	const char *name = clang_getCString(clang_getCursorSpelling(cusr));
	char *buf, *p, *q;
	unsigned start, end;
	get_cursor_extent(cusr, &start, &end);

	fprintf(para->fout, "long %s%s(", PATCHED_FUNC_PREFIX, name);
	fprintf(para->fmain, "extern long %s%s(", PATCHED_FUNC_PREFIX, name);

	p = strchr(g_srcbuf + start, ',');
	q = strchr(g_srcbuf + start, ')');
	if (p == NULL) {	/* SYSCALL_DEFINE0 */
		fprintf(para->fout, "void)");
		fprintf(para->fmain, "void);\n");
	} else {
		buf = strndup(p + 1, q - p);
		p = buf;
		do {
			p = strchr(p + 1, ',');
			*p = ' ';
			do {
				p++;
			} while ((*p != ',') && (*p != ')'));
		} while (*p != ')');
		fprintf(para->fout, "%s", buf);
		fprintf(para->fmain, "%s;\n", buf);
		free(buf);
	}

	fwrite(q + 1, 1, g_srcbuf + end - q, para->fout);
	fprintf(para->fout, "\n");
}

/* only support CONFIG_LIVEPATCH_WO_FTRACE */
static int is_syscall(CXCursor cusr)
{
	return !strncmp(clang_getCString(clang_getCursorSpelling(cusr)),
							SYSCALL_PREFIX, SYSCALL_PREFIX_LEN);
}

static enum CXChildVisitResult output_cursors(CXCursor cusr,
			CXCursor parent, CXClientData para)
{
	int is_sys = is_syscall(cusr);

	if (!is_in_main_src(cusr) && !is_sys)
		return CXChildVisit_Continue;

	enum CXCursorKind kind = clang_getCursorKind(cusr);

	if (clang_CXCursorSet_contains(g_non_included, cusr)) {
		output_func_prototype(cusr, 0, para);
		fprintf(((struct para_t *)para)->fout, ";\n\n");
	} else if (clang_CXCursorSet_contains(g_func_inlined, cusr)) {
		if (is_sys)
			output_syscall(cusr, para);
		else
			output_func_body(cusr, para);
	} else if (clang_CXCursorSet_contains(g_type_def, cusr)) {
		output_type_def(cusr, para);
	} else if (clang_CXCursorSet_contains(g_new_items, cusr)) {
		output_new_items(cusr, para);
	} else if (kind == CXCursor_InclusionDirective) {
		output_include(cusr, para);
	} else if (kind == CXCursor_MacroDefinition) {
		output_macro(cusr, para);		/* forward type declaration */
	} else if (((kind == CXCursor_TypedefDecl) || (kind == CXCursor_StructDecl)
			|| (kind == CXCursor_UnionDecl) || (kind == CXCursor_EnumDecl))) {
		CXType ct = clang_getCursorType(cusr);
		CXCursor def = clang_getTypeDeclaration(ct);
		if (!clang_Cursor_isNull(def) && clang_CXCursorSet_contains(g_type_def, def))
			output_type_def(cusr, para);
	}

	return CXChildVisit_Continue;
}

#define COMPILER_OPTS 14
char arg[COMPILER_OPTS][MAX_ROOT_PATH];

static void put_in_compiler_opts(const char *args[], struct patch_t *patch)
{
	sprintf(arg[0], "-nostdinc");
	sprintf(arg[1], "-I%s/%s/include", patch->dev_root, ARCH_PATH);
	sprintf(arg[2], "-I%s/%s/include/generated", patch->dev_root, ARCH_PATH);
	sprintf(arg[3], "-I%s/include", patch->dev_root);
	sprintf(arg[4], "-I%s/%s/include/uapi", patch->dev_root, ARCH_PATH);
	sprintf(arg[5], "-I%s/%s/include/generated/uapi", patch->dev_root, ARCH_PATH);
	sprintf(arg[6], "-I%s/include/uapi", patch->dev_root);
	sprintf(arg[7], "-I%s/include/generated/uapi", patch->dev_root);
	sprintf(arg[8], "-include %s/include/linux/kconfig.h", patch->dev_root);
	sprintf(arg[9], "-include %s/include/linux/compiler_types.h", patch->dev_root);
	sprintf(arg[10], "-D__KERNEL__");
	sprintf(arg[11], "-std=gnu11");
	sprintf(arg[12], "-DMODULE");

	for (int i = 0; i < COMPILER_OPTS; i++)
		args[i] = arg[i];

/*
gcc -Wp,-MMD,/root/kpatch-example/klp/example/netlink/.af_netlink.o.d
-DCC_USING_PATCHABLE_FUNCTION_ENTRY -fmacro-prefix-map=./= -Wall -Wundef -Werror=strict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -fshort-wchar -fno-PIE
-Werror=implicit-function-declaration -Werror=implicit-int -Werror=return-type -Wno-format-security -funsigned-char
-mabi=lp64 -march=rv64imac_zicsr_zifencei_zihintpause -mno-save-restore -DCONFIG_PAGE_OFFSET=0xff60000000000000 -mcmodel=medany -fno-omit-frame-pointer
-fno-asynchronous-unwind-tables -fno-unwind-tables -mno-riscv-attribute -Wa,-mno-arch-attr -mstrict-align -fno-delete-null-pointer-checks -Wno-frame-address
-Wno-format-truncation -Wno-format-overflow -Wno-address-of-packed-member -O2 -fno-allow-store-data-races -Wframe-larger-than=2048 -fstack-protector-strong -Wno-main
-Wno-unused-but-set-variable -Wno-unused-const-variable -Wno-dangling-pointer -fno-omit-frame-pointer -fno-optimize-sibling-calls -fno-stack-clash-protection
-fpatchable-function-entry=4 -fno-inline-functions-called-once -Wdeclaration-after-statement -Wvla -Wno-pointer-sign -Wcast-function-type -Wno-stringop-truncation
-Wno-stringop-overflow -Wno-restrict -Wno-maybe-uninitialized -Wno-array-bounds -Wno-alloc-size-larger-than -Wimplicit-fallthrough=5 -fno-strict-overflow -fno-stack-check
-fconserve-stack -Werror=date-time -Werror=incompatible-pointer-types -Werror=designated-init -Wno-packed-not-aligned -g -gdwarf-4 -mstack-protector-guard=tls
-mstack-protector-guard-reg=tp -mstack-protector-guard-offset=1432   -mno-relax  -DKBUILD_BASENAME='"af_netlink"' -DKBUILD_MODNAME='"netlinkfix"'
-D__KBUILD_MODNAME=kmod_netlinkfix -c -o /root/kpatch-example/klp/example/netlink/af_netlink.o /root/kpatch-example/klp/example/netlink/af_netlink.c
*/
}

int main(int argc, char *argv[])
{
	if (argc != 2) {
		printf("Usage: $0 patch-module-name\n");
		return 0;
	}

	/* prepare parameters */
	struct patch_t patch;
	if (parse_arguments(&patch) == -1)
		return -1;
	const char *args[COMPILER_OPTS];
	put_in_compiler_opts(args, &patch);

	CXIndex index;
	CXTranslationUnit unit;
	CXCursor cursor;
	CXFile sfile;
	struct para_t para = {0};
	char *f, output[256];
	int ret = 0;

	/* prepare klp module main source */
	para.fmain = fopen(KLP_MAIN_SRC, "w");
	if (para.fmain == NULL) {
		perror(ERROR_MSG_PREFIX"open "KLP_MAIN_SRC);
		return -2;
	}
	begin_main_src(para.fmain);

	for (int i = 0; i < patch.mod_count; i++) {
		/* prepare ksympos for every module */
		para.src_root = patch.src_root;
		para.debug_root = patch.debug_root;
		para.mod = patch.mods[i].mod_name;
		if (begin_mod_ksympos(&para, patch.mods[i].srcs, patch.mods[i].src_count) < 0) {
			ret = -1;
			goto OUT;
		}

		for (int j = 0; j < patch.mods[i].src_count; j++) {
			/* prepare parsing for every source */
			para.src = patch.mods[i].srcs[j].src_name;
			para.src_idx = j;
			f = strrchr(para.src, '/');
			if (!f)
				f = para.src;
			else
				f++;
			snprintf(arg[COMPILER_OPTS - 1], strlen(patch.src_root) + 3 + f - para.src, "-I%s/%s", patch.src_root, para.src);
			index = clang_createIndex(0, 1);
			unit = clang_parseTranslationUnit(index, f, args, COMPILER_OPTS, NULL, 0,
						CXTranslationUnit_DetailedPreprocessingRecord);
			if (unit == NULL) {
				fprintf(stderr, ERROR_MSG_PREFIX"unable to parse %s\n",para.src);
				clang_disposeIndex(index);
				ret = -1;
				goto OUT;
			}
			g_func_inlined = clang_createCXCursorSet();
			g_non_included = clang_createCXCursorSet();
			g_type_def = clang_createCXCursorSet();
			g_new_items = clang_createCXCursorSet();
			g_non_exported = clang_createCXCursorSet();
			cursor = clang_getTranslationUnitCursor(unit);

			/*
			 * Recursively walkthrough patched funcs and their callees to
			 * find all used elements, functions, type def, etc.
			 */
			para.func_count = patch.mods[i].srcs[j].func_count;
			for (int k = 0; k < patch.mods[i].srcs[j].func_count; k++)
				para.funcs[k] = patch.mods[i].srcs[j].funcs[k];
			para.new_count = patch.mods[i].srcs[j].new_count;
			for (int k = 0; k < patch.mods[i].srcs[j].new_count; k++)
				para.news[k] = patch.mods[i].srcs[j].news[k];
			para.pos = patch.mods[i].srcs[j].pos;
			if (clang_visitChildren(cursor, find_used, &para)) {
				ret = -1;
				goto OUT;// bad cleanup???????????
			}

			/* output klp source */
			sfile = clang_getFile(unit, f);
			g_srcbuf = clang_getFileContents(unit, sfile, NULL);
			sprintf(output, "%s.%s", f, KLPSRC_SUFFIX);
			if ((para.fout = fopen(output, "w")) == NULL) {
				perror(ERROR_MSG_PREFIX"fopen for write source");
				ret = -1;
				goto OUT;
			}
			clang_visitChildren(cursor, output_cursors, &para);
			fclose(para.fout);

			/* cleanup */
			clang_disposeCXCursorSet(g_non_exported);
			clang_disposeCXCursorSet(g_new_items);
			clang_disposeCXCursorSet(g_type_def);
			clang_disposeCXCursorSet(g_non_included);
			clang_disposeCXCursorSet(g_func_inlined);
			clang_disposeTranslationUnit(unit);
			clang_disposeIndex(index);
		}
		end_mod_ksympos(&para, patch.mods[i].srcs, patch.mods[i].src_count, 0);
	}

	end_main_src(para.fmain, &patch);
	gen_makefile(&patch, argv[1]);
OUT:
	fclose(para.fmain);
	end_mod_ksympos(&para, NULL, 0, 1);
	return ret;
}
