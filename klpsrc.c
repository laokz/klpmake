/*
 * Klpsrc is part of klpmake. It generates livepatch source through
 * abbreviating patched source, and generates KLPSYM position info.
 *
 * Patched source top level entities:
 * include                  keep
 * macro                    keep
 * type def, forward decl   keep used
 * var                      keep used declaration, remove attribute
 *                          non-support function inner static
 * func                     keep used, remove attribute
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
#include <sys/utsname.h>
#include "klpsrc.h"

/* arguments to clang parsing frontend */
#define COMPILER_OPTS 15
#if defined(__aarch64__)
#define ARCH_PATH "arch/arm64"
#elif defined(__riscv) && (__riscv_xlen == 64)
#define ARCH_PATH "arch/riscv"
#elif defined(__x86_64__)
#define ARCH_PATH "arch/x86"
#else
#error "unsupported architecture"
#endif
static char arg[COMPILER_OPTS][MAX_ROOT_PATH];

#define KLPSYM_LIST "./_klpmake.syms"
/*
 * For syscall, now only support CONFIG_LIVEPATCH_WO_FTRACE
 * livepatch mechanism
 */
#define SYSCALL_PREFIX "__do_sys_"
#define SYSCALL_PREFIX_LEN 9

/*
 * These CXCursorSets are disjoint and might contain out-of-main
 * source entities. Only in-main entities been output.
 */

/*
 * Funcs only: non-included local, weak global functions.
 * Keep prototype, remove attributes.
 */
static CXCursorSet g_non_included;
/*
 * Inlined local and patched funcs, new var/funcs.
 * Keep all the body.
 *
 * For now keep them in the same set. Would there be any attributes of
 * inlined functions might do bad?
 */
static CXCursorSet g_func_inlined;
/*
 * Declarations only: type def, forward, extern and
 * non-included local variable declarations.
 * Keep all the body, except variable linkage change
 * to extern and remove attributes.
 */
static CXCursorSet g_type_def;

/*
 * Non-exported global functions/variables.
 * Only for avoiding duplicate in KLPSYM_LIST.
 */
static CXCursorSet g_non_exported;
/*
 * Already visited cursors.
 * Only for avoiding dead loop.
 */
static CXCursorSet g_visited;

/* whether output debug log */
int g_debug = 0;

/* Patched source file buffer, for output */
static const char *g_srcbuf;

static int is_in_main_src(CXCursor cusr)
{
    if (clang_Cursor_isNull(cusr))
        return 0;

    CXSourceLocation loc = clang_getCursorLocation(cusr);
    return clang_Location_isFromMainFile(loc);
}

static void output_klpsym_list(const char *sym, int pos, char *mod)
{
    char buf[256];
    int n;
    n = snprintf(buf, 256, "echo %s %d %s >>"KLPSYM_LIST, sym, pos, mod);
    if (n >= 256)   /* nearly never? */
        fprintf(stderr, "ERROR: command line too long: %s\n", buf);
    system(buf);
}

/* insert into visited set and test if already in there */
static inline int is_visited(CXCursor cusr)
{
    return clang_CXCursorSet_insert(g_visited, cusr) == 0;
}

static int is_patched_func_str(char *name, struct para_t *para)
{
    for (int i = 0; i < para->func_count; i++)
        if (!strcmp(name, para->funcs[i]))
            return 1;

    return 0;
}

static int is_patched_func(CXCursor cusr, struct para_t *para)
{
    int ret;
    CXString string = clang_getCursorSpelling(cusr);
    const char *p = clang_getCString(string);

    ret = is_patched_func_str(name, para);

    clang_disposeString(string);
    return ret;
}

/*
 * Check a global is exported or not, or a new one.
 * return 1 indicate need to recursively visit function's body,
 * otherwise only need to visit function's arguments.
 */
static int check_global(CXCursor cusr, struct para_t *para, int is_var)
{
    CXCursor def = clang_getCursorDefinition(cusr);
    if (clang_Cursor_isNull(def))
        def = cusr;
    /* changed function left to `find_used` */
    else if (!is_var && is_patched_func(cusr, para))
        return 0;

    if (is_visited(def))
        return 0;

    int ret = 0;
    CXString string = clang_getCursorSpelling(def);
    const char *name = clang_getCString(string);
    int result = non_exported(para, name);
    switch (result) {
    case KLPSYM_NON_EXPORTED:
        /* global symbol position always be 0 -- unique */
        output_klpsym_list(name, 0, para->mod);
        clang_CXCursorSet_insert(g_non_exported, def);
        break;

    case KLPSYM_WEAK:
        /*
         * For kallsyms weak symbol, we need its position information,
         * also need its prototype because the arch not define strong
         * implementation or declaration.
         */
        output_klpsym_list(name, 0, para->mod);
        clang_CXCursorSet_insert(g_non_included, cusr);
        break;

    case KLPSYM_NOT_FOUND:  /* must be new var/func */
        clang_CXCursorSet_insert(g_func_inlined, cusr);
        if (!is_var)
            ret = 1;
        break;

    default:    /* KLPSYM_EXPORTED */
        break;
    }
    log_debug("check global: %s, result: %d\n", name, result);
    clang_disposeString(string);
    return ret;
}

/*
 * Return variable defined scope in patched source, either file scope which
 * return NULL, or function scope which return function name(strdup).
 */
static char* get_var_scope(CXCursor cusr)
{
    CXCursor parent = cusr;
    CXType type;
    CXString scope;
    char *p;

    /* must not dead loop */
    while (1) {
        parent = clang_getCursorSemanticParent(parent);
        type = clang_getCursorType(parent);
        if (type.kind == CXCursor_FunctionDecl) {
            scope = clang_getCursorDisplayName(parent);
            p = strdup(clang_getCString(scope));
            clang_disposeString(scope);
            break;
        } else if (clang_isTranslationUnit(parent.kind)) {
            p = NULL;
            break;
        }
    }

    return p;
}

/* used for query static var/func defined location in original source */
struct orig_static_t {
    const char *name;               /* static identifier */
    CXSourceLocation *loc;          /* save its location*/
    int is_var;                     /* var or func */
    enum CXChildVisitResult ret;    /* sibling or recursively visit */
};

static enum CXChildVisitResult query_orig_static_loc(CXCursor cusr,
                                    CXCursor parent, CXClientData data)
{
    struct orig_static_t *id = data;
    if (id->is_var && (cusr.kind != CXCursor_VarDecl) ||
        !id->is_var && (cusr.kind != CXCursor_FunctionDecl) ||
        !clang_isCursorDefinition(cusr) ||
        (clang_getCursorLinkage(cusr) != CXLinkage_Internal)) {
        return id->ret;
    }

    CXString string = clang_getCursorSpelling(cusr);
    const char *p = clang_getCString(string);
    if (!strcmp(id->name, p)) {
        *id->loc = clang_getCursorLocation(cusr);
        clang_disposeString(string);
        return CXChildVisit_Break;
    }
    clang_disposeString(string);
    return id->ret;
}

/* return static var/func definition line number in original source */
static int get_orig_lineno(const char *scope, const char *name,
                            struct para_t *para, int is_var)
{
    CXSourceLocation loc = clang_getNullLocation();
    int lineno;
    struct orig_static_t id = { .loc = &loc };

    CXCursor cursor = clang_getTranslationUnitCursor(para->old_tu);
    if (scope) {
        id.name = scope;
        id.is_var = 0;
        id.ret = CXChildVisit_Continue;
        clang_visitChildren(cursor, query_orig_static_loc, &id);
        /*
         * Not found variable's containing function in original source.
         * The variable and its function must be newly defined.
         */
        if (clang_equalLocations(loc, clang_getNullLocation()))
            return 0;
        cursor = clang_getCursor(para->old_tu, loc);
        loc = clang_getNullLocation();
        id.name = name;
        id.is_var = 1;
        id.ret = CXChildVisit_Recurse;
        clang_visitChildren(cursor, query_orig_static_loc, &id);
    } else {
        id.name = name;
        id.is_var = is_var;
        id.ret = CXChildVisit_Continue;
        clang_visitChildren(cursor, query_orig_static_loc, &id);
    }

    if (clang_equalLocations(loc, clang_getNullLocation()))
        return 0;
    clang_getSpellingLocation(loc, NULL, &lineno, NULL, NULL);
    return lineno;
}

/*
 * Check a local definition is included(inlined) or not, or a new one.
 * Return 1 indicate need to recursively visit function's body,
 * -1 error, otherwise only need to visit function's arguments.
 *
 * Not support different compile units access different non-included
 * same-named symbols. For now, leave this to klpmake to error out.
 */
static int check_local(CXCursor cusr, struct para_t *para, int is_var)
{
    if (is_visited(cusr) || (!is_var && is_patched_func(cusr, para)))
        return 0;

    CXString string = clang_getCursorSpelling(cusr);
    const char *name = clang_getCString(string);
    char *scope = is_var ? get_var_scope(cusr) : NULL;
    int orig_lineno;
    int ret, pos;

    ret = is_in_main_src(cusr);
    if (ret)
        orig_lineno = get_orig_lineno(scope, name, para, is_var);
    if (!ret && is_var ||           /* static variable defined in headers */
         ret && is_var && scope && orig_lineno) {           /* in function */
        fprintf(stderr, "WARNING: static variable %s defined in header or"
                    " in function, will be treated as new variable\n", name);
        /* they will be auto-output along with include or function */
        ret = 0;
        goto out;
    }

    /* header defined function or new var/func */
    if (!ret || (orig_lineno == 0)) {
        clang_CXCursorSet_insert(g_func_inlined, cusr);
        if (ret)
            log_debug("new local %s: %s\n", is_var ? "variable" : "function", name);
        if (!is_var)
            ret = 1;
        goto out;
    }

    ret = 0;
    pos = non_included(para, name, is_var, scope, orig_lineno);
    switch (pos) {
    case KLPSYM_ERROR:
        ret = -1;
        break;

    case KLPSYM_NOT_FOUND:
        /*
         * Static variable defined in inlined function should
         * be kept as KLPSYMs because they are not changed
         * intentionally by the user(for patched function it
         * be treated as new now)???
         *
         * They are mostly KLPSYM_NOT_FOUND due to gcc mangling
         * their name to name.123.
         *
         * That is, if the 'scope' -- the inlined function which
         * already been in g_func_inlined, is not a patched func,
         * we should not put the static variable in this set again.
         * Instead, we should put them in a specific set, and in
         * later output, replace their definitions to extern
         * declarations.
         */
        if (scope && !is_patched_func_str(scope, para)) {
            fprintf(stderr, "ERROR: not support function scope static definition"
                                " %s:%s\n", scope, name);
            ret = -1;
            break;
        }

        clang_CXCursorSet_insert(g_func_inlined, cusr);
        if (!is_var)
            ret = 1;
        break;

    default:    /* >= 0, position */
        output_klpsym_list(name, pos, para->mod);
        if (is_var)
            clang_CXCursorSet_insert(g_type_def, cusr);
        else
            clang_CXCursorSet_insert(g_non_included, cusr);
        break;
    }
    log_debug("check local: %s, result: %d\n", name, pos);

out:
    clang_disposeString(string);
    free(scope);
    return ret;
}

static enum CXChildVisitResult find_used_recursive(CXCursor cusr,
                        CXCursor parent, CXClientData data);

/* find used type definition and put in if defined in main source */
static int find_used_type(CXCursor cusr, struct para_t *para)
{
    CXCursor def = clang_getCursorDefinition(cusr);

    if (is_in_main_src(def)) {
        log_debug("visit TypeRef->definition: %s\n",
                clang_getCString(clang_getCursorDisplayName(def)));
        clang_CXCursorSet_insert(g_type_def, def);
        /*
         * It may use other type-defs. If we didn't visit them now,
         * that might leave an incomplete type.
         */
        if (clang_visitChildren(def, find_used_recursive, para))
            return 1;
    }
    return 0;
}

/* find used enum type definition according to enumerator reference */
static void find_used_enum_type(CXCursor cusr)
{
    CXCursor def, decl;

    decl = clang_getCursorSemanticParent(cusr);
    def = clang_getCursorDefinition(decl);
    if (is_in_main_src(def)) {
        log_debug("visit DeclRefExpr->EnumConstantDecl->enum definition: %s\n",
                clang_getCString(clang_getCursorDisplayName(def)));
        clang_CXCursorSet_insert(g_type_def, def);
    }
}

static int find_used_varfunc(CXCursor cusr, struct para_t *para, int is_var)
{
    CXCursor def = clang_getCursorDefinition(cusr);

    /* reference to an extern func/var */
    if (clang_Cursor_isNull(def)) {
        if (is_in_main_src(cusr)) { /* extern prototype */
            log_debug("visit DeclRefExpr->Func/VarDecl->extern prototype: %s\n",
                clang_getCString(clang_getCursorDisplayName(cusr)));
            clang_CXCursorSet_insert(g_type_def, cusr);
        }
        (void)check_global(cusr, para, is_var);
        return 0;
    }

    /* reference to a self or headers defined func/var */
    int visit_body;
    if (!clang_equalCursors(cusr, def))    /* forward func declaration */
        clang_CXCursorSet_insert(g_type_def, cusr);
    if (clang_getCursorLinkage(def) == CXLinkage_External) {
        visit_body = check_global(def, para, is_var);
    } else if (clang_getCursorLinkage(def) == CXLinkage_Internal) {
        visit_body = check_local(def, para, is_var);
        if (visit_body == -1)
            return 1;
    }
    if (visit_body == 1) {
        if (clang_visitChildren(def, find_used_recursive, para))
            return 1;
    }

    return 0;
}

/*
 * Due to macro expansion and include, the cursor might be out
 * of the main source, but its body might be in, or its referencee
 * might be KLPSYMs. So here we must visit it even it's out of
 * the main source.
 *
 * And, if the macro defined a static variable outside, broken?!
 * such as printk_once() defined
 * `static bool __section(".data.once") __already_done`
 * in include/linux/once_lite.h.
 */
static enum CXChildVisitResult find_used_recursive(CXCursor cusr,
                        CXCursor parent, CXClientData data)
{
    if (is_visited(cusr))
        return CXChildVisit_Continue;

    struct para_t *para = data;
    CXCursor decl;
    enum CXCursorKind kind = clang_getCursorKind(cusr);
    switch (kind) {
    case CXCursor_TypeRef:
        if (find_used_type(cusr, para))
            return CXChildVisit_Break;
        break;

    case CXCursor_DeclRefExpr:
        decl = clang_getCursorReferenced(cusr);
        enum CXCursorKind refkind = clang_getCursorKind(decl);
        if (refkind == CXCursor_EnumConstantDecl) {
            find_used_enum_type(decl);
        } else if ((refkind == CXCursor_FunctionDecl) ||
                   (refkind == CXCursor_VarDecl)) {
            if (find_used_varfunc(decl, para, refkind == CXCursor_VarDecl))
                return CXChildVisit_Break;
        }
        break;

    default:
        break;
    }
    return CXChildVisit_Recurse;
}

/*
 * Find patched functions definition on the top level of source,
 * then do recursive searching for used entities for everyone.
 */
static enum CXChildVisitResult find_used(CXCursor cusr,
            CXCursor parent, CXClientData data)
{
    struct para_t *para = data;
    enum CXChildVisitResult ret = CXChildVisit_Continue;

    if ((clang_getCursorKind(cusr) != CXCursor_FunctionDecl) ||
                                    !clang_isCursorDefinition(cusr))
        return CXChildVisit_Continue;

    CXString string = clang_getCursorSpelling(cusr);
    const char *p = clang_getCString(string);
    for (int i = 0; i < para->func_count; i++) {
        if (strcmp(p, para->funcs[i]))
            continue;

        if (clang_Cursor_isVariadic(cusr)) {
            fprintf(stderr, "ERROR: not support variadic function %s:%s\n",
                                                     para->src, p);
            ret = CXChildVisit_Break;
            goto out;
        }

        if(clang_visitChildren(cusr, find_used_recursive, para)) {
            ret = CXChildVisit_Break;
            goto out;
        }

        clang_CXCursorSet_insert(g_func_inlined, cusr);
        /* verify the patched func and its position */
        if (clang_Cursor_getStorageClass(cusr) == CX_SC_Static) {
            para->pos[i] = non_included(para, p, 0, NULL,
                                    get_orig_lineno(NULL, p, para, 0));
            if (para->pos[i] < 0) { /* KLPSYM_NOT_FOUND or KLPSYM_ERROR */
                fprintf(stderr, "ERROR: finding %s:%s\n", para->src, p);
                ret = CXChildVisit_Break;
                goto out;
            }
        } else {
            if (non_exported(para, p) == KLPSYM_NOT_FOUND) {
                fprintf(stderr, "ERROR: not found %s in kallsyms\n", p);
                ret = CXChildVisit_Break;
                goto out;
            }
            para->pos[i] = 0;
        }
    }

out:
    clang_disposeString(string);
    return ret;
}

/* get cursor corresponding source code range */
static void get_cursor_body(CXCursor cusr, unsigned *start, unsigned *end)
{
    CXSourceRange r = clang_getCursorExtent(cusr);
    clang_getSpellingLocation(clang_getRangeStart(r), NULL, NULL, NULL, start);
    clang_getSpellingLocation(clang_getRangeEnd(r), NULL, NULL, NULL, end);
}

static void output_include(CXCursor cusr, struct para_t *para)
{
    unsigned start, end;
    char *s;
    get_cursor_body(cusr, &start, &end);

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
    get_cursor_body(cusr, &start, &end);

    /* macro's cursor body doesn't contain "#define" */
    fprintf(para->fout, "#define ");
    fwrite(g_srcbuf + start, 1, end - start, para->fout);
    fprintf(para->fout, "\n");
}

static void output_type_def(CXCursor cusr, struct para_t *para)
{
    unsigned start, end;
    get_cursor_body(cusr, &start, &end);

    if (clang_getCursorKind(cusr) == CXCursor_VarDecl) {
        /*
         * For variable declaration, we must use "extern", remove any
         * attributes and initializer to avoid unintended side-effect.
         */
        CXString id = clang_getCursorSpelling(cusr);
        CXType ty = clang_getCursorType(cusr);
        int is_array = (ty.kind ==  CXType_VariableArray) ||
                       (ty.kind == CXType_ConstantArray);
        if (is_array)
            ty = clang_getArrayElementType(ty);
        CXString type = clang_getTypeSpelling(ty);
        fprintf(para->fout, "extern %s %s%s;\n\n", clang_getCString(type),
                                clang_getCString(id), is_array ? "[]" : "");
        clang_disposeString(type);
        clang_disposeString(id);
    } else {
        fwrite(g_srcbuf + start, 1, end - start, para->fout);
        fprintf(para->fout, ";\n\n");
    }
}

/*
 * Except the patched and weak func, all others are local(static).
 * Remove all attributes to avoid side-effect.
 */
static void output_func_prototype(CXCursor cusr, struct para_t *para,
                                                        int is_patched)
{
    CXString id = clang_getCursorSpelling(cusr);
    CXString type = clang_getTypeSpelling(clang_getCursorResultType(cusr));
    const char *name = clang_getCString(id);
    const char *ret_type = clang_getCString(type);
    unsigned start, end;
    get_cursor_body(cusr, &start, &end);

    if (is_patched) {
        /*
         * Keep patched func original linkage even it is external.
         * It seems linker could auto translate it to local symbol type
         * to avoid global namespace pollution?
         */
        fprintf(para->fout, "%s%s %s",
            clang_getCursorLinkage(cusr) == CXLinkage_Internal ? "static " : "",
            ret_type, name);
    } else {
        /*
         * Non-include local is really an extern because
         * the actual symbol is in the running kernel.
         */
        fprintf(para->fout, "extern %s %s", ret_type, name);
    }

    /*
     * There must no attributes between function name and '(', right?
     * Not support parameters have attributes yet.
     */
    char *p, *q;
    q = strstr(g_srcbuf + start, name);
    p = strchr(q, '(');
    q = strchr(p, ')');
    fwrite(p, 1, q - p + 1, para->fout);

    clang_disposeString(type);
    clang_disposeString(id);
}

/*
 * There might be multiple patched funcs and they might call each other.
 * Keep the patched func names untouched so keep the calling logic.
 * Add wrappers to each of them for `struct klp_func`.
 *
 * All wrappers set to `extern` linkage because we separate sources
 * to different compile units. If namespace conflicts still concerned,
 * maybe could mangle the name?
 *
 * Here also output wrappers prototype to klp main src.
 */
static void output_patched_wrapper(CXCursor cusr, struct para_t *para)
{
    CXString func = clang_getCursorSpelling(cusr);
    CXType ret_ty = clang_getCursorResultType(cusr);
    int is_ret_void = ret_ty.kind == CXType_Void;
    CXString type = clang_getTypeSpelling(ret_ty);
    const char *func_name = clang_getCString(func);
    const char *type_name = clang_getCString(type);

    /* declaration */
    fprintf(para->fout, "%s %s%s(", type_name, PATCHED_FUNC_PREFIX, func_name);
    fprintf(para->fmain, "extern %s %s%s(", type_name, PATCHED_FUNC_PREFIX,
                                                                func_name);
    clang_disposeString(type);
    int n = clang_Cursor_getNumArguments(cusr);
    if (n == 0) {
        fprintf(para->fout, "void)\n{\n\t%s%s();}\n", is_ret_void ?
                                        "" : "return ", func_name);
        fprintf(para->fmain, "void);\n");
        clang_disposeString(func);
        return;
    }

    /* body */
    CXString *args = malloc(n * sizeof(CXString));
    if (!args) {
        perror("malloc");
        clang_disposeString(func);
        return;
    }
    CXCursor arg_cusr;
    const char *name;
    for (int i = 0; i < n; i++) {
        arg_cusr = clang_Cursor_getArgument(cusr, i);
        args[i] = clang_getCursorSpelling(arg_cusr);
        name = clang_getCString(args[i]);
        type = clang_getTypeSpelling(clang_getCursorType(arg_cusr));
        type_name = clang_getCString(type);
        fprintf(para->fout, "%s%s %s", i ? ", " : "", type_name, name);
        fprintf(para->fmain, "%s%s %s", i ? ", " : "", type_name, name);
        clang_disposeString(type);
    }
    fprintf(para->fout, ")\n{\n\t%s%s(", is_ret_void ? "" : "return ", func_name);
    for (int i = 0; i < n; i++) {
        fprintf(para->fout, "%s%s", i ? ", " : "", clang_getCString(args[i]));
        clang_disposeString(args[i]);
    }
    fprintf(para->fout, ");\n}\n\n");
    fprintf(para->fmain, ");\n");
    free(args);
    clang_disposeString(func);
}

/* output all the body, including var initializer */
static void output_inlined(CXCursor cusr, struct para_t *para)
{
    unsigned start, end;
    get_cursor_body(cusr, &start, &end);

    int is_patched = is_patched_func(cusr, para);

    if (is_patched) {
        output_func_prototype(cusr, para, is_patched);
        while (*(g_srcbuf + start) != '{')
            start++;
        fprintf(para->fout, "\n");
        fwrite(g_srcbuf + start, 1, end - start, para->fout);
        fprintf(para->fout, "\n\n");
        output_patched_wrapper(cusr, para);
    } else {
        fwrite(g_srcbuf + start, 1, end - start, para->fout);
        if (clang_getCursorKind(cusr) == CXCursor_VarDecl)
            fprintf(para->fout,";");
        fprintf(para->fout,"\n\n");
    }
}

static void output_syscall(CXCursor cusr, struct para_t *para)
{
    CXString id = clang_getCursorSpelling(cusr);
    const char *name = clang_getCString(id);
    char *buf, *p, *q;
    unsigned start, end;
    get_cursor_body(cusr, &start, &end);

    fprintf(para->fout, "long %s%s(", PATCHED_FUNC_PREFIX, name);
    fprintf(para->fmain, "extern long %s%s(", PATCHED_FUNC_PREFIX, name);

    p = strchr(g_srcbuf + start, ',');
    q = strchr(g_srcbuf + start, ')');
    if (p == NULL) {    /* SYSCALL_DEFINE0 */
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
    clang_disposeString(id);
}

static int is_syscall(CXCursor cusr)
{
    CXString id = clang_getCursorSpelling(cusr);
    int ret = !strncmp(clang_getCString(id), SYSCALL_PREFIX, SYSCALL_PREFIX_LEN);
    clang_disposeString(id);
    return ret;
}

static enum CXChildVisitResult output_cursors(CXCursor cusr,
            CXCursor parent, CXClientData para)
{
    int is_sys = is_syscall(cusr);

    /* syscall begin with macro which is out of main src */
    if (!is_in_main_src(cusr) && !is_sys)
        return CXChildVisit_Continue;

    enum CXCursorKind kind = clang_getCursorKind(cusr);

    if (clang_CXCursorSet_contains(g_non_included, cusr)) {
        output_func_prototype(cusr, para, 0);
        fprintf(((struct para_t *)para)->fout, ";\n\n");
    } else if (clang_CXCursorSet_contains(g_func_inlined, cusr)) {
        if (is_sys)
            output_syscall(cusr, para);
        else
            output_inlined(cusr, para);
    } else if (clang_CXCursorSet_contains(g_type_def, cusr)) {
        output_type_def(cusr, para);
    } else if (kind == CXCursor_InclusionDirective) {
        output_include(cusr, para);
    } else if (kind == CXCursor_MacroDefinition) {
        output_macro(cusr, para);               /* forward type declaration */
    } else if (((kind == CXCursor_TypedefDecl) || (kind == CXCursor_StructDecl)
            || (kind == CXCursor_UnionDecl) || (kind == CXCursor_EnumDecl))) {
        CXType ct = clang_getCursorType(cusr);
        CXCursor def = clang_getTypeDeclaration(ct);
        if (!clang_Cursor_isNull(def) &&
                            clang_CXCursorSet_contains(g_type_def, def)) {
            /* output the forward declaration itself */
            output_type_def(cusr, para);
        }
    }

    return CXChildVisit_Continue;
}

/* the opts came from `make V=1 modules` output */
static void fill_compiler_opts(const char *args[], char *mod)
{
    struct utsname u;
    (void)uname(&u);

    sprintf(arg[0], "-nostdinc");
    sprintf(arg[1], "-I"KERNEL_DEV_ROOT"%s/include", u.release, ARCH_PATH);
    sprintf(arg[2], "-I"KERNEL_DEV_ROOT"%s/include/generated", u.release, ARCH_PATH);
    sprintf(arg[3], "-I"KERNEL_DEV_ROOT"include", u.release);
    sprintf(arg[4], "-I"KERNEL_DEV_ROOT"%s/include/uapi", u.release, ARCH_PATH);
    sprintf(arg[5], "-I"KERNEL_DEV_ROOT"%s/include/generated/uapi", u.release, ARCH_PATH);
    sprintf(arg[6], "-I"KERNEL_DEV_ROOT"include/uapi", u.release);
    sprintf(arg[7], "-I"KERNEL_DEV_ROOT"include/generated/uapi", u.release);
    /* Clang15 think the blank between -include and KERNEL_DEV_ROOT significant?! */
    sprintf(arg[8], "-include"KERNEL_DEV_ROOT"include/linux/kconfig.h", u.release);
    sprintf(arg[9], "-include"KERNEL_DEV_ROOT"include/linux/compiler_types.h", u.release);
    sprintf(arg[10], "-D__KERNEL__");
    sprintf(arg[11], "-std=gnu11");
    sprintf(arg[12], "-DMODULE");
    sprintf(arg[13], "-DKBUILD_MODNAME=\"%s\"", mod);
    /* the last one is left for internal headers' path */

    for (int i = 0; i < COMPILER_OPTS; i++)
        args[i] = arg[i];
}

/* return pointer to source basename */
static char *fill_last_compiler_opts(char *root, char *src)
{
    char *f = strrchr(src, '/');
    if (!f)
        f = src;
    else
        f++;

    int maxlen = strlen(root) + 3 + f - src;
    if (maxlen > MAX_ROOT_PATH) {
        fprintf(stderr, "ERROR: internal header path been too long: %d\n", maxlen);
        f = NULL;
    } else {
        snprintf(arg[COMPILER_OPTS - 1], maxlen, "-I%s/%s", root, src);
    }
    return f;
}

/*
 * We have two translation units at the same time.
 * One for patched source, the main part, e.g. index, unit, g_...
 * Another for original source, temporarily used, e.g. para->old_...
 */
static int parse_ast(char *src, const char *args[], CXIndex *index,
                                    CXTranslationUnit *unit)
{
    *index = clang_createIndex(0, 1);
    *unit = clang_parseTranslationUnit(*index, src, args, COMPILER_OPTS, NULL,
                     0, CXTranslationUnit_DetailedPreprocessingRecord |
						CXTranslationUnit_KeepGoing |
						CXTranslationUnit_IgnoreNonErrorsFromIncludedFiles);
    if (*unit == NULL) {
        fprintf(stderr, "ERROR: unable to parse %s\n", src);
        clang_disposeIndex(*index);
        return 1;
    }
    return 0;
}

static void cleanup_ast(CXIndex index, CXTranslationUnit unit, struct para_t *para)
{
    clang_disposeTranslationUnit(para->old_tu);
    clang_disposeIndex(para->old_idx);
    clang_disposeCXCursorSet(g_visited);
    clang_disposeCXCursorSet(g_non_exported);
    clang_disposeCXCursorSet(g_type_def);
    clang_disposeCXCursorSet(g_func_inlined);
    clang_disposeCXCursorSet(g_non_included);
    clang_disposeTranslationUnit(unit);
    clang_disposeIndex(index);
}

/* and set g_srcbuf */
static FILE *open_output_file(CXTranslationUnit unit, char *file)
{
    char buf[MAX_FILE_NAME];
    CXFile sfile = clang_getFile(unit, file);
    g_srcbuf = clang_getFileContents(unit, sfile, NULL);

    snprintf(buf, MAX_FILE_NAME, "%s%s", file, KLPSRC_SUFFIX);
    FILE *fp = fopen(buf, "w");
    if (fp == NULL)
        perror("fopen for write source");
    return fp;
}

int main(int argc, char *argv[])
{
    /* prepare arg, patch, compiler opts info */
    struct patch_t patch = {0};
    if (parse_arg_and_patch(argc, argv, &patch))
        exit(EXIT_FAILURE);
    const char *args[COMPILER_OPTS];
    fill_compiler_opts(args, patch.objm);

    /* prepare writing the only livepatch main file */
    struct para_t para = {0};
    para.fmain = fopen(KLP_MAIN_SRC, "w");
    if (para.fmain == NULL) {
        perror("open "KLP_MAIN_SRC);
        exit(EXIT_FAILURE);
    }
    write_main_src_head(para.fmain);

    CXIndex index;
    CXTranslationUnit unit;
    CXCursor cursor;
    char *f;
    int ret = EXIT_SUCCESS;
    char buf[MAX_FILE_NAME];

    para.src_root = patch.src_root;
    para.debug_root = patch.debug_root;
    for (int i = 0; i < patch.mod_count; i++) {
        /* prepare sympos for every module */
        para.mod = patch.mods[i].mod_name;
        if (begin_mod_sympos(&para, patch.mods[i].srcs, patch.mods[i].src_count)) {
            ret = EXIT_FAILURE;
            goto out;
        }

        for (int j = 0; j < patch.mods[i].src_count; j++) {
            /* prepare parsing every source */
            para.src = patch.mods[i].srcs[j].src_name;
            para.src_idx = j;
            if ((f = fill_last_compiler_opts(patch.src_root, para.src)) == NULL) {
                ret = EXIT_FAILURE;
                goto out;
            }
            if (parse_ast(f, args, &index, &unit)) {    /* patched */
                ret = EXIT_FAILURE;
                goto out;
            }
            snprintf(buf, MAX_FILE_NAME, "%s/%s", para.src_root, para.src);
            if (parse_ast(buf, args, &para.old_idx, &para.old_tu)) {/* original */
                clang_disposeTranslationUnit(unit);
                clang_disposeIndex(index);
                ret = EXIT_FAILURE;
                goto out;
            }
            g_non_included = clang_createCXCursorSet();
            g_func_inlined = clang_createCXCursorSet();
            g_type_def = clang_createCXCursorSet();
            g_non_exported = clang_createCXCursorSet();
            g_visited = clang_createCXCursorSet();
            cursor = clang_getTranslationUnitCursor(unit);

            /*
             * Recursively walkthrough patched funcs and their callees to
             * find all used types, variables, functions, etc.
             */
            para.func_count = patch.mods[i].srcs[j].func_count;
            for (int k = 0; k < patch.mods[i].srcs[j].func_count; k++)
                para.funcs[k] = patch.mods[i].srcs[j].funcs[k];
            para.pos = patch.mods[i].srcs[j].pos;
            if (clang_visitChildren(cursor, find_used, &para)) {
                cleanup_ast(index, unit, &para);
                ret = EXIT_FAILURE;
                goto out;
            }

            /* output klp source */
            if ((para.fout = open_output_file(unit, f)) == NULL) {
                cleanup_ast(index, unit, &para);
                ret = EXIT_FAILURE;
                goto out;
            }
            (void)clang_visitChildren(cursor, output_cursors, &para);
            fclose(para.fout);

            cleanup_ast(index, unit, &para);
        }
        end_mod_sympos(&para, patch.mods[i].src_count, 0);
    }

    write_main_src_tail(para.fmain, &patch);
    gen_makefile(&patch);

out:
    fclose(para.fmain);
    end_mod_sympos(&para, 0, 1);
    exit(ret);
}
