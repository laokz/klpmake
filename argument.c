/* bad yet? */
/*
 * Part of klpsrc. It gives functions parse arguments, output
 * file contents, etc.
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
#include <string.h>
#include <ctype.h>
#include "klpsrc.h"

enum arg_scope_t {
	IN_TOP,
	IN_MOD,
	IN_SRC,
	IN_FUNC,
};

int parse_arguments(struct patch_t *patch)
{
	char buf[256], key[64], value[128];
	int nmod, nsrc, nfunc, nnew, line, n;
	enum arg_scope_t scope;
	FILE *fp = fopen(KLPSRC_CONF, "r");
	if (fp == NULL) {
		fprintf(stderr, ERROR_MSG_PREFIX"error open %s\n", KLPSRC_CONF);
		return -1;
	}

	memset(patch, sizeof(struct patch_t), 0);
	scope = IN_TOP;
	line = 0;
	while (fgets(buf, 256, fp)) {
		line++;
		n = 0;
		while (buf[n] && isspace(buf[n]))
			n++;
		if ((buf[n] == '#') || (buf[n] == '\0'))
			continue;
		if (sscanf(buf, "%s %s\n", key, value) != 2) {
			fprintf(stderr, ERROR_MSG_PREFIX"error read %s at line %d\n", KLPSRC_CONF, line);
			goto err_out;
		}
		switch (scope) {
		case IN_TOP:
			if (!strcmp(key, "src-root"))
				sprintf(patch->src_root, value);
			else if (!strcmp(key, "dev-root"))
				sprintf(patch->dev_root, value);
			else if (!strcmp(key, "debug-root"))
				sprintf(patch->debug_root, value);
			else if (!strcmp(key, "module-name")) {
				nmod = 0;	/* first module */
				sprintf(patch->mods[nmod].mod_name, value);
				scope = IN_MOD;
			} else {
				fprintf(stderr, ERROR_MSG_PREFIX"expect module-name at line %d\n", line);
				goto err_out;
			}
			break;
		case IN_MOD:
			if (!strcmp(key, "src-name")) {
				nsrc = 0;	/* first source in this module */
				sprintf(patch->mods[nmod].srcs[nsrc].src_name, value);
				scope = IN_SRC;
			} else {
				fprintf(stderr, ERROR_MSG_PREFIX"expect src-name at line %d\n", line);
				goto err_out;
			}
			break;
		case IN_SRC:
			if (!strcmp(key, "func-name")) {
				nfunc = 0;	/* first func in this source */
				nnew = 0;
				sprintf(patch->mods[nmod].srcs[nsrc].funcs[nfunc], value);
				scope = IN_FUNC;
			} else {
				fprintf(stderr, ERROR_MSG_PREFIX"expect func-name at line %d\n", line);
				goto err_out;
			}
			break;
		case IN_FUNC:
			if (!strcmp(key, "func-name")) {
				nfunc++;
				sprintf(patch->mods[nmod].srcs[nsrc].funcs[nfunc], value);
			} else if (!strcmp(key, "src-name")) {
				patch->mods[nmod].srcs[nsrc].new_count = nnew;
				patch->mods[nmod].srcs[nsrc].func_count = nfunc + 1;
				nsrc++;	/* another source in this module */
				sprintf(patch->mods[nmod].srcs[nsrc].src_name, value);
				scope = IN_SRC;
			} else if (!strcmp(key, "module-name")) {
				patch->mods[nmod].srcs[nsrc].new_count = nnew;
				patch->mods[nmod].srcs[nsrc].func_count = nfunc + 1;
				patch->mods[nmod].src_count = nsrc + 1;
				nmod++;	/* another module in this config */
				sprintf(patch->mods[nmod].mod_name, value);
				scope = IN_MOD;
			} else if (!strcmp(key, "new-item")) {
				sprintf(patch->mods[nmod].srcs[nsrc].news[nnew], value);
				nnew++;
			} else {
				fprintf(stderr, ERROR_MSG_PREFIX"unexpected argument at line %d\n", line);
				goto err_out;
			}
			break;
		}
	}
	patch->mods[nmod].srcs[nsrc].new_count = nnew;
	patch->mods[nmod].srcs[nsrc].func_count = nfunc + 1;
	patch->mods[nmod].src_count = nsrc + 1;
	patch->mod_count = nmod + 1;
	fclose(fp);
	return 0;

err_out:
	fclose(fp);
	return -1;
}

void begin_main_src(FILE *fp)
{
	fprintf(fp, "// SPDX-License-Identifier: GPL-2.0-or-later\n");
	fprintf(fp, "/*\n");
	fprintf(fp, " * livepatch-sample.c - Kernel Live Patching Sample Module\n");
	fprintf(fp, " *\n");
	fprintf(fp, " * Copyright (C) 2014 Seth Jennings <sjenning@redhat.com>\n");
	fprintf(fp, " */\n");
	fprintf(fp, "#define pr_fmt(fmt) KBUILD_MODNAME \": \" fmt\n");
	fprintf(fp, "#include <linux/module.h>\n");
	fprintf(fp, "#include <linux/kernel.h>\n");
	fprintf(fp, "#include <linux/livepatch.h>\n");
}

void end_main_src(FILE *fp, struct patch_t *patch)
{
	for (int i = 0; i < patch->mod_count; i++) {
		fprintf(fp, "static struct klp_func funcs%d[] = {\n", i);
		for (int j = 0; j < patch->mods[i].src_count; j++) {
		for (int k = 0; k < patch->mods[i].srcs[j].func_count; k++) {
			fprintf(fp, "\t{\n");
			fprintf(fp, "\t\t.old_name = \"%s\",\n", patch->mods[i].srcs[j].funcs[k]);
			fprintf(fp, "\t\t.new_func = %s%s,\n", PATCHED_FUNC_PREFIX, patch->mods[i].srcs[j].funcs[k]);
			fprintf(fp, "\t\t.old_sympos = %d,\n", patch->mods[i].srcs[j].pos[k]);
			fprintf(fp, "\t},\n");
		}
		}
		fprintf(fp, "\t{ }\n};\n");
	}

	fprintf(fp, "static struct klp_object objs[] = {\n");
	for (int i = 0; i < patch->mod_count; i++) {
		fprintf(fp, "\t{\n");
		if (strcmp(patch->mods[i].mod_name, "vmlinux"))
			fprintf(fp, "\t\t.name = \"%s\",\n", patch->mods[i].mod_name);
		fprintf(fp, "\t\t.funcs = funcs%d,\n", i);
		fprintf(fp, "\t},\n");
	}
	fprintf(fp, "\t{ }\n};\n");

	fprintf(fp, "static struct klp_patch patch = {\n");
	fprintf(fp, "	.mod = THIS_MODULE,\n");
	fprintf(fp, "	.objs = objs,\n");
	fprintf(fp, "};\n");
	fprintf(fp, "static int livepatch_init(void)\n");
	fprintf(fp, "{\n");
	fprintf(fp, "#ifdef CONFIG_LIVEPATCH_WO_FTRACE\n");
	fprintf(fp, "	return klp_register_patch(&patch);\n");
	fprintf(fp, "#else\n");
	fprintf(fp, "	return klp_enable_patch(&patch);\n");
	fprintf(fp, "#endif\n");
	fprintf(fp, "}\n");
	fprintf(fp, "static void livepatch_exit(void)\n");
	fprintf(fp, "{\n");
	fprintf(fp, "#ifdef CONFIG_LIVEPATCH_WO_FTRACE\n");
	fprintf(fp, "	WARN_ON(klp_unregister_patch(&patch));\n");
	fprintf(fp, "#endif\n");
	fprintf(fp, "}\n");
	fprintf(fp, "module_init(livepatch_init);\n");
	fprintf(fp, "module_exit(livepatch_exit);\n");
	fprintf(fp, "MODULE_LICENSE(\"GPL\");\n");
	fprintf(fp, "MODULE_INFO(livepatch, \"Y\");\n");
}

void gen_makefile(struct patch_t *patch, const char *mod)
{
	char *p, buf[64];
	FILE *fp = fopen("Makefile", "w");
	if (fp == NULL) {
		perror(ERROR_MSG_PREFIX"open Makefile");
		return;
	}

	sprintf(buf, "%s", KLP_MAIN_SRC);
	p = strrchr(buf, '.');
	*p = '\0';
	fprintf(fp, "obj-m := %s.o\n", mod);
	fprintf(fp, "%s-y := %s.o ", mod, buf);
	for (int i = 0; i < patch->mod_count; i++) {
		for (int j = 0; j < patch->mods[i].src_count; j++) {
			/* the data is no used later */
			p = strrchr(patch->mods[i].srcs[j].src_name, '.');
			*p = '\0';
			p = strrchr(patch->mods[i].srcs[j].src_name, '/');
			if (!p)
				p = patch->mods[i].srcs[j].src_name;
			else
				p++;
			fprintf(fp, "%s.o ", p);
		}
	}
	fprintf(fp, "\n\nall:\n");
	fprintf(fp, "\tmake -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules\n");
	fprintf(fp, "clean:\n");
	fprintf(fp, "\tmake -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean\n");
}

/*
int main()
{
	struct patch_t patch;
	if (parse_arguments(&patch) == -1)
		return -1;
	printf("src-root=%s\n", patch.src_root);
	printf("debug-root=%s\n", patch.debug_root);
	for (int i = 0; i < patch.mod_count; i++) {
		printf("mod-name=%s\n", patch.mods[i].mod_name);
		for (int j = 0; j < patch.mods[i].src_count; j++) {
			printf("\tsrc-name=%s\n", patch.mods[i].srcs[j].src_name);
			for (int k = 0; k < patch.mods[i].srcs[j].func_count; k++) {
				printf("\t\tfunc-name=%s\n", patch.mods[i].srcs[j].funcs[k]);
			}
		}
	}
}*/