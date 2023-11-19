// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * livepatch-sample.c - Kernel Live Patching Sample Module
 *
 * Copyright (C) 2014 Seth Jennings <sjenning@redhat.com>
 */
//KLPMAKE kernel/jump_label.c
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/livepatch.h>

#include <linux/memory.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/err.h>
#include <linux/static_key.h>
#include <linux/jump_label_ratelimit.h>
#include <linux/bug.h>
#include <linux/cpu.h>
#include <asm/sections.h>

struct static_key_mod {
	struct static_key_mod *next;
	struct jump_entry *entries;
	struct module *mod;
};
static inline bool static_key_linked(struct static_key *key)
{
	return key->type & JUMP_TYPE_LINKED;
}
static inline struct jump_entry *static_key_entries(struct static_key *key)
{
	WARN_ON_ONCE(key->type & JUMP_TYPE_LINKED);
	return (struct jump_entry *)(key->type & ~JUMP_TYPE_MASK);
}
static inline void static_key_clear_linked(struct static_key *key)
{
	key->type &= ~JUMP_TYPE_LINKED;
}
static void jump_label_swap(void *a, void *b, int size)
{
	long delta = (unsigned long)a - (unsigned long)b;
	struct jump_entry *jea = a;
	struct jump_entry *jeb = b;
	struct jump_entry tmp = *jea;

	jea->code	= jeb->code - delta;
	jea->target	= jeb->target - delta;
	jea->key	= jeb->key - delta;

	jeb->code	= tmp.code + delta;
	jeb->target	= tmp.target + delta;
	jeb->key	= tmp.key + delta;
}
static int jump_label_cmp(const void *a, const void *b)
{
	const struct jump_entry *jea = a;
	const struct jump_entry *jeb = b;

	/*
	 * Entrires are sorted by key.
	 */
	if (jump_entry_key(jea) < jump_entry_key(jeb))
		return -1;

	if (jump_entry_key(jea) > jump_entry_key(jeb))
		return 1;

	/*
	 * In the batching mode, entries should also be sorted by the code
	 * inside the already sorted list of entries, enabling a bsearch in
	 * the vector.
	 */
	if (jump_entry_code(jea) < jump_entry_code(jeb))
		return -1;

	if (jump_entry_code(jea) > jump_entry_code(jeb))
		return 1;

	return 0;
}
static void
jump_label_sort_entries(struct jump_entry *start, struct jump_entry *stop)
{
	unsigned long size;
	void *swapfn = NULL;

	if (IS_ENABLED(CONFIG_HAVE_ARCH_JUMP_LABEL_RELATIVE))
		swapfn = jump_label_swap;

	size = (((unsigned long)stop - (unsigned long)start)
								/ sizeof(struct jump_entry));
	sort(start, size, sizeof(struct jump_entry), jump_label_cmp, swapfn);
}
static void static_key_set_entries(struct static_key *key,
						   struct jump_entry *entries)
{
	unsigned long type;

	WARN_ON_ONCE((unsigned long)entries & JUMP_TYPE_MASK);
	type = key->type & JUMP_TYPE_MASK;
	key->entries = entries;
	key->type |= type;
}
static void static_key_set_mod(struct static_key *key,
					       struct static_key_mod *mod)
{
	unsigned long type;

	WARN_ON_ONCE((unsigned long)mod & JUMP_TYPE_MASK);
	type = key->type & JUMP_TYPE_MASK;
	key->next = mod;
	key->type |= type;
}
static inline void static_key_set_linked(struct static_key *key)
{
		key->type |= JUMP_TYPE_LINKED;
}
static inline struct static_key_mod *static_key_mod(struct static_key *key)
{
	WARN_ON_ONCE(!static_key_linked(key));
	return (struct static_key_mod *)(key->type & ~JUMP_TYPE_MASK);
}
static enum jump_label_type jump_label_type(struct jump_entry *entry)
{
	struct static_key *key = jump_entry_key(entry);
	bool enabled = static_key_enabled(key);
	bool branch = jump_entry_is_branch(entry);

	/* See the comment in linux/jump_label.h */
	return enabled ^ branch;
}
static bool jump_label_can_update(struct jump_entry *entry, bool init)
{
	/*
	 * Cannot update code that was in an init text area.
	 */
	if (!init && jump_entry_is_init(entry))
		return false;

	if (!kernel_text_address(jump_entry_code(entry))) {
		/*
		 * This skips patching built-in __exit, which
		 * is part of init_section_contains() but is
		 * not part of kernel_text_address().
		 *
		 * Skipping built-in __exit is fine since it
		 * will never be executed.
		 */
		WARN_ONCE(!jump_entry_is_init(entry),
					  "can't patch jump_label at %pS",
		  			  (void *)jump_entry_code(entry));
		return false;
	}

	return true;
}
static void __jump_label_update(struct static_key *key,
						struct jump_entry *entry,
						struct jump_entry *stop,
						bool init)
{
	for (; (entry < stop) && (jump_entry_key(entry) == key); entry++) {
		if (jump_label_can_update(entry, init))
			arch_jump_label_transform(entry, jump_label_type(entry));
	}
}

static int livepatch_jump_label_add_module(struct module *mod)
{
	struct jump_entry *iter_start = mod->jump_entries;
	struct jump_entry *iter_stop = iter_start + mod->num_jump_entries;
	struct jump_entry *iter;
	struct static_key *key = NULL;
	struct static_key_mod *jlm, *jlm2;

#ifdef CONFIG_LIVEPATCH_WO_FTRACE
	// KLPMAKE 真正修改的第一行，去掉了mod_...前的感叹号
	if (unlikely(mod_klp_rel_completed(mod)))
		return 0;
#endif

	/* if the module doesn't have jump label entries, just return */
	if (iter_start == iter_stop)
		return 0;

	jump_label_sort_entries(iter_start, iter_stop);

	for (iter = iter_start; iter < iter_stop; iter++) {
		struct static_key *iterk;
		bool in_init;

		in_init = within_module_init(jump_entry_code(iter), mod);
		jump_entry_set_init(iter, in_init);

		iterk = jump_entry_key(iter);
		if (iterk == key)
			continue;

		key = iterk;
		if (within_module((unsigned long)key, mod)) {
			static_key_set_entries(key, iter);
			continue;
		}
		jlm = kzalloc(sizeof(struct static_key_mod), GFP_KERNEL);
		if (!jlm)
			return -ENOMEM;
		if (!static_key_linked(key)) {
			jlm2 = kzalloc(sizeof(struct static_key_mod),
				       GFP_KERNEL);
			if (!jlm2) {
				kfree(jlm);
				return -ENOMEM;
			}
			preempt_disable();
			jlm2->mod = __module_address((unsigned long)key);
			preempt_enable();
			jlm2->entries = static_key_entries(key);
			jlm2->next = NULL;
			static_key_set_mod(key, jlm2);
			static_key_set_linked(key);
		}
		jlm->mod = mod;
		jlm->entries = iter;
		jlm->next = static_key_mod(key);
		static_key_set_mod(key, jlm);
		static_key_set_linked(key);

		/* Only update if we've changed from our initial state */
		if (jump_label_type(iter) != jump_label_init_type(iter))
			__jump_label_update(key, iter, iter_stop, true);
	}

	return 0;
}

static void livepatch_jump_label_del_module(struct module *mod)
{
	struct jump_entry *iter_start = mod->jump_entries;
	struct jump_entry *iter_stop = iter_start + mod->num_jump_entries;
	struct jump_entry *iter;
	struct static_key *key = NULL;
	struct static_key_mod *jlm, **prev;

#ifdef CONFIG_LIVEPATCH_WO_FTRACE
	// KLPMAKE 真正修改的第二行，去掉了mod_...前的感叹号
	if (unlikely(mod_klp_rel_completed(mod)))
		return;
#endif

	for (iter = iter_start; iter < iter_stop; iter++) {
		if (jump_entry_key(iter) == key)
			continue;

		key = jump_entry_key(iter);

		if (within_module((unsigned long)key, mod))
			continue;

		/* No memory during module load */
		if (WARN_ON(!static_key_linked(key)))
			continue;

		prev = &key->next;
		jlm = static_key_mod(key);

		while (jlm && jlm->mod != mod) {
			prev = &jlm->next;
			jlm = jlm->next;
		}

		/* No memory during module load */
		if (WARN_ON(!jlm))
			continue;

		if (prev == &key->next)
			static_key_set_mod(key, jlm->next);
		else
			*prev = jlm->next;

		kfree(jlm);

		jlm = static_key_mod(key);
		/* if only one etry is left, fold it back into the static_key */
		if (jlm->next == NULL) {
			static_key_set_entries(key, jlm->entries);
			static_key_clear_linked(key);
			kfree(jlm);
		}
	}
}

static struct klp_func funcs[] = {
	{
		.old_name = "jump_label_add_module",
		.new_func = livepatch_jump_label_add_module,
	},
	{
		.old_name = "jump_label_del_module",
		.new_func = livepatch_jump_label_del_module,
	}, { }
};

static struct klp_object objs[] = {
	{
		/* name being NULL means vmlinux */
		.funcs = funcs,
	}, { }
};

static struct klp_patch patch = {
	.mod = THIS_MODULE,
	.objs = objs,
};

static int livepatch_init(void)
{
	return klp_register_patch(&patch);
}

static void livepatch_exit(void)
{
	WARN_ON(klp_unregister_patch(&patch));
}

module_init(livepatch_init);
module_exit(livepatch_exit);
MODULE_LICENSE("GPL");
MODULE_INFO(livepatch, "Y");
