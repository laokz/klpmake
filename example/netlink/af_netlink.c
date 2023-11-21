// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * livepatch-sample.c - Kernel Live Patching Sample Module
 *    /proc/fs/nfs/exports
 * Copyright (C) 2014 Seth Jennings <sjenning@redhat.com>
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/livepatch.h>
// KLPMAKE 以上是内核livepatch-sample.c中的内容
//KLPMAKE net/netlink/af_netlink.c



// KLPMAKE 为了省事，除函数和数据定义，被补丁源文件其它内容都可以保留
#include <linux/module.h>
#include <linux/bpf.h>
#include <linux/capability.h>
#include <linux/kernel.h>
#include <linux/filter.h>
#include <linux/init.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/socket.h>
#include <linux/un.h>
#include <linux/fcntl.h>
#include <linux/termios.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/notifier.h>
#include <linux/security.h>
#include <linux/jhash.h>
#include <linux/jiffies.h>
#include <linux/random.h>
#include <linux/bitops.h>
#include <linux/mm.h>
#include <linux/types.h>
#include <linux/audit.h>
#include <linux/mutex.h>
#include <linux/vmalloc.h>
#include <linux/if_arp.h>
#include <linux/rhashtable.h>
#include <asm/cacheflush.h>
#include <linux/hash.h>
#include <linux/genetlink.h>
#include <linux/net_namespace.h>
#include <linux/nospec.h>
#include <linux/btf_ids.h>

#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/sock.h>
#include <net/scm.h>
#include <net/netlink.h>
#define CREATE_TRACE_POINTS
#include <trace/events/netlink.h>
// KLPMAKE 因为补丁是OOT模块，所以内部文件头用绝对路径
#include "/usr/src/linux-6.4.0-10.1.0.21.oe2309.riscv64/net/netlink/af_netlink.h"

struct listeners {
	struct rcu_head		rcu;
	unsigned long		masks[];
};

/* state bits */
#define NETLINK_S_CONGESTED		0x0

struct netlink_set_err_data {
	struct sock *exclude_sk;
	u32 portid;
	u32 group;
	int code;
};

// KLPMAKE klpmake提示未找到符号，可能内联化了，所以把它搬过来
static int do_one_set_err(struct sock *sk, struct netlink_set_err_data *p)
{
	struct netlink_sock *nlk = nlk_sk(sk);
	int ret = 0;

	if (sk == p->exclude_sk)
		goto out;

	if (!net_eq(sock_net(sk), sock_net(p->exclude_sk)))
		goto out;

	if (nlk->portid == p->portid || p->group - 1 >= nlk->ngroups ||
	    !test_bit(p->group - 1, nlk->groups))
		goto out;

	if (p->code == ENOBUFS && nlk->flags & NETLINK_F_RECV_NO_ENOBUFS) {
		ret = 1;
		goto out;
	}

	sk->sk_err = p->code;
	sk_error_report(sk);
out:
	return ret;
}

// KLPMAKE klpmake工具提示补丁函数引用了一个static函数，所以要将其声明，注意：保持static
static int netlink_release(struct socket *sock);

int livepatch_netlink_set_err(struct sock *ssk, u32 portid, u32 group, int code)
{
	struct netlink_set_err_data info;
// KLPMAKE 这是补丁增加的一行
	unsigned long flags;
	struct sock *sk;
	int ret = 0;

	info.exclude_sk = ssk;
	info.portid = portid;
	info.group = group;
	/* sk->sk_err wants a positive error value */
	info.code = -code;
// KLPMAKE 这是补丁修改的一行
	read_lock_irqsave(&nl_table_lock, flags);

	sk_for_each_bound(sk, &nl_table[ssk->sk_protocol].mc_list)
		ret += do_one_set_err(sk, &info);
// KLPMAKE 这是补丁修改的一行
	read_unlock_irqrestore(&nl_table_lock, flags);
// KLPMAKE 为了演示目的，增加无害/nop的non-exported global和non-included local函数调用
	netlink_policy_dump_free(NULL);
	struct socket temp = { .sk = NULL };
	netlink_release(&temp);
	return ret;
}
// KLPMAKE 原函数是exported，补丁函数不能，但引用原函数时就会跳到补丁函数
//EXPORT_SYMBOL(netlink_set_err);

// KLPMAKE 这个被补丁函数是位于另一个编译单元的static函数，我们必须将其补丁函数声明、定义成extern
extern int livepatch___netlink_diag_dump(struct sk_buff *skb, struct netlink_callback *cb, int protocol, int s_num);



// KLPMAKE 以下是内核livepatch-sample.c中的内容，仅funcs内容进行了定制
static struct klp_func funcs[] = {
	{
		.old_name = "netlink_set_err",
		.new_func = livepatch_netlink_set_err,
// KLPMAKE 被补丁函数是全局的，所以它的position是0
		.old_sympos = 0,
	},
	{
		.old_name = "__netlink_diag_dump",
		.new_func = livepatch___netlink_diag_dump,
// KLPMAKE 被补丁函数是static的，用kallsympos工具查找确定它的position
		.old_sympos = 0,
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
#ifdef CONFIG_LIVEPATCH_WO_FTRACE
	return klp_register_patch(&patch);
#else
	return klp_enable_patch(&patch);
#endif
}

static void livepatch_exit(void)
{
#ifdef CONFIG_LIVEPATCH_WO_FTRACE
	WARN_ON(klp_unregister_patch(&patch));
#endif
}

module_init(livepatch_init);
module_exit(livepatch_exit);
MODULE_LICENSE("GPL");
MODULE_INFO(livepatch, "Y");
