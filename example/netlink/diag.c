// SPDX-License-Identifier: GPL-2.0-only
#include <linux/module.h>
//KLPMAKE net/netlink/diag.c
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <linux/netlink_diag.h>
#include <linux/rhashtable.h>

#include "/usr/src/linux-6.4.0-10.1.0.21.oe2309.riscv64/net/netlink/af_netlink.h"


// KLPMAKE 内联化了的函数，原样搬过来
static int sk_diag_put_flags(struct sock *sk, struct sk_buff *skb)
{
	struct netlink_sock *nlk = nlk_sk(sk);
	u32 flags = 0;

	if (nlk->cb_running)
		flags |= NDIAG_FLAG_CB_RUNNING;
	if (nlk->flags & NETLINK_F_RECV_PKTINFO)
		flags |= NDIAG_FLAG_PKTINFO;
	if (nlk->flags & NETLINK_F_BROADCAST_SEND_ERROR)
		flags |= NDIAG_FLAG_BROADCAST_ERROR;
	if (nlk->flags & NETLINK_F_RECV_NO_ENOBUFS)
		flags |= NDIAG_FLAG_NO_ENOBUFS;
	if (nlk->flags & NETLINK_F_LISTEN_ALL_NSID)
		flags |= NDIAG_FLAG_LISTEN_ALL_NSID;
	if (nlk->flags & NETLINK_F_CAP_ACK)
		flags |= NDIAG_FLAG_CAP_ACK;

	return nla_put_u32(skb, NETLINK_DIAG_FLAGS, flags);
}
static int sk_diag_dump_groups(struct sock *sk, struct sk_buff *nlskb)
{
	struct netlink_sock *nlk = nlk_sk(sk);

	if (nlk->groups == NULL)
		return 0;

	return nla_put(nlskb, NETLINK_DIAG_GROUPS, NLGRPSZ(nlk->ngroups),
		       nlk->groups);
}
static int sk_diag_fill(struct sock *sk, struct sk_buff *skb,
			struct netlink_diag_req *req,
			u32 portid, u32 seq, u32 flags, int sk_ino)
{
	struct nlmsghdr *nlh;
	struct netlink_diag_msg *rep;
	struct netlink_sock *nlk = nlk_sk(sk);

	nlh = nlmsg_put(skb, portid, seq, SOCK_DIAG_BY_FAMILY, sizeof(*rep),
			flags);
	if (!nlh)
		return -EMSGSIZE;

	rep = nlmsg_data(nlh);
	rep->ndiag_family	= AF_NETLINK;
	rep->ndiag_type		= sk->sk_type;
	rep->ndiag_protocol	= sk->sk_protocol;
	rep->ndiag_state	= sk->sk_state;

	rep->ndiag_ino		= sk_ino;
	rep->ndiag_portid	= nlk->portid;
	rep->ndiag_dst_portid	= nlk->dst_portid;
	rep->ndiag_dst_group	= nlk->dst_group;
	sock_diag_save_cookie(sk, rep->ndiag_cookie);

	if ((req->ndiag_show & NDIAG_SHOW_GROUPS) &&
	    sk_diag_dump_groups(sk, skb))
		goto out_nlmsg_trim;

	if ((req->ndiag_show & NDIAG_SHOW_MEMINFO) &&
	    sock_diag_put_meminfo(sk, skb, NETLINK_DIAG_MEMINFO))
		goto out_nlmsg_trim;

	if ((req->ndiag_show & NDIAG_SHOW_FLAGS) &&
	    sk_diag_put_flags(sk, skb))
		goto out_nlmsg_trim;

	nlmsg_end(skb, nlh);
	return 0;

out_nlmsg_trim:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

int livepatch___netlink_diag_dump(struct sk_buff *skb, struct netlink_callback *cb,
				int protocol, int s_num)
{
	struct rhashtable_iter *hti = (void *)cb->args[2];
	struct netlink_table *tbl = &nl_table[protocol];
	struct net *net = sock_net(skb->sk);
	struct netlink_diag_req *req;
	struct netlink_sock *nlsk;
	unsigned long flags;
	struct sock *sk;
	int num = 2;
	int ret = 0;

	req = nlmsg_data(cb->nlh);

	if (s_num > 1)
		goto mc_list;

	num--;

	if (!hti) {
		hti = kmalloc(sizeof(*hti), GFP_KERNEL);
		if (!hti)
			return -ENOMEM;

		cb->args[2] = (long)hti;
	}

	if (!s_num)
		rhashtable_walk_enter(&tbl->hash, hti);

	rhashtable_walk_start(hti);

	while ((nlsk = rhashtable_walk_next(hti))) {
		if (IS_ERR(nlsk)) {
			ret = PTR_ERR(nlsk);
			if (ret == -EAGAIN) {
				ret = 0;
				continue;
			}
			break;
		}

		sk = (struct sock *)nlsk;

		if (!net_eq(sock_net(sk), net))
			continue;

		if (sk_diag_fill(sk, skb, req,
				 NETLINK_CB(cb->skb).portid,
				 cb->nlh->nlmsg_seq,
				 NLM_F_MULTI,
				 sock_i_ino(sk)) < 0) {
			ret = 1;
			break;
		}
	}

	rhashtable_walk_stop(hti);

	if (ret)
		goto done;

	rhashtable_walk_exit(hti);
	num++;

mc_list:
	read_lock_irqsave(&nl_table_lock, flags);
	sk_for_each_bound(sk, &tbl->mc_list) {
		if (sk_hashed(sk))
			continue;
		if (!net_eq(sock_net(sk), net))
			continue;
		if (num < s_num) {
			num++;
			continue;
		}

		if (sk_diag_fill(sk, skb, req,
				 NETLINK_CB(cb->skb).portid,
				 cb->nlh->nlmsg_seq,
				 NLM_F_MULTI,
				 sock_i_ino(sk)) < 0) {
			ret = 1;
			break;
		}
		num++;
	}
	read_unlock_irqrestore(&nl_table_lock, flags);

done:
	cb->args[0] = num;

	return ret;
}
