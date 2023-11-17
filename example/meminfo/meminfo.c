// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * livepatch-sample.c - Kernel Live Patching Sample Module
 *
 * Copyright (C) 2014 Seth Jennings <sjenning@redhat.com>
 */
//KLPMAKE fs/proc/meminfo.c
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/livepatch.h>

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/mman.h>
#include <linux/mmzone.h>
#include <linux/memblock.h>
#include <linux/proc_fs.h>
#include <linux/percpu.h>
#include <linux/seq_file.h>
#include <linux/swap.h>
#include <linux/vmstat.h>
#include <linux/atomic.h>
#include <linux/vmalloc.h>
#ifdef CONFIG_CMA
#include <linux/cma.h>
#endif
#include <asm/page.h>
#include "/usr/src/linux-6.4.0-10.1.0.21.oe2309.riscv64/fs/proc/internal.h"

// KLPMAKE 新增静态变量
static int foo = 5;

// KLPMAKE 新增全局函数
void kpatch_print_message(void)
{
	if (jiffies)
		printk("hello there!\n");
}

// KLPMAKE 引用的内联化了的函数
static void show_val_kb(struct seq_file *m, const char *s, unsigned long num)
{
	seq_put_decimal_ull_width(m, s, num << (PAGE_SHIFT - 10), 8);
	seq_write(m, " kB\n", 4);
}

// KLPMAKE 引用了本文件中定义的弱全局函数，声明要去除弱属性
extern void arch_report_meminfo(struct seq_file *m);

static int livepatch_meminfo_proc_show(struct seq_file *m, void *v)
{
	struct sysinfo i;
	unsigned long committed;
	long cached;
	long available;
	unsigned long pages[NR_LRU_LISTS];
	unsigned long sreclaimable, sunreclaim;
	int lru;

	si_meminfo(&i);
	si_swapinfo(&i);
	committed = vm_memory_committed();

	cached = global_node_page_state(NR_FILE_PAGES) -
			total_swapcache_pages() - i.bufferram;
	if (cached < 0)
		cached = 0;

	for (lru = LRU_BASE; lru < NR_LRU_LISTS; lru++)
		pages[lru] = global_node_page_state(NR_LRU_BASE + lru);

	available = si_mem_available();
	sreclaimable = global_node_page_state_pages(NR_SLAB_RECLAIMABLE_B);
	sunreclaim = global_node_page_state_pages(NR_SLAB_UNRECLAIMABLE_B);

// KLPMAKE 调用新增全局函数
	kpatch_print_message();
	show_val_kb(m, "MemTotal:       ", i.totalram);
	show_val_kb(m, "MemFree:        ", i.freeram);
	show_val_kb(m, "MemAvailable:   ", available);
	show_val_kb(m, "Buffers:        ", i.bufferram);
	show_val_kb(m, "Cached:         ", cached);
	show_val_kb(m, "SwapCached:     ", total_swapcache_pages());
	show_val_kb(m, "Active:         ", pages[LRU_ACTIVE_ANON] +
					   pages[LRU_ACTIVE_FILE]);
	show_val_kb(m, "Inactive:       ", pages[LRU_INACTIVE_ANON] +
					   pages[LRU_INACTIVE_FILE]);
	show_val_kb(m, "Active(anon):   ", pages[LRU_ACTIVE_ANON]);
	show_val_kb(m, "Inactive(anon): ", pages[LRU_INACTIVE_ANON]);
	show_val_kb(m, "Active(file):   ", pages[LRU_ACTIVE_FILE]);
	show_val_kb(m, "Inactive(file): ", pages[LRU_INACTIVE_FILE]);
	show_val_kb(m, "Unevictable:    ", pages[LRU_UNEVICTABLE]);
	show_val_kb(m, "Mlocked:        ", global_zone_page_state(NR_MLOCK));

#ifdef CONFIG_HIGHMEM
	show_val_kb(m, "HighTotal:      ", i.totalhigh);
	show_val_kb(m, "HighFree:       ", i.freehigh);
	show_val_kb(m, "LowTotal:       ", i.totalram - i.totalhigh);
	show_val_kb(m, "LowFree:        ", i.freeram - i.freehigh);
#endif

#ifndef CONFIG_MMU
	show_val_kb(m, "MmapCopy:       ",
		    (unsigned long)atomic_long_read(&mmap_pages_allocated));
#endif

	show_val_kb(m, "SwapTotal:      ", i.totalswap);
	show_val_kb(m, "SwapFree:       ", i.freeswap);
#ifdef CONFIG_ZSWAP
	seq_printf(m,  "Zswap:          %8lu kB\n",
		   (unsigned long)(zswap_pool_total_size >> 10));
	seq_printf(m,  "Zswapped:       %8lu kB\n",
		   (unsigned long)atomic_read(&zswap_stored_pages) <<
		   (PAGE_SHIFT - 10));
#endif
	show_val_kb(m, "Dirty:          ",
		    global_node_page_state(NR_FILE_DIRTY));
	show_val_kb(m, "Writeback:      ",
		    global_node_page_state(NR_WRITEBACK));
	show_val_kb(m, "AnonPages:      ",
		    global_node_page_state(NR_ANON_MAPPED));
	show_val_kb(m, "Mapped:         ",
		    global_node_page_state(NR_FILE_MAPPED));
	show_val_kb(m, "Shmem:          ", i.sharedram);
	show_val_kb(m, "KReclaimable:   ", sreclaimable +
		    global_node_page_state(NR_KERNEL_MISC_RECLAIMABLE));
	show_val_kb(m, "Slab:           ", sreclaimable + sunreclaim);
	show_val_kb(m, "SReclaimable:   ", sreclaimable);
	show_val_kb(m, "SUnreclaim:     ", sunreclaim);
	seq_printf(m, "KernelStack:    %8lu kB\n",
		   global_node_page_state(NR_KERNEL_STACK_KB));
#ifdef CONFIG_SHADOW_CALL_STACK
	seq_printf(m, "ShadowCallStack:%8lu kB\n",
		   global_node_page_state(NR_KERNEL_SCS_KB));
#endif
	show_val_kb(m, "PageTables:     ",
		    global_node_page_state(NR_PAGETABLE));
	show_val_kb(m, "SecPageTables:  ",
		    global_node_page_state(NR_SECONDARY_PAGETABLE));

	show_val_kb(m, "NFS_Unstable:   ", 0);
	show_val_kb(m, "Bounce:         ",
		    global_zone_page_state(NR_BOUNCE));
	show_val_kb(m, "WritebackTmp:   ",
		    global_node_page_state(NR_WRITEBACK_TEMP));
	show_val_kb(m, "CommitLimit:    ", vm_commit_limit());
	show_val_kb(m, "Committed_AS:   ", committed);
	seq_printf(m, "VmallocTotal:   %8lu kB\n",
		   (unsigned long)VMALLOC_TOTAL >> 10);
	show_val_kb(m, "VmallocUsed:    ", vmalloc_nr_pages());
// KLPMAKE 修改原字符串
	show_val_kb(m, "VMALLOCCHUNK:   ", 0ul);
	show_val_kb(m, "Percpu:         ", pcpu_nr_pages());

#ifdef CONFIG_MEMTEST
	if (early_memtest_done) {
		unsigned long early_memtest_bad_size_kb;

		early_memtest_bad_size_kb = early_memtest_bad_size>>10;
		if (early_memtest_bad_size && !early_memtest_bad_size_kb)
			early_memtest_bad_size_kb = 1;
		/* When 0 is reported, it means there actually was a successful test */
		seq_printf(m, "EarlyMemtestBad:   %5lu kB\n", early_memtest_bad_size_kb);
	}
#endif

#ifdef CONFIG_MEMORY_FAILURE
	seq_printf(m, "HardwareCorrupted: %5lu kB\n",
		   atomic_long_read(&num_poisoned_pages) << (PAGE_SHIFT - 10));
#endif

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	show_val_kb(m, "AnonHugePages:  ",
		    global_node_page_state(NR_ANON_THPS));
	show_val_kb(m, "ShmemHugePages: ",
		    global_node_page_state(NR_SHMEM_THPS));
	show_val_kb(m, "ShmemPmdMapped: ",
		    global_node_page_state(NR_SHMEM_PMDMAPPED));
	show_val_kb(m, "FileHugePages:  ",
		    global_node_page_state(NR_FILE_THPS));
	show_val_kb(m, "FilePmdMapped:  ",
		    global_node_page_state(NR_FILE_PMDMAPPED));
#endif
// KLPMAKE 输出新增static变量值
	seq_printf(m, "kpatch: %d\n", foo);

#ifdef CONFIG_CMA
	show_val_kb(m, "CmaTotal:       ", totalcma_pages);
	show_val_kb(m, "CmaFree:        ",
		    global_zone_page_state(NR_FREE_CMA_PAGES));
#endif

	hugetlb_report_meminfo(m);

	arch_report_meminfo(m);

	return 0;
}


static struct klp_func funcs[] = {
	{
		.old_name = "meminfo_proc_show",
		.new_func = livepatch_meminfo_proc_show,
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
