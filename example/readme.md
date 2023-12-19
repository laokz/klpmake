以下示例在openEuler 23.09 kernel 6.4.0-10.1.0.20，启用CONFIG_LIVEPATCH_WO_FTRACE热补丁机制的x86_64、aarch64、riscv64平台上进行了测试验证。

注意：补丁模块引用了jump_label中的符号时会崩溃，如aarch64上的netlink示例，具体原因待查。表现是插入补丁模块时，在注册jump_label节中符号阶段，内核写了只读内存。

### netlink

原始补丁：[netlink: fix potential deadlock in netlink_set_err()](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?h=linux-6.4.y&id=1556ba034b95cfd4f75ea93c1a2679ae0444bba1)

补丁模块插入内核时，报了[T11932] Could not create tracefs 'netlink_extack' directory，似与内核配置有关，无其它异常，未深入追究。

### meminfo

补丁来自KPATCH示例。加载使能补丁模块后，`cat /proc/meminfo`可以看到：

原有字符串改为大写：VMALLOCCHUNK

新增的static变量值：kpatch: 5

控制台新增内核日志：hello there!

这个示例在Fedora Linux 39 (Server Edition) x86_64上也测试通过。

### syscall

补丁来自KPATCH示例。加载使能补丁模块后，`uname -a`输出中带上了“.kpatch”字样。

以上示例均没有kallsyms中同名符号的情况，以后遇到再补上。
