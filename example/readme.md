以下示例在openEuler 23.09 kernel 6.4.0-10.1.0.20，启用CONFIG_LIVEPATCH_WO_FTRACE热补丁机制的riscv64平台上进行了测试验证。

### netlink

补丁源码编写主要由该补丁示例。

原始补丁：[netlink: fix potential deadlock in netlink_set_err()](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?h=linux-6.4.y&id=1556ba034b95cfd4f75ea93c1a2679ae0444bba1)

补丁模块代码参照内核livepatch-sample.c的样式编写，按照KLPMAKE工具提示的信息完善，并注解在了源码中。af_netlink.c是补丁模块的主文件。

补丁模块插入内核时，报了[T11932] Could not create tracefs 'netlink_extack' directory，似与内核配置有关，无其它异常，未深入追究。

### meminfo

补丁来自KPATCH示例。加载使能补丁模块后，`cat /proc/meminfo`可以看到：

原有字符串改为大写：VMALLOCCHUNK

新增的static变量值：kpatch: 5

控制台新增内核日志：hello there!

### syscall

补丁来自KPATCH示例。加载使能补丁模块后，`uname -a`输出中带上了“.kpatch”字样。

以上示例均没有kallsyms中同名符号的情况，以后遇到再补上。

