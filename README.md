# KLPMAKE

Inspired by KPATCH @ https://github.com/dynup/kpatch. Many thanks!

KLPMAKE 是Linux内核热补丁制作工具，它调用编译工具链，将用户的补丁文件生成为“部分链接”的目标文件，对其中的`Livepatch Symbols -- non-exported global symbols and non-included local symbols`进行修正，最终生成符合[Livepatch module ELF format](https://www.kernel.org/doc/html/latest/livepatch/module-elf-format.html)的内核模块。

用户以内核samples/livepatch/livepatch-sample.c为模板编写补丁模块源码。KLPMAKE通过内核DWARF信息和/proc/kallsyms，可靠解析定位`Livepatch Symbols`。制作时不编译内核，不深入hacking ELF格式，也基本架构无关。

KLPMAKE小、简单、快，但不支持对内核模块打补丁。

### 用法

软件依赖：libdwarf-tools(dwarfdump) elfutils-libelf(gelf) bash

软件运行时需要获取对应当前内核的vmlinux中的DWARF信息，请确保使能了相关编译选项。在补丁模块目录下运行，
```
sudo KLPMAKE_VMLINUX=path-to-vmlinux klpmake-dir/klpmake
```
`KLPMAKE_VMLINUX`默认值为`/usr/lib/debug/lib/modules/$(uname -r)/vmlinux`。

当要打补丁的是static函数时，先运行`kallsympos`查找定位它的position，写入补丁源码文件，然后再运行`klpmake`。

`_klpmake.syms`是工具产生的`Livepatch Symbols`的position信息，需要时可进行手工查验。

### 补丁编写

为可靠地进行热补丁制作，补丁源码文件需按如下规则编写：

1. 按照对应的内核原文件，一个一个组织需要的补丁文件
2. 每个补丁文件增加一行单独的注释`//KLPMAKE 内核原文件路径名`，称为tag ，路径名是相对于内核源码树根
3. 补丁文件中有一个是主文件，集中了livepatch的所有要素
4. 引用未修改的static函数时，按原prototype进行声明，保持static关键字不变
5. 内联化了的static函数引用，可展开，也可引入原static函数定义
6. 补丁由多个文件组成时，主文件用extern声明其它文件中的补丁函数原型，其它文件中必须将补丁函数定义为全局的

以上看起来挺复杂，实际是普通模块编写中的常见问题，反复运行klpmake也可以一步步地提示解决。

### 示例

见[example](example/readme.md)。

注意：示例仅针对的是[openEuler](https://openeuler.org/)riscv64操作系统及其CONFIG_LIVEPATCH_WO_FTRACE热补丁机制。

### 局限

不支持数据类`Livepatch Symbols`。

未考虑KSYM_NAME_LEN（512）符号名长度限制，不超过200时不会有问题。

KLPMAKE依赖一些系统工具产生的信息进行分析识别，当前用到的是这些，gcc 12.3.1、ld 2.40、dwarfdump 0.7.0（DWARF v4）、kallsyms（内核6.4）。具体见程序脚本。

工具是在riscv64平台上开发和测试的，刚刚迈出一小步...

非常期待你的试用与反馈！非常欢迎hacker来指点贡献！

