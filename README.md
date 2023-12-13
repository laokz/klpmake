# KLPMAKE

正试验自动生成补丁源码，并增加对已加载模块打补丁、处理变量类`Livepatch Symbols`问题，所以代码有点乱、垃圾（

Inspired by KPATCH @ https://github.com/dynup/kpatch. Many thanks!

Klpmake 是Linux内核热补丁制作工具，它调用编译工具链，将用户的补丁文件生成为“部分链接”的目标文件，对其中的`Livepatch Symbols -- non-exported global symbols and non-included local symbols`进行修正，最终生成符合[Livepatch module ELF format](https://www.kernel.org/doc/html/latest/livepatch/module-elf-format.html)的内核模块。

Klpmake以内核samples/livepatch/livepatch-sample.c为模板，通过patch文件自动生成补丁模块源码。再通过内核和模块DWARF信息及/proc/kallsyms，可靠解析定位`Livepatch Symbols`。制作时不编译内核，不深入hacking ELF格式，也基本架构无关。

KLPMAKE小、简单、快。

### 用法

##### 软件依赖及编译

libdwarf(>=0.8.0) libclang elfutils-libelf(gelf) bash

不同的发行版，软件安装的目录可能不同。目前这里是openEuler的。

编译：`make`

##### 运行

软件运行时需要获取对应当前内核的vmlinux中的DWARF信息，请确保使能了相关编译选项。将补丁文件放到工作目录下，并按照klpsrc.conf.sample的样子，手工编辑一个klpsrc.conf文件，然后
```
sudo klpmake-dir/klpmake
```

Klpmake可分两步执行：
 - 一是`klpmake 1`生成补丁模块源码，之后你可以检查生成了哪些东西，是否正确，并且可以修改。这步还为下步提供一个`_klpmake.syms`文件，保存的是`Livepatch Symbols`的position信息，需要时可进行手工查验修改
 - 二是`klpmake 2`编译出二进制模块，这一步除修正`Livepatch Symbols`的ELF信息外，其它与常规模块编译相同

### 示例

见[example](example/readme.md)。示例部分这次未作修改，如果修改的话，每个示例下存放的应是klpsrc.conf和.patch两个文件。

### 局限

未考虑KSYM_NAME_LEN（512）符号名长度限制，不超过200时不会有问题。

如果vmlinux中的DWARF信息不完整或被破坏，工具将无法正常工作。

工具是在riscv64平台上开发和测试的，刚刚迈出一小步...

非常期待你的试用与反馈！非常欢迎hacker来指点贡献！

