# KLPMAKE

目前工具运行只需要一个.patch文件，在x86_64、aarch64上跑过了这几个示例。

Inspired by KPATCH @ https://github.com/dynup/kpatch. Many thanks!

Klpmake 是Linux内核热补丁制作工具，它调用编译工具链，将用户的补丁文件生成为“部分链接”的目标文件，对其中的`Livepatch Symbols -- non-exported global symbols and non-included local symbols`进行修正，最终生成符合[Livepatch module ELF format](https://www.kernel.org/doc/html/latest/livepatch/module-elf-format.html)的内核模块。

Klpmake以内核samples/livepatch/livepatch-sample.c为模板，通过patch文件自动生成补丁模块源码。再通过内核和模块DWARF信息及/proc/kallsyms，可靠解析定位`Livepatch Symbols`。制作时不编译内核，不深入hacking ELF格式，也基本架构无关。

KLPMAKE小、简单、快。

### 用法

##### 软件依赖及编译

libdwarf(>=0.8.0) libclang elfutils-libelf(gelf) bash

不同的发行版，软件安装的目录可能不同。在编译`make`前检查并修改config.h和Makefile中的有关内容。

##### 运行

软件运行时需要获取对应当前内核的vmlinux中的DWARF信息，请确保使能了相关编译选项。将补丁文件放到工作目录下，
```
sudo klpmake-dir/klpmake -s source-tree-root -b debuginfo-tree-root
```

### 生成的文件

- livepatch.c		补丁模块主文件
- *.c			    补丁模块其它文件
- Makefile			补丁模块Makefile，以上文件由klpsrc生成
- *.ko              最终生成的补丁模块
- _klpsrc.conf      补丁基本信息，klpmake生成，klpsrc使用
- _klpmake.syms		KLPSYM位置信息，klpsrc生成，fixklp使用
- *.c.patched       打补丁后的源码文件
- *.ko.patial       “部分链接”的补丁，内核编译工具生成，fixklp使用

### 示例

见[example](example/readme.md)。示例部分这次未作修改，如果修改的话，每个示例下存放的应是一个.patch文件。

### 局限

- 查找源码所属模块时，依赖同目录下Makefile严格的代码模式匹配（klpmake）
- 查找修改的函数时，依赖严格的.patch代码模式匹配（klpmake）
- 不支持对基于ftrace livepatch机制的系统调用打补丁（klpmake、klpsrc）
- 不支持patched函数及其inlined的被调用者引用原有的const变量（klpsrc）
- 不支持patched函数及其inlined的被调用函数参数有属性（klpsrc）
- 如果vmlinux/模块的DWARF信息不完整工具将无法工作（klpsrc）
- 未考虑hook问题（klpsrc）
- 不支持不同源文件的non-included static符号、被补丁函数重名（klpsrc、fixklp）
- 未考虑KSYM_NAME_LEN（512）符号名长度限制（klpsrc、fixklp）
- 已知报错`fatal error: '.../include/linux/kconfig.h' file not found`，报警`warning: "..."（macro）redefined`（klpsrc - clang）

工具是在riscv64平台上开发和测试的，刚刚迈出一小步...

非常期待你的试用与反馈！非常欢迎hacker来指点贡献！

