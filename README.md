# KLPMAKE

Inspired by KPATCH @ https://github.com/dynup/kpatch. Many thanks!

Klpmake 是Linux内核热补丁制作工具，它调用编译工具链，将用户的补丁文件生成为“部分链接”的目标文件，对其中的`Livepatch Symbols -- non-exported global symbols and non-included local symbols`进行修正，最终生成符合[Livepatch module ELF format](https://www.kernel.org/doc/html/latest/livepatch/module-elf-format.html)的内核模块。

Klpmake以内核`samples/livepatch/livepatch-sample.c`为模板，通过.patch文件自动生成补丁模块源码。再通过内核和模块DWARF信息及`/proc/kallsyms`、`/proc/modules`，可靠解析定位`Livepatch Symbols`。制作时不编译内核，不深入hacking ELF格式，也基本架构无关。

Klpmake小、简单、快，支持对内核及已加载的模块打补丁。

当前主要针对的是openEuler操作系统。

### 用法

##### 软件依赖及编译

软件依赖libdwarf(>=0.8.0)、libclang、elfutils-libelf(gelf)、bash及一些coreutils工具。运行时需要内核/模块源码、debuginfo文件（DWARF4格式）。热补丁模块制作过程与常规模块基本相同，需要内核的编译构建基础设施。一些依赖库的安装命令：

```
sudo dnf install clang-libs clang-devel libdwarf-devel elfutils-libelf-devel bash
```

不同的发行版，软件安装的目录可能不同。在编译klpmake前请检查并修改当前还很简陋的config.h和Makefile内容，然后：
```
make
```
Klpmake由klpmake（主入口）、klpsrc、fixklp三个可执行文件组成。

##### 运行

创建工作目录，目录名将作为热补丁的模块名；将补丁文件放到工作目录下，执行：
```
sudo klpmake-dir/klpmake -s source-tree-root -b debuginfo-tree-root
```
source-tree-root是源码树根目录，debuginfo-tree-root是包含debuginfo文件的根目录，如vmlinux、*.ko.debug等。

建议分步执行klpmake，这样可以检查确认每步的结果是否正确是否符合预期，并可以根据需要增加hook功能等。用法见klpmake的Usage。

### 生成的文件

- livepatch.c		补丁模块主文件
- *.c			    补丁模块其它文件
- Makefile			补丁模块Makefile，以上文件由klpsrc生成
- *.ko              最终生成的补丁模块
- _klpsrc.conf      补丁基本信息，klpmake生成，klpsrc使用
- _klpmake.syms		KLPSYMs位置信息，klpsrc生成，fixklp使用
- *.c.patched       打补丁后的源码文件
- *.ko.patial       “部分链接”的补丁，内核编译工具生成，fixklp使用

### 示例

见[example](example/readme.md)。

### 局限

- 查找源码所属模块时，依赖同目录下Makefile严格的代码模式匹配（klpmake）
- 查找修改的函数时，依赖严格的.patch代码模式匹配（klpmake）
- 只支持一个.patch文件（klpmake、klpsrc）
- 不支持检测基于ftrace livepatch机制的函数打补丁条件（klpmake、klpsrc）
- 不支持热补丁代码引用原有的const变量（klpsrc）
- 不支持热补丁代码保留有原函数内定义的static变量（klpsrc）
- 内核/模块二进制必须有DWARF4信息，有.debug_info和，.debug_aranges或.debug_ranges节（klpsrc）
- 不支持同一源文件中的static变量重名或与extern变量重名（klpsrc）
- 不支持不同源文件的non-included static符号、被补丁函数重名（klpsrc、fixklp）
- 未考虑KSYM_NAME_LEN（512）符号名长度限制（klpsrc、fixklp）

工具是在riscv64平台上开发和测试的，刚刚迈出一小步...

非常期待你的试用与反馈！非常欢迎hacker来指点贡献！
