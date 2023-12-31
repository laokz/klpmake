# KLPMAKE

Inspired by KPATCH @ https://github.com/dynup/kpatch. Many thanks!

Klpmake is a Linux kernel livepatch making tool. It calls toolchain to make the patched source to "partial linked" object, which included `Livepatch Symbols -- non-exported global symbols and non-included local symbols`, then fixes these symbols to respect [Livepatch module ELF format](https://www.kernel.org/doc/html/latest/livepatch/module-elf-format.html) and generates a normal kernel module.

Klpmake auto-generate livepatch sources according to `samples/livepatch/livepatch-sample.c` style, based on patch file. Then resolves the `Livepatch Symbols` reliably through vmlinux/module DWARF infomation and `/proc/kallsyms`, `/proc/modules`. It doesn't compile the kernel source nor hacking the ELF too deeply, and nearly nothing architecture specific.

It's fast, simple and small, support patch kernel and loaded module.

Now klpmake mainly focused on openEuler OS.

### Usage

##### Requires and Compile

The tool relies on libdwarf(>=0.8.0), libclang, elfutils-libelf(gelf), bash and some coreutils tools. At runtime, it needs vmlinux/module source code, debuginfo files(DWARF4). The procedure for making livepatch is nearly the same as normal module making, so there must be kernel building infrastructure. Install some libraries by:

```
sudo dnf install clang-libs clang-devel libdwarf-devel elfutils-libelf-devel bash
```

Different OS distribution may have different install directory. Before making the tool, please check and modify the ugly config.h and Makefile, then,
```
make
```

Klpmake has three executes, klpmake(main entry), klpsrc, fixklp.

##### Run

Create working directory, the name will be the livepatch module name. Copy in .patch file. Then,
```
sudo klpmake-dir/klpmake -s source-tree-root -b debuginfo-tree-root
```
Source-tree-root is the root directory of source code. Debuginfo-tree-root is the root directory which contains debuginfo files, such as vmlinux, *.ko.debug.

Suggest running klpmake step by step, after each step you can check and verify the result, add hook etc. See tool usage.

### Genarated Files

- livepatch.c		livepatch main source
- *.c			    livepatch other sources
- Makefile			livepatch Makefile，they are generated by klpsrc
- *.ko              livepatch module
- _klpsrc.conf      patch basic information, generated by klpmake, used by klpsrc
- _klpmake.syms		KLPSYMs position information, generated by klpsrc, used by fixklp
- *.c.patched       patched source
- *.ko.patial       "partial linked" module, generated by kernel build tool, used by fixklp

### Examples

See [example](example/readme.md).

### Limits

- depend on strict matching in Makefile when querying source module（klpmake）
- depend on strict matching in .patch when qeurying changed functions（klpmake）
- only support one .patch file（klpmake、klpsrc）
- not support ftrace-based livepatch condition detection（klpmake、klpsrc）
- static variable defined in headers or in functions will be treated as new variable（klpsrc）
- not support patch variadic function（klpsrc）
- kernel/module binary must have DWARF4 information, have .debug_info and, .debug_aranges or .debug_ranges section（klpsrc）
- not support static variables duplicate name or duplicate with extern varaible in same source（klpsrc）
- not support duplicate name from different sources' KLPSYMs（klpsrc、fixklp）
- not considered KSYM_NAME_LEN(512) limits（klpsrc、fixklp）

+##### About DWARF information

There is concern about the reliability of DWARF information. Here list klpmake used:
- locating function symbol: DW_TAG_compile_unit DW_AT_name, DW_AT_low_pc, DW_AT_high_pc, DW_AT_ranges
- locating function symbol(only for info now): DW_TAG_subprogram DW_AT_name, DW_AT_low_pc, DW_AT_decl_line
- locating variable symbol: DW_TAG_variable DW_AT_name, DW_AT_location,  DW_AT_decl_line(only for info now )

The tool is developed and test on riscv64, and it's just on the first step...

Welcome to try and feedback. Welcome contribution.

