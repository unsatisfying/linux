// SPDX-License-Identifier: GPL-2.0-only
/* -*- linux-c -*- ------------------------------------------------------- *
 *
 *   Copyright (C) 1991, 1992 Linus Torvalds
 *   Copyright 2007 rPath, Inc. - All Rights Reserved
 *   Copyright 2009 Intel Corporation; author H. Peter Anvin
 *
 * ----------------------------------------------------------------------- */

/*
 * Main module for the real-mode kernel code
 */
#include <linux/build_bug.h>

#include "boot.h"
#include "string.h"

struct boot_params boot_params __attribute__((aligned(16)));

char *HEAP = _end;
char *heap_end = _end;		/* Default end of heap = no heap */

/*
 * Copy the header into the boot parameter block.  Since this
 * screws up the old-style command line protocol, adjust by
 * filling in the new-style command line pointer instead.
 */

static void copy_boot_params(void)
{
	struct old_cmdline {
		u16 cl_magic;
		u16 cl_offset;
	};
	const struct old_cmdline * const oldcmd =
		(const struct old_cmdline *)OLD_CL_ADDRESS;

	BUILD_BUG_ON(sizeof(boot_params) != 4096);// boot_params 结构体定义在arch/x86/include/uapi/asm/bootparam.h
	memcpy(&boot_params.hdr, &hdr, sizeof(hdr)); //memcpy函数定义在copy.S中，这里利用fastcall调用规则，调用参数都存在寄存器中，不是运用堆栈传入。

	if (!boot_params.hdr.cmd_line_ptr &&
	    oldcmd->cl_magic == OLD_CL_MAGIC) {
		/* Old-style command line protocol. */
		u16 cmdline_seg;

		/* Figure out if the command line falls in the region
		   of memory that an old kernel would have copied up
		   to 0x90000... */
		if (oldcmd->cl_offset < boot_params.hdr.setup_move_size)
			cmdline_seg = ds();
		else
			cmdline_seg = 0x9000;

		boot_params.hdr.cmd_line_ptr =
			(cmdline_seg << 4) + oldcmd->cl_offset;
	}
}

/*
 * Query the keyboard lock status as given by the BIOS, and
 * set the keyboard repeat rate to maximum.  Unclear why the latter
 * is done here; this might be possible to kill off as stale code.
 */
static void keyboard_init(void)
{
	struct biosregs ireg, oreg;
	initregs(&ireg);

	ireg.ah = 0x02;		/* Get keyboard status */
	intcall(0x16, &ireg, &oreg);
	boot_params.kbd_status = oreg.al;

	ireg.ax = 0x0305;	/* Set keyboard repeat rate */
	intcall(0x16, &ireg, NULL);
}

/*
 * Get Intel SpeedStep (IST) information.
 */
static void query_ist(void)
{
	struct biosregs ireg, oreg;

	/* Some older BIOSes apparently crash on this call, so filter
	   it from machines too old to have SpeedStep at all. */
	if (cpu.level < 6)
		return;

	initregs(&ireg);
	ireg.ax  = 0xe980;	 /* IST Support */
	ireg.edx = 0x47534943;	 /* Request value */
	intcall(0x15, &ireg, &oreg);

	boot_params.ist_info.signature  = oreg.eax;
	boot_params.ist_info.command    = oreg.ebx;
	boot_params.ist_info.event      = oreg.ecx;
	boot_params.ist_info.perf_level = oreg.edx;
}

/*
 * Tell the BIOS what CPU mode we intend to run in.
 */
static void set_bios_mode(void)
{
#ifdef CONFIG_X86_64
	struct biosregs ireg;

	initregs(&ireg);
	ireg.ax = 0xec00;
	ireg.bx = 2;
	intcall(0x15, &ireg, NULL);
#endif
}

static void init_heap(void)
{
	char *stack_end;

	if (boot_params.hdr.loadflags & CAN_USE_HEAP) {
		asm("leal %P1(%%esp),%0"
		    : "=r" (stack_end) : "i" (-STACK_SIZE));	//stack_end=$esp-STACK_SIZE

		heap_end = (char *)
			((size_t)boot_params.hdr.heap_end_ptr + 0x200);	
		if (heap_end > stack_end)
			heap_end = stack_end;		//堆栈相邻，方向相反
	} else {
		/* Boot protocol 2.00 only, no heap available */
		puts("WARNING: Ancient bootloader, some functionality "
		     "may be limited!\n");
	}
}

void main(void)
{
	/* First, copy the boot header into the "zeropage" */
	copy_boot_params();

	/* Initialize the early-boot console */	//，控制台初始化，console_init()函数定义在arch/x86/boot/early_serial_console.c
	console_init();
	if (cmdline_find_option_bool("debug"))
		puts("early console in setup code\n");

	/* End of heap check */ //初始化堆，保证堆栈是没有重合，然后堆栈增长方向相反。
	init_heap();

	/* Make sure we have all the proper CPU support */	//validate_cpu()检查CPU类型，函数在arch/x86/boot/cpu.c定义
	//1）检查cpu标志，如果cpu是64位cpu，那么就设置long mode, 
	//2) 检查CPU的制造商，根据制造商的不同，设置不同的CPU选项。比如对于AMD出厂的cpu，如果不支持 SSE+SSE2，那么就禁止这些选项。
	if (validate_cpu()) {
		puts("Unable to boot - please use a kernel appropriate "
		     "for your CPU.\n");
		die();
	}

	/* Tell the BIOS what CPU mode we intend to run in. */
	set_bios_mode();

	/* Detect memory layout */ 
	//检测内存分布，有多种检测方法，逐一尝试
	//随后会在dmesg中显示内存相关的分布
	// [    0.000000] e820: BIOS-provided physical RAM map:
	// [    0.000000] BIOS-e820: [mem 0x0000000000000000-0x000000000009fbff] usable
	// [    0.000000] BIOS-e820: [mem 0x000000000009fc00-0x000000000009ffff] reserved
	// [    0.000000] BIOS-e820: [mem 0x00000000000f0000-0x00000000000fffff] reserved
	// [    0.000000] BIOS-e820: [mem 0x0000000000100000-0x000000003ffdffff] usable
	// [    0.000000] BIOS-e820: [mem 0x000000003ffe0000-0x000000003fffffff] reserved
	// [    0.000000] BIOS-e820: [mem 0x00000000fffc0000-0x00000000ffffffff] reserved
	detect_memory();

	/* Set keyboard repeat rate (why?) and query the lock flags */
	//键盘检测
	keyboard_init();

	//接下来就是系统的一些参数查询，这些有专门的编程接口ABI，查询手册就能知道。
	//把查询出来的内容放入boot_params中。
	/* Query Intel SpeedStep (IST) information */
	query_ist();

	/* Query APM information */
	//电源管理信息查询
#if defined(CONFIG_APM) || defined(CONFIG_APM_MODULE)
	query_apm_bios();
#endif

	/* Query EDD information */
	//Enhanced Disk Drive查询
#if defined(CONFIG_EDD) || defined(CONFIG_EDD_MODULE)
	query_edd();
#endif

	/* Set the video mode */
	//显示模式的初始化，函数定义在 arch/x86/boot/video.c
	set_video();

	/* Do the last things and invoke protected mode */
	go_to_protected_mode();
}
