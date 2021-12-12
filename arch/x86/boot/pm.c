// SPDX-License-Identifier: GPL-2.0-only
/* -*- linux-c -*- ------------------------------------------------------- *
 *
 *   Copyright (C) 1991, 1992 Linus Torvalds
 *   Copyright 2007 rPath, Inc. - All Rights Reserved
 *
 * ----------------------------------------------------------------------- */

/*
 * Prepare the machine for transition to protected mode.
 */

#include "boot.h"
#include <asm/segment.h>

/*
 * Invoke the realmode switch hook if present; otherwise
 * disable all interrupts.
 */
//如果提供了realmode 切换的hook，就调用它，不然就关中断。所谓的hook，就是说如果boot loader运行在一个hostile
//的环境下（只有当 bootloader 运行在宿主环境下（比如在 DOS 下运行 ）， hook 才会被使用），就使用其准备的hook来调用，详情看文档ttps://www.kernel.org/doc/Documentation/x86/boot.txt
// static inline void io_delay(void)
// {
//     const u16 DELAY_PORT = 0x80;
//     asm volatile("outb %%al,%0" : : "dN" (DELAY_PORT));
// }
//io_delay这个函数把al寄存器的值写入0x80的io端口，而对0x80写入任何字节都会有一毫秒的延迟，所以函数名叫io_delay.
static void realmode_switch_hook(void)
{
	if (boot_params.hdr.realmode_swtch) {
		asm volatile("lcallw *%0"
			     : : "m" (boot_params.hdr.realmode_swtch)
			     : "eax", "ebx", "ecx", "edx");
	} else {
		asm volatile("cli");//清除中断标志IF
		outb(0x80, 0x70); /* Disable NMI */
		io_delay();
	}
}

/*
 * Disable all interrupts at the legacy PIC.
 */
static void mask_all_interrupts(void)
{
	outb(0xff, 0xa1);	/* Mask all interrupts on the secondary PIC */
	io_delay();
	outb(0xfb, 0x21);	/* Mask all but cascade on the primary PIC */
	io_delay();
}

/*
 * Reset IGNNE# if asserted in the FPU.
 */
static void reset_coprocessor(void)
{
	outb(0, 0xf0);
	io_delay();
	outb(0, 0xf1);
	io_delay();
}

/*
 * Set up the GDT
 */

struct gdt_ptr {
	u16 len;
	u32 ptr;
} __attribute__((packed));

static void setup_gdt(void)
{
	/* There are machines which are known to not boot with the GDT
	   being 8-byte unaligned.  Intel recommends 16 byte alignment. */
	//这个表门道挺多的其实，主要这个是16字节对齐的， 首先在arch/x86/include/asm/segment.h中定义了
	//#define GDT_ENTRY_BOOT_CS	2
	//#define GDT_ENTRY_BOOT_DS	3
	//#define GDT_ENTRY_BOOT_TSS	4
	//所以0和1两项是空的，cs是第二项，ds是第三项，TSS是第四项，一个表项是8字节，所以是5*8=40字节，又因为是16字节对齐，所以这应该是48字节大小
	//具体GDT_ENTRY中每一段的含义是啥就看Intel手册http://www.intel.com/content/www/us/en/processors/architectures-software-developer-manuals.html
	static const u64 boot_gdt[] __attribute__((aligned(16))) = {
		/* CS: code, read/execute, 4 GB, base 0 */
		[GDT_ENTRY_BOOT_CS] = GDT_ENTRY(0xc09b, 0, 0xfffff),
		/* DS: data, read/write, 4 GB, base 0 */
		[GDT_ENTRY_BOOT_DS] = GDT_ENTRY(0xc093, 0, 0xfffff),
		/* TSS: 32-bit tss, 104 bytes, base 4096 */
		/* We only have a TSS here to keep Intel VT happy;
		   we don't actually use it for anything. */
		//其实这里设置这个TSS段就是为了让Intel CPU正确进入保护模式
		[GDT_ENTRY_BOOT_TSS] = GDT_ENTRY(0x0089, 4096, 103),
	};
	/* Xen HVM incorrectly stores a pointer to the gdt_ptr, instead
	   of the gdt_ptr contents.  Thus, make it static so it will
	   stay in memory, at least long enough that we switch to the
	   proper kernel GDT. */
	static struct gdt_ptr gdt;

	gdt.len = sizeof(boot_gdt)-1;//获取gdt的长度，即boot_gdt表的大小
	gdt.ptr = (u32)&boot_gdt + (ds() << 4);

	asm volatile("lgdtl %0" : : "m" (gdt));//然后把地址写入gdtr中
}

/*
 * Set up the IDT
 */
static void setup_idt(void)
{
	static const struct gdt_ptr null_idt = {0, 0};
	asm volatile("lidtl %0" : : "m" (null_idt));
}

/*
 * Actual invocation sequence
 */
void go_to_protected_mode(void)
{
	/* Hook before leaving real mode, also disables interrupts */
	realmode_switch_hook();

	/* Enable the A20 gate */
	//打开A20总线,函数实现在arch/x86/boot/a20.c
	//die定义在arch/x86/boot/header.S
	// die:
    // hlt
    // jmp    die
    // .size    die, .-die
	if (enable_a20()) {
		puts("A20 gate not responding, unable to boot...\n");
		die();
	}

	/* Reset coprocessor (IGNNE#) */
	//reset_coprocessor()函数如下，即复位协处理器，就是写0到端口上就行
	// outb(0, 0xf0);
	// outb(0, 0xf1);
	reset_coprocessor();

	/* Mask all interrupts in the PIC */
	//mask_all_interrupts()函数实现如下：
	// outb(0xff, 0xa1);       /* Mask all interrupts on the secondary PIC */
	// outb(0xfb, 0x21);       /* Mask all but cascade on the primary PIC */
	//就是把中断控制器的所有位置1，但是主PIC上的IRQ2是用于与从PIC交互的，所以这里没断它
	mask_all_interrupts();
	//到这里就完成了所有的准备工作，就开始正式要进入保护模式了。
	/* Actual transition to protected mode... */
	//设置IDT表，即中断描述符表
	// static void setup_idt(void)
	// {
	// 	static const struct gdt_ptr null_idt = {0, 0};
	// 	asm volatile("lidtl %0" : : "m" (null_idt));//把null_idt所指向的中断描述符表写入idt寄存器，但是这里是0，也就是没有任何中断被写入
	// }
	//这里只是一个结构体而已，结构体的实现如下：
	// struct gdt_ptr {
	// 	u16 len;
	// 	u32 ptr;
	// } __attribute__((packed));
	setup_idt();
	setup_gdt();//gdtr寄存器是48位的
	//protected_mode_jump 函数定义在 arch/x86/boot/pmjump.S
	protected_mode_jump(boot_params.hdr.code32_start,
			    (u32)&boot_params + (ds() << 4));
}
