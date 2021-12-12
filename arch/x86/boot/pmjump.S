/* SPDX-License-Identifier: GPL-2.0-only */
/* ----------------------------------------------------------------------- *
 *
 *   Copyright (C) 1991, 1992 Linus Torvalds
 *   Copyright 2007 rPath, Inc. - All Rights Reserved
 *
 * ----------------------------------------------------------------------- */

/*
 * The actual transition into protected mode
 */

#include <asm/boot.h>
#include <asm/processor-flags.h>
#include <asm/segment.h>
#include <linux/linkage.h>

	.text
	.code16

/*
 * void protected_mode_jump(u32 entrypoint, u32 bootparams);
 */
SYM_FUNC_START_NOALIGN(protected_mode_jump)
	movl	%edx, %esi		# Pointer to boot_params table，boot_params结构保存在edx寄存器中，这里把该地址放入esi寄存器

	xorl	%ebx, %ebx	#清空ebx寄存器
	movw	%cs, %bx		#把cs寄存器中的内容存入bx寄存器
	shll	$4, %ebx		
	addl	%ebx, 2f			#cs<<4+2f(这里2f就是指标号为2处的代码相对地址)，所以此时ebx寄存器内容即2处的代码地址
	jmp	1f			# Short jump to serialize on 386/486
1:

	movw	$__BOOT_DS, %cx		#把__BOOT_DS值给cx	#define __BOOT_DS		(GDT_ENTRY_BOOT_DS*8)，即cx内容就是8*2=16
	movw	$__BOOT_TSS, %di	#把 #define __BOOT_TSS		(GDT_ENTRY_BOOT_TSS*8)值给di，即di=8*4=32

	movl	%cr0, %edx		#把cr0中保护模式bit设置成1
	orb	$X86_CR0_PE, %dl	# Protected mode
	movl	%edx, %cr0		#写回cr0，正式进入保护模式

	# Transition to 32-bit mode
	.byte	0x66, 0xea		# ljmpl opcode
2:	.long	.Lin_pm32		# offset  偏移量，即下面函数.lin_pm32处的段偏移
	.word	__BOOT_CS		# segment	段描述符的索引，这里是16，这里就会跳转进入32位模式下的代码执行
SYM_FUNC_END(protected_mode_jump)

	.code32
	.section ".text32","ax"
SYM_FUNC_START_LOCAL_NOALIGN(.Lin_pm32)
	# Set up data segments for flat 32-bit mode，把所有的段寄存器都重新设置成0，除了cs寄存器因为上面我们把数据段描述符__BOOT_DS 放入了cs寄存器
	movl	%ecx, %ds
	movl	%ecx, %es
	movl	%ecx, %fs
	movl	%ecx, %gs
	movl	%ecx, %ss
	# The 32-bit code sets up its own stack, but this way we do have
	# a valid stack if some debugging hack wants to use it.
	# 这个ebx寄存器前面说了存着2处代码的内容，这一块主要是为了一些debug用的，但是这块代码只会运行一次，所以就把前面代码段设置成为栈地址，当作废物利用，反正只会执行这一次，也不影响后面代码的执行
	addl	%ebx, %esp

	# Set up TR to make Intel VT happy，前面说了di的值是32，是TSS段的索引 ，这里装载入tr寄存器，让intel CPU能够正常启动
	ltr	%di

	# Clear registers to allow for future extensions to the
	# 32-bit boot protocol，清空所有通用寄存器
	xorl	%ecx, %ecx
	xorl	%edx, %edx
	xorl	%ebx, %ebx
	xorl	%ebp, %ebp
	xorl	%edi, %edi

	# Set up LDTR to make Intel VT happy
	lldt	%cx

	jmpl	*%eax			# Jump to the 32-bit entrypoint， eax中存着内核入口地址0x100000  ，这是linux boot规范规定的  ，入口地址的代码在arch/x86/boot/compressed/head_64.S中的startup_32，这个函数在head_32.S中也有，但是根据makefile规则，会参考机器的BIT来链接相应的.S文件，我们的机器是64位，所以跳转到head_64.S中的代码。
SYM_FUNC_END(.Lin_pm32)
