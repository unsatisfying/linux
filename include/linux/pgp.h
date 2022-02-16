#ifndef _PGP_H
#define _PGP_H

#include <linux/types.h>
#include <asm/bug.h>
#include <asm/io.h>
#include <linux/pt.h>
#include <linux/kvm_para.h>
//#define PGP_DEBUG_ALLOCATION

extern volatile bool pgp_hyp_init;
extern unsigned long pgp_ro_buf_base;
extern unsigned long pgp_ro_buf_end;
extern unsigned long pgp_ro_buf_base_va;
extern unsigned long pgp_ro_buf_end_va;
extern bool pgp_ro_buf_ready;
extern bool pgp_vmfunc_init;

#ifdef PGP_DEBUG_ALLOCATION
extern int pgcnt;
extern long alloc_cnt;
extern long free_cnt;
#endif

/* defined in kernel/pgp.c */
#define PGP_RO_BUF_BASE pgp_ro_buf_base
#define PGP_ROBUF_VA pgp_ro_buf_base_va

#define PGP_ROBUF_SIZE (0x10000000UL)
#define PGP_RO_PAGES (PGP_ROBUF_SIZE >> PAGE_SHIFT)

#define PGP_WARNING_ALLOC() PGP_WARNING("[PGP WARNING ALLOC] %s: use normal allocator instead\n", __FUNCTION__)
#define PGP_WARNING_FREE(x) PGP_WARNING("[PGP WARNING FREE] %s: not a pgp page: 0x%016lx\n", __FUNCTION__, (unsigned long)x)
#define PGP_WARNING_SET(x) PGP_WARNING("[PGP WARNING SET] %s: not in a pgp page: 0x%016lx\n", __FUNCTION__, (unsigned long)x)


//#define __DEBUG_PAGE_TABLE_PROTECTION
#ifdef __DEBUG_PAGE_TABLE_PROTECTION
#define PGP_WARNING(format...) WARN(true, format)
#define PGP_WRITE_ONCE(addr, value) WRITE_ONCE(*(unsigned long *)addr, (unsigned long)value)
#else
#define PGP_WARNING(format...)
#define PGP_WRITE_ONCE(addr, value) pgp_write_long((unsigned long *)addr, (unsigned long)value)
#endif

#define PARAVIRT_VMFUNC
#ifdef PARAVIRT_VMFUNC
#define ASM_VMX_VMFUNC		  ".byte 0x0f, 0x01, 0xd4"
extern unsigned long pgp_rw_eptp_idx;
extern unsigned long pgp_ro_eptp_idx;
#endif

/**
 * Initialize a page list which links all pages in pgp ro buffer.
 */
void __init init_pgp_page_list(void);

/**
 * pgp_ro_alloc - alloc a page from pgp ro buffer
 * @return: struct page of the allocated page on success, NULL on failure
 *
 * Spin lock is userd and IRQ is disabled when we alloc the page.
 */
struct page *pgp_ro_alloc(void);

/**
 * pgp_ro_zalloc - alloc a page from pgp ro buffer and set the page memory to 0.
 * @return: base vitural address of the allocated page on success, NULL on failure
 *
 * Spin lock is userd and IRQ is disabled when we alloc the page.
 */
void *pgp_ro_zalloc(void);

/* 
 * pgp_ro_free - free a page to pgp ro buffer.
 * @ret: false if not a ro page to free, true if a ro page to free
 * 
 * Spin lock is userd and IRQ is disabled when we alloc the page.
 * In case of a ro page free, it should never fail.
 */
bool pgp_ro_free(void* addr);

/* 
 * pgp_memset - initialize the memory region.
 * @dst: base virtual address of the memroy region.
 * @c: the value of the byte that all memory will be initialized to.
 * @len: the length of the memory region in byte.
 * 
 * For a ro page use the jailhouse hypercall while for a normal page use the memset.
 */
void pgp_memset(void *dst, char n, size_t len);

/* 
 * pgp_memcpy - copy the content of the source memory region to the destination memory region.
 * @dst: base virtual address of the source memroy region.
 * @src: base virtual address of the destination memroy region.
 * @len: the length of the memory region in byte.
 * 
 * For a ro page use the jailhouse hypercall while for a normal page use the memcpy.
 */
void pgp_memcpy(void *dst, void *src, size_t len);

/* 
 * is_pgp_ro_page - determine whether a address is in a page from pgp ro buffer.
 * @addr: virtual address of the page.
 * @return: true if the address is in a page from pgp ro buffer.
 */
static inline bool is_pgp_ro_page(unsigned long addr)
{
	if (addr >= pgp_ro_buf_base_va && addr < pgp_ro_buf_end_va)
		return true;
	else
		return false;
}

/* 
 * pgp_write_long - write the long word to memory.
 * @addr: virtual address of the .
 * @val: value to be written.
 * 
 * For a addr from pgp ro region use the jailhouse hypercall use WRITE_ONCE otherwise.
 */

#ifdef PARAVIRT_VMFUNC
static inline u8 __vmx_vmfunc(u32 eptp, u32 func)
{
	u8 error;
	__asm __volatile(ASM_VMX_VMFUNC "; setna %0"
			 : "=q" (error) : "c" (eptp), "a" (func)
			 : "cc");
	return error;
}

static inline void pgp_write_long(unsigned long *addr, unsigned long val)
{
	if(pgp_vmfunc_init == false)
		WRITE_ONCE(*addr, val);
	else
	{
		__vmx_vmfunc(pgp_rw_eptp_idx,0);
		WRITE_ONCE(*addr, val);  
		__vmx_vmfunc(pgp_ro_eptp_idx,0);  
	}                                                                                                                                                                                                                                           
}

#else
static inline void pgp_write_long(unsigned long *addr, unsigned long val)
{
	if(pgp_hyp_init == false)
		WRITE_ONCE(*addr, val);
	else
		kvm_hypercall2(KVM_HC_WRITE_LONG, (unsigned long)(virt_to_phys(addr)), val);                                                                                                                                                                                                                                                
}

#endif

#endif // _PGP_H
