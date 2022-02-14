#include <linux/pgp.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/mm.h>
//#include <linux/pt.h>

unsigned long pgp_ro_buf_base = 0;
EXPORT_SYMBOL(pgp_ro_buf_base);
unsigned long pgp_ro_buf_end = 0;
EXPORT_SYMBOL(pgp_ro_buf_end);
unsigned long pgp_ro_buf_base_va = 0;
EXPORT_SYMBOL(pgp_ro_buf_base_va);
unsigned long pgp_ro_buf_end_va = 0;
EXPORT_SYMBOL(pgp_ro_buf_end_va);


bool pgp_ro_buf_ready = false;
EXPORT_SYMBOL(pgp_ro_buf_ready);
volatile bool pgp_hyp_init = false;
EXPORT_SYMBOL(pgp_hyp_init);


#ifdef PGP_DEBUG_ALLOCATION
int pgcnt = 0;
EXPORT_SYMBOL(pgcnt);
long alloc_cnt = 0;
EXPORT_SYMBOL(alloc_cnt);
long free_cnt = 0;
EXPORT_SYMBOL(free_cnt);
#endif

spinlock_t ro_pgp_pages_lock = __SPIN_LOCK_UNLOCKED();
LIST_HEAD(pgp_page_list);

/**
 * Initialize a page list which links all pages in pgp ro buffer.
 */
void __init init_pgp_page_list(void)
{
	unsigned long start_pfn = PFN_DOWN(pgp_ro_buf_base);
	unsigned long end_pfn = PFN_UP(pgp_ro_buf_end);
	struct page *page;
	int cnt = 0;
	memset(pgp_ro_buf_base_va, 0, PGP_ROBUF_SIZE);
	for (; start_pfn < end_pfn; start_pfn++) {
		if (pfn_valid(start_pfn)) {
			cnt ++;
			page = pfn_to_page(start_pfn);
			list_add(&page->lru, &pgp_page_list);
		}
	}
	printk("[PGP INIT]: %d available pgp ro pages in total, expect: %ld\n", cnt, PGP_RO_PAGES);
#ifdef PGP_DEBUG_ALLOCATION
	pgcnt = cnt;
#endif
}

/**
 * pgp_ro_alloc - alloc a page from pgp ro buffer
 * @return: struct page of the allocated page on success, NULL on failure
 *
 * Spin lock is userd and IRQ is disabled when we alloc the page.
 */
struct page *pgp_ro_alloc(void)
{
	unsigned long flags;
	struct page *page = NULL;

	if(!pgp_ro_buf_ready)
		goto out;
	
	spin_lock_irqsave(&ro_pgp_pages_lock, flags);
	page = list_first_entry_or_null(&pgp_page_list, struct page, lru);
	if(page != NULL) {
		list_del(&page->lru);
	}
#ifdef PGP_DEBUG_ALLOCATION
		pgcnt --;
		alloc_cnt ++;
#endif
	spin_unlock_irqrestore(&ro_pgp_pages_lock,flags);

out:
	return page;
}
EXPORT_SYMBOL(pgp_ro_alloc);

/**
 * pgp_ro_zalloc - alloc a page from pgp ro buffer and set the page memory to 0.
 * @return: base vitural address of the allocated page on success, NULL on failure
 *
 * Spin lock is userd and IRQ is disabled when we alloc the page.
 */
void *pgp_ro_zalloc(void)
{
	struct page *page;
	void *ret = NULL;
	
	page = pgp_ro_alloc();
	if(page != NULL) {
		ret = page_address(page);
		pgp_memset(ret, 0, PAGE_SIZE);
	}
	return ret;
}
EXPORT_SYMBOL(pgp_ro_zalloc);

/* 
 * pgp_ro_free - free a page to pgp ro buffer.
 * @ret: false if not a ro page to free, true if a ro page to free
 * 
 * Spin lock is userd and IRQ is disabled when we alloc the page.
 * In case of a ro page free, it should never fail.
 */
bool pgp_ro_free(void* addr)
{
	unsigned long flags;
	struct page *page = virt_to_page(addr);

	if(!is_pgp_ro_page((unsigned long)addr))
        return false;
	
	spin_lock_irqsave(&ro_pgp_pages_lock, flags);
	//pgp_memset(addr, 0, PAGE_SIZE);
	list_add(&page->lru, &pgp_page_list);
#ifdef PGP_DEBUG_ALLOCATION
	pgcnt ++;
	free_cnt ++;
#endif
	spin_unlock_irqrestore(&ro_pgp_pages_lock, flags);

	return true;
}
EXPORT_SYMBOL(pgp_ro_free);

/* 
 * pgp_memset - initialize the memory region.
 * @dst: base virtual address of the memroy region.
 * @c: the value of the byte that all memory will be initialized to.
 * @len: the length of the memory region in byte.
 * 
 * For a ro page use the jailhouse hypercall while for a normal page use the memset.
 */
void pgp_memset(void *dst, char c, size_t len)
{
	if(is_pgp_ro_page((unsigned long)dst)){
#ifdef __DEBUG_PAGE_TABLE_PROTECTION
		memset(dst, c, len);
#else
		if(pgp_hyp_init == false)
			memset(dst, c, len);
		else
			kvm_hypercall3(KVM_HC_MEMSET, (unsigned long)(virt_to_phys(dst)), c, len);
#endif
    } else {
		if(pgp_hyp_init && pgp_ro_buf_ready)
			PGP_WARNING("[PGP] pgp_memset fail at 0x%016lx", (unsigned long)(virt_to_phys(dst)));
        memset(dst, c, len);
    }
}
EXPORT_SYMBOL(pgp_memset);

/* 
 * pgp_memcpy - copy the content of the source memory region to the destination memory region.
 * @dst: base virtual address of the source memroy region.
 * @src: base virtual address of the destination memroy region.
 * @len: the length of the memory region in byte.
 * 
 * For a ro page use the jailhouse hypercall while for a normal page use the memcpy.
 */
void pgp_memcpy(void *dst, void *src, size_t len)
{
    if(is_pgp_ro_page((unsigned long)dst)){
// #ifdef __DEBUG_PAGE_TABLE_PROTECTION
// 		memcpy(dst, src, len);
// #else
		if(pgp_hyp_init == false)
			memcpy(dst, src, len);
		else
			kvm_hypercall3(KVM_HC_MEMCPY, (unsigned long)(virt_to_phys(dst)), (unsigned long)(virt_to_phys(src)), len);
// #endif
    } else {
		if(pgp_hyp_init && pgp_ro_buf_ready)
			PGP_WARNING("[PGP] pgp_memcpy fail from src 0x%016lx to dst 0x%016lx", (unsigned long)(virt_to_phys(src)), (unsigned long)(virt_to_phys(dst)));
        memcpy(dst, src, len);
    }
}
EXPORT_SYMBOL(pgp_memcpy);