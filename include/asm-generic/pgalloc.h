/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_GENERIC_PGALLOC_H
#define __ASM_GENERIC_PGALLOC_H

#ifdef CONFIG_PAGE_TABLE_PROTECTION
#include <linux/pgp.h>
#endif
#ifdef CONFIG_MMU

#define GFP_PGTABLE_KERNEL	(GFP_KERNEL | __GFP_ZERO)
#define GFP_PGTABLE_USER	(GFP_PGTABLE_KERNEL | __GFP_ACCOUNT)

/**
 * __pte_alloc_one_kernel - allocate a page for PTE-level kernel page table
 * @mm: the mm_struct of the current context
 *
 * This function is intended for architectures that need
 * anything beyond simple page allocation.
 *
 * Return: pointer to the allocated memory or %NULL on error
 */
static inline pte_t *__pte_alloc_one_kernel(struct mm_struct *mm)
{
#ifdef CONFIG_PAGE_TABLE_PROTECTION_PTE
	pte_t *pte;
	
	pte = (pte_t *)pgp_ro_zalloc();
	if (!pte) {
		PGP_WARNING_ALLOC();
		return (pte_t *)__get_free_page(GFP_PGTABLE_KERNEL);
	}
	return pte;
#else
	return (pte_t *)__get_free_page(GFP_PGTABLE_KERNEL);
#endif
}

#ifndef __HAVE_ARCH_PTE_ALLOC_ONE_KERNEL
/**
 * pte_alloc_one_kernel - allocate a page for PTE-level kernel page table
 * @mm: the mm_struct of the current context
 *
 * Return: pointer to the allocated memory or %NULL on error
 */
static inline pte_t *pte_alloc_one_kernel(struct mm_struct *mm)
{
	return __pte_alloc_one_kernel(mm);
}
#endif

/**
 * pte_free_kernel - free PTE-level kernel page table page
 * @mm: the mm_struct of the current context
 * @pte: pointer to the memory containing the page table
 */
static inline void pte_free_kernel(struct mm_struct *mm, pte_t *pte)
{
#ifdef CONFIG_PAGE_TABLE_PROTECTION_PTE
	if (!pgp_ro_free((void *)pte)) {
		PGP_WARNING_FREE(pte);
		free_page((unsigned long)pte);
	}
#else
	free_page((unsigned long)pte);
#endif
}

/**
 * __pte_alloc_one - allocate a page for PTE-level user page table
 * @mm: the mm_struct of the current context
 * @gfp: GFP flags to use for the allocation
 *
 * Allocates a page and runs the pgtable_pte_page_ctor().
 *
 * This function is intended for architectures that need
 * anything beyond simple page allocation or must have custom GFP flags.
 *
 * Return: `struct page` initialized as page table or %NULL on error
 */
static inline pgtable_t __pte_alloc_one(struct mm_struct *mm, gfp_t gfp)
{
	struct page *pte;
#ifdef CONFIG_PAGE_TABLE_PROTECTION_PTE
	void* ret;
	ret = pgp_ro_zalloc();
	if (!ret) {
		PGP_WARNING_ALLOC();
		pte = alloc_page(gfp);
		if(!pte)
			return NULL;
		if (!pgtable_pte_page_ctor(pte)) {
			__free_page(pte);
			return NULL;
		}
		return pte;
	}

	pte = virt_to_page(ret);
	if(!pgtable_pte_page_ctor(pte)) {
		pgp_ro_free(ret);
		return NULL;
	}
	return pte;
#else
	pte = alloc_page(gfp);
	if (!pte)
		return NULL;
	if (!pgtable_pte_page_ctor(pte)) {
		__free_page(pte);
		return NULL;
	}

	return pte;
#endif
}

#ifndef __HAVE_ARCH_PTE_ALLOC_ONE
/**
 * pte_alloc_one - allocate a page for PTE-level user page table
 * @mm: the mm_struct of the current context
 *
 * Allocates a page and runs the pgtable_pte_page_ctor().
 *
 * Return: `struct page` initialized as page table or %NULL on error
 */
static inline pgtable_t pte_alloc_one(struct mm_struct *mm)
{
	return __pte_alloc_one(mm, GFP_PGTABLE_USER);
}
#endif

/*
 * Should really implement gc for free page table pages. This could be
 * done with a reference count in struct page.
 */

/**
 * pte_free - free PTE-level user page table page
 * @mm: the mm_struct of the current context
 * @pte_page: the `struct page` representing the page table
 */
static inline void pte_free(struct mm_struct *mm, struct page *pte_page)
{
#ifdef CONFIG_PAGE_TABLE_PROTECTION_PTE
	void *pte = page_address(pte_page);
	pgtable_pte_page_dtor(pte_page);
	if(!pgp_ro_free(pte)){
		PGP_WARNING_FREE(pte);
		__free_page(pte_page);
	}
#else
	pgtable_pte_page_dtor(pte_page);
	__free_page(pte_page);
#endif
}

#endif /* CONFIG_MMU */

#endif /* __ASM_GENERIC_PGALLOC_H */
