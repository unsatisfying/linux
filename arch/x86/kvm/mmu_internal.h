/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_MMU_INTERNAL_H
#define __KVM_X86_MMU_INTERNAL_H

/* make pte_list_desc fit well in cache line */
#define PTE_LIST_EXT 3
#define PT64_SECOND_AVAIL_BITS_SHIFT 54
#define PT64_ROOT_5LEVEL 5
#define PT64_ROOT_4LEVEL 4
#define PT32_ROOT_LEVEL 2
#define PT32E_ROOT_LEVEL 3
#define PT64_LEVEL_BITS 9
#define PT_PAGE_SIZE_SHIFT 7
#define PT_PAGE_SIZE_MASK (1ULL << PT_PAGE_SIZE_SHIFT)

#define PT64_LEVEL_SHIFT(level) \
		(PAGE_SHIFT + (level - 1) * PT64_LEVEL_BITS)

#define PT64_INDEX(address, level)\
	(((address) >> PT64_LEVEL_SHIFT(level)) & ((1 << PT64_LEVEL_BITS) - 1))

#define SHADOW_PT_INDEX(addr, level) PT64_INDEX(addr, level)

#ifdef CONFIG_DYNAMIC_PHYSICAL_MASK
#define PT64_BASE_ADDR_MASK (physical_mask & ~(u64)(PAGE_SIZE-1))
#else
#define PT64_BASE_ADDR_MASK (((1ULL << 52) - 1) & ~(u64)(PAGE_SIZE-1))
#endif
#define PT64_LVL_ADDR_MASK(level) \
	(PT64_BASE_ADDR_MASK & ~((1ULL << (PAGE_SHIFT + (((level) - 1) \
						* PT64_LEVEL_BITS))) - 1))
#define PT64_SPP_SAVED_BIT      (1ULL << (PT64_SECOND_AVAIL_BITS_SHIFT + 1))
/*
 * Used by the following functions to iterate through the sptes linked by a
 * rmap.  All fields are private and not assumed to be used outside.
 */
struct rmap_iterator {
	/* private fields */
	struct pte_list_desc *desc;	/* holds the sptep if not NULL */
	int pos;			/* index of the sptep */
};

struct pte_list_desc {
	u64 *sptes[PTE_LIST_EXT];
	struct pte_list_desc *more;
};

struct kvm_shadow_walk_iterator {
	u64 addr;
	hpa_t shadow_addr;
	u64 *sptep;
	int level;
	unsigned index;
};

int is_large_pte(u64 pte);
int is_last_spte(u64 pte, int level);

u64 mmu_spte_update_no_track(u64 *sptep, u64 new_spte);

void shadow_walk_init_using_root(struct kvm_shadow_walk_iterator *iterator,
					struct kvm_vcpu *vcpu, hpa_t root,
					u64 addr);
void shadow_walk_init(struct kvm_shadow_walk_iterator *iterator,
			     struct kvm_vcpu *vcpu, u64 addr);
bool shadow_walk_okay(struct kvm_shadow_walk_iterator *iterator);

void __shadow_walk_next(struct kvm_shadow_walk_iterator *iterator,
			       u64 spte);
void shadow_walk_next(struct kvm_shadow_walk_iterator *iterator);

u64 *rmap_get_first(struct kvm_rmap_head *rmap_head,
			   struct rmap_iterator *iter);

bool spte_write_protect(u64 *sptep, bool pt_protect);

u64 *rmap_get_next(struct rmap_iterator *iter);

bool is_obsolete_sp(struct kvm *kvm, struct kvm_mmu_page *sp);

#define for_each_valid_sp(_kvm, _sp, _gfn)				\
	hlist_for_each_entry(_sp,					\
	  &(_kvm)->arch.mmu_page_hash[kvm_page_table_hashfn(_gfn)], hash_link) \
		if (is_obsolete_sp((_kvm), (_sp))) {			\
		} else

#define for_each_rmap_spte(_rmap_head_, _iter_, _spte_)			\
	for (_spte_ = rmap_get_first(_rmap_head_, _iter_);		\
	     _spte_; _spte_ = rmap_get_next(_iter_))

#define for_each_shadow_entry_using_root(_vcpu, _root, _addr, _walker)     \
	for (shadow_walk_init_using_root(&(_walker), (_vcpu),              \
					 (_root), (_addr));                \
	     shadow_walk_okay(&(_walker));			           \
	     shadow_walk_next(&(_walker)))

#define for_each_shadow_entry(_vcpu, _addr, _walker)            \
	for (shadow_walk_init(&(_walker), _vcpu, _addr);	\
	     shadow_walk_okay(&(_walker));			\
	     shadow_walk_next(&(_walker)))

bool is_mmio_spte(u64 spte);

int is_shadow_present_pte(u64 pte);

void __set_spte(u64 *sptep, u64 spte);

int mmu_topup_memory_caches(struct kvm_vcpu *vcpu);

void drop_spte(struct kvm *kvm, u64 *sptep);

int mmu_spte_clear_track_bits(u64 *sptep);

void rmap_remove(struct kvm *kvm, u64 *spte);

bool mmu_spte_update(u64 *sptep, u64 new_spte);

struct kvm_rmap_head *__gfn_to_rmap(gfn_t gfn, int level,
				    struct kvm_memory_slot *slot);

void __pte_list_remove(u64 *spte, struct kvm_rmap_head *rmap_head);

void pte_list_remove(struct kvm_rmap_head *rmap_head, u64 *sptep);

u64 __get_spte_lockless(u64 *sptep);

void pte_list_remove(struct kvm_rmap_head *rmap_head, u64 *sptep);

u64 mmu_spte_get_lockless(u64 *sptep);

unsigned kvm_page_table_hashfn(gfn_t gfn);

void mmu_spte_set(u64 *sptep, u64 new_spte);

void *mmu_memory_cache_alloc(struct kvm_mmu_memory_cache *mc);

struct pte_list_desc *mmu_alloc_pte_list_desc(struct kvm_vcpu *vcpu);

int pte_list_add(struct kvm_vcpu *vcpu, u64 *spte,
			struct kvm_rmap_head *rmap_head);

void mmu_page_add_parent_pte(struct kvm_vcpu *vcpu,
				    struct kvm_mmu_page *sp, u64 *parent_pte);
void kvm_mod_used_mmu_pages(struct kvm *kvm, unsigned long nr);

struct kvm_mmu_page *kvm_mmu_alloc_page(struct kvm_vcpu *vcpu, int direct);
#endif
