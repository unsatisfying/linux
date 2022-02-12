#include <linux/list.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <asm/uaccess.h>	/* for copy_*_user */
#include <asm/pgtable.h>
#include <linux/sched/signal.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/sched/task.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/list.h>
#include <linux/efi.h>
#include <linux/set_memory.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/debugfs.h>
#include <linux/kasan.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/highmem.h>
#include <linux/pci.h>

#include <asm/e820/types.h>
#include <asm/pgtable.h>

#include <asm-generic/sections.h>
#include <asm/sections.h>
#include <asm/io.h>
#include <linux/pt.h>
#include <linux/pgp.h>
#include <linux/kvm_para.h>
#define MAX_SIZE 4096
static char msg[MAX_SIZE];
// static unsigned long phys_start = 0;
// static unsigned long phys_end = 0x4080000000;
unsigned long check_sum = 0;
EXPORT_SYMBOL(check_sum);
struct pgp_fail_struct {
    unsigned long addr;
    char *name;
    struct list_head list;
};
LIST_HEAD(pgp_fail_list);
EXPORT_SYMBOL(pgp_fail_list);

void ptdump_walk_pgd_level_old(struct seq_file *m, pgd_t *pgd);

int pgp_check_fail(unsigned long addr, char *name)
{
    struct pgp_fail_struct *p, *new;
    list_for_each_entry(p, &pgp_fail_list, list) {
        if(addr == p->addr)
            return 0;
        else if(addr < p->addr) {
            new = kmalloc(sizeof(struct pgp_fail_struct), GFP_KERNEL);
            new->addr = addr;
            new->name = name;
            if(!new)
                panic("cannot alloc pgp fail struct\n");
            list_add_tail(&(new->list), &(p->list));
            return 0;
        }
    }
    new = kmalloc(sizeof(struct pgp_fail_struct), GFP_KERNEL);
    new->addr = addr;
    new->name = name;
    if(!new)
        panic("cannot alloc pgp fail struct\n");
    list_add_tail(&(new->list), &pgp_fail_list);
    return 0;
}


int check_pgt_region(void)
{
    struct task_struct *process, *task;
    struct mm_struct *mm;
    pgd_t *pgdp;
    struct pgp_fail_struct *p;
    int cnt = 0;
    check_sum=0;
    while(p = list_first_entry_or_null(&pgp_fail_list, struct pgp_fail_struct, list)) {
        list_del(&(p->list));
        kfree(p);
    }
    for_each_process_thread(process, task) {
        get_task_struct(task);
        mm = task->mm;
        if(mm != NULL) {
            down_read(&mm->mmap_sem);
            pgdp = mm->pgd;
            if(pgdp)
                ptdump_walk_pgd_level_old(NULL,pgdp);
                //check_pgd(pgdp);
            up_read(&mm->mmap_sem);
        }
        mm = task->active_mm;
        if(mm != NULL){
            down_read(&mm->mmap_sem);
            pgdp = mm->pgd;
            if(pgdp)    
                ptdump_walk_pgd_level_old(NULL,pgdp); 
            up_read(&mm->mmap_sem);
        }
        put_task_struct(task);
    }
#if defined(CONFIG_EFI) && defined(CONFIG_X86_64)
    down_read(&efi_mm.mmap_sem);
    pgdp = efi_mm.pgd;
    if(pgdp)
        ptdump_walk_pgd_level_old(NULL,pgdp);
        //check_pgd(pgdp);
    up_read(&efi_mm.mmap_sem);
#endif
    list_for_each_entry(p, &pgp_fail_list, list) {
        printk("[PGP WARNING CHECK] addr: 0x%016lx, name: %s\n", p->addr, p->name);
        cnt ++;
    }
    printk("[PGP WARNING CHECK] total fail: %d, check pages: %ld\n", cnt, check_sum);
    while(p = list_first_entry_or_null(&pgp_fail_list, struct pgp_fail_struct, list)) {
        list_del(&(p->list));
        kfree(p);
    }
    check_sum = 0;
    cnt =0 ;
    ptdump_walk_pgd_level_old(NULL,swapper_pg_dir);
    list_for_each_entry(p, &pgp_fail_list, list) {
        printk("[PGP WARNING CHECK] addr: 0x%016lx, name: %s\n", p->addr, p->name);
        cnt ++;
    }
    printk("[PGP WARNING CHECK] total fail: %d, check pages: %ld\n", cnt, check_sum);
    while(p = list_first_entry_or_null(&pgp_fail_list, struct pgp_fail_struct, list)) {
        list_del(&(p->list));
        kfree(p);
    }
	//printk("[PGP WARNING CHECK] pgcnt: %d,alloc_cnt: %ld,free_cnt: %ld\n", pgcnt, alloc_cnt, free_cnt);

    return 0;
}






/*
 * The dumper groups pagetable entries of the same type into one, and for
 * that it needs to keep some state when walking, and flush this state
 * when a "break" in the continuity is found.
 */
struct pg_state {
	int level;
	pgprot_t current_prot;
	pgprotval_t effective_prot;
	unsigned long start_address;
	unsigned long current_address;
	const struct addr_marker *marker;
	unsigned long lines;
	bool to_dmesg;
	bool check_wx;
	unsigned long wx_pages;
};

struct addr_marker {
	unsigned long start_address;
	const char *name;
	unsigned long max_lines;
};

/* Address space markers hints */

#ifdef CONFIG_X86_64

enum address_markers_idx {
	USER_SPACE_NR = 0,
	KERNEL_SPACE_NR,
#ifdef CONFIG_MODIFY_LDT_SYSCALL
	LDT_NR,
#endif
	LOW_KERNEL_NR,
	VMALLOC_START_NR,
	VMEMMAP_START_NR,
#ifdef CONFIG_KASAN
	KASAN_SHADOW_START_NR,
	KASAN_SHADOW_END_NR,
#endif
	CPU_ENTRY_AREA_NR,
#ifdef CONFIG_X86_ESPFIX64
	ESPFIX_START_NR,
#endif
#ifdef CONFIG_EFI
	EFI_END_NR,
#endif
	HIGH_KERNEL_NR,
	MODULES_VADDR_NR,
	MODULES_END_NR,
	FIXADDR_START_NR,
	END_OF_SPACE_NR,
};

static struct addr_marker address_markers[] = {
	[USER_SPACE_NR]		= { 0,			"User Space" },
	[KERNEL_SPACE_NR]	= { (1UL << 63),	"Kernel Space" },
	[LOW_KERNEL_NR]		= { 0UL,		"Low Kernel Mapping" },
	[VMALLOC_START_NR]	= { 0UL,		"vmalloc() Area" },
	[VMEMMAP_START_NR]	= { 0UL,		"Vmemmap" },
#ifdef CONFIG_KASAN
	/*
	 * These fields get initialized with the (dynamic)
	 * KASAN_SHADOW_{START,END} values in pt_dump_init().
	 */
	[KASAN_SHADOW_START_NR]	= { 0UL,		"KASAN shadow" },
	[KASAN_SHADOW_END_NR]	= { 0UL,		"KASAN shadow end" },
#endif
#ifdef CONFIG_MODIFY_LDT_SYSCALL
	[LDT_NR]		= { 0UL,		"LDT remap" },
#endif
	[CPU_ENTRY_AREA_NR]	= { CPU_ENTRY_AREA_BASE,"CPU entry Area" },
#ifdef CONFIG_X86_ESPFIX64
	[ESPFIX_START_NR]	= { ESPFIX_BASE_ADDR,	"ESPfix Area", 16 },
#endif
#ifdef CONFIG_EFI
	[EFI_END_NR]		= { EFI_VA_END,		"EFI Runtime Services" },
#endif
	[HIGH_KERNEL_NR]	= { __START_KERNEL_map,	"High Kernel Mapping" },
	[MODULES_VADDR_NR]	= { MODULES_VADDR,	"Modules" },
	[MODULES_END_NR]	= { MODULES_END,	"End Modules" },
	[FIXADDR_START_NR]	= { FIXADDR_START,	"Fixmap Area" },
	[END_OF_SPACE_NR]	= { -1,			NULL }
};

#define INIT_PGD	((pgd_t *) &init_top_pgt)

#else /* CONFIG_X86_64 */

enum address_markers_idx {
	USER_SPACE_NR = 0,
	KERNEL_SPACE_NR,
	VMALLOC_START_NR,
	VMALLOC_END_NR,
#ifdef CONFIG_HIGHMEM
	PKMAP_BASE_NR,
#endif
#ifdef CONFIG_MODIFY_LDT_SYSCALL
	LDT_NR,
#endif
	CPU_ENTRY_AREA_NR,
	FIXADDR_START_NR,
	END_OF_SPACE_NR,
};

static struct addr_marker address_markers[] = {
	[USER_SPACE_NR]		= { 0,			"User Space" },
	[KERNEL_SPACE_NR]	= { PAGE_OFFSET,	"Kernel Mapping" },
	[VMALLOC_START_NR]	= { 0UL,		"vmalloc() Area" },
	[VMALLOC_END_NR]	= { 0UL,		"vmalloc() End" },
#ifdef CONFIG_HIGHMEM
	[PKMAP_BASE_NR]		= { 0UL,		"Persistent kmap() Area" },
#endif
#ifdef CONFIG_MODIFY_LDT_SYSCALL
	[LDT_NR]		= { 0UL,		"LDT remap" },
#endif
	[CPU_ENTRY_AREA_NR]	= { 0UL,		"CPU entry area" },
	[FIXADDR_START_NR]	= { 0UL,		"Fixmap area" },
	[END_OF_SPACE_NR]	= { -1,			NULL }
};

#define INIT_PGD	(swapper_pg_dir)

#endif /* !CONFIG_X86_64 */

/* Multipliers for offsets within the PTEs */
#define PTE_LEVEL_MULT (PAGE_SIZE)
#define PMD_LEVEL_MULT (PTRS_PER_PTE * PTE_LEVEL_MULT)
#define PUD_LEVEL_MULT (PTRS_PER_PMD * PMD_LEVEL_MULT)
#define P4D_LEVEL_MULT (PTRS_PER_PUD * PUD_LEVEL_MULT)
#define PGD_LEVEL_MULT (PTRS_PER_P4D * P4D_LEVEL_MULT)

#define pt_dump_seq_printf(m, to_dmesg, fmt, args...)		\
({								\
	if (to_dmesg)					\
		printk(KERN_INFO fmt, ##args);			\
	else							\
		if (m)						\
			seq_printf(m, fmt, ##args);		\
})

#define pt_dump_cont_printf(m, to_dmesg, fmt, args...)		\
({								\
	if (to_dmesg)					\
		printk(KERN_CONT fmt, ##args);			\
	else							\
		if (m)						\
			seq_printf(m, fmt, ##args);		\
})

/*
 * Print a readable form of a pgprot_t to the seq_file
 */
static void printk_prot(struct seq_file *m, pgprot_t prot, int level, bool dmsg)
{
	pgprotval_t pr = pgprot_val(prot);
	static const char * const level_name[] =
		{ "cr3", "pgd", "p4d", "pud", "pmd", "pte" };

	if (!(pr & _PAGE_PRESENT)) {
		/* Not present */
		pt_dump_cont_printf(m, dmsg, "                              ");
	} else {
		if (pr & _PAGE_USER)
			pt_dump_cont_printf(m, dmsg, "USR ");
		else
			pt_dump_cont_printf(m, dmsg, "    ");
		if (pr & _PAGE_RW)
			pt_dump_cont_printf(m, dmsg, "RW ");
		else
			pt_dump_cont_printf(m, dmsg, "ro ");
		if (pr & _PAGE_PWT)
			pt_dump_cont_printf(m, dmsg, "PWT ");
		else
			pt_dump_cont_printf(m, dmsg, "    ");
		if (pr & _PAGE_PCD)
			pt_dump_cont_printf(m, dmsg, "PCD ");
		else
			pt_dump_cont_printf(m, dmsg, "    ");

		/* Bit 7 has a different meaning on level 3 vs 4 */
		if (level <= 4 && pr & _PAGE_PSE)
			pt_dump_cont_printf(m, dmsg, "PSE ");
		else
			pt_dump_cont_printf(m, dmsg, "    ");
		if ((level == 5 && pr & _PAGE_PAT) ||
		    ((level == 4 || level == 3) && pr & _PAGE_PAT_LARGE))
			pt_dump_cont_printf(m, dmsg, "PAT ");
		else
			pt_dump_cont_printf(m, dmsg, "    ");
		if (pr & _PAGE_GLOBAL)
			pt_dump_cont_printf(m, dmsg, "GLB ");
		else
			pt_dump_cont_printf(m, dmsg, "    ");
		if (pr & _PAGE_NX)
			pt_dump_cont_printf(m, dmsg, "NX ");
		else
			pt_dump_cont_printf(m, dmsg, "x  ");
	}
	pt_dump_cont_printf(m, dmsg, "%s\n", level_name[level]);
}

/*
 * On 64 bits, sign-extend the 48 bit address to 64 bit
 */
static unsigned long normalize_addr(unsigned long u)
{
	int shift;
	if (!IS_ENABLED(CONFIG_X86_64))
		return u;

	shift = 64 - (__VIRTUAL_MASK_SHIFT + 1);
	return (signed long)(u << shift) >> shift;
}

static void note_wx(struct pg_state *st)
{
	unsigned long npages;

	npages = (st->current_address - st->start_address) / PAGE_SIZE;

#ifdef CONFIG_PCI_BIOS
	/*
	 * If PCI BIOS is enabled, the PCI BIOS area is forced to WX.
	 * Inform about it, but avoid the warning.
	 */
	if (pcibios_enabled && st->start_address >= PAGE_OFFSET + BIOS_BEGIN &&
	    st->current_address <= PAGE_OFFSET + BIOS_END) {
		pr_warn_once("x86/mm: PCI BIOS W+X mapping %lu pages\n", npages);
		return;
	}
#endif
	/* Account the WX pages */
	st->wx_pages += npages;
	WARN_ONCE(__supported_pte_mask & _PAGE_NX,
		  "x86/mm: Found insecure W+X mapping at address %pS\n",
		  (void *)st->start_address);
}

/*
 * This function gets called on a break in a continuous series
 * of PTE entries; the next one is different so we need to
 * print what we collected so far.
 */
static void note_page(struct seq_file *m, struct pg_state *st,
		      pgprot_t new_prot, pgprotval_t new_eff, int level)
{
	pgprotval_t prot, cur, eff;
	static const char units[] = "BKMGTPE";

	/*
	 * If we have a "break" in the series, we need to flush the state that
	 * we have now. "break" is either changing perms, levels or
	 * address space marker.
	 */
	prot = pgprot_val(new_prot);
	cur = pgprot_val(st->current_prot);
	eff = st->effective_prot;

	if (!st->level) {
		/* First entry */
		st->current_prot = new_prot;
		st->effective_prot = new_eff;
		st->level = level;
		st->marker = address_markers;
		st->lines = 0;
		// pt_dump_seq_printf(m, st->to_dmesg, "---[ %s ]---\n",
		// 		   st->marker->name);
	} else if (prot != cur || new_eff != eff || level != st->level ||
		   st->current_address >= st->marker[1].start_address) {
		const char *unit = units;
		unsigned long delta;
		int width = sizeof(unsigned long) * 2;

		if (st->check_wx && (eff & _PAGE_RW) && !(eff & _PAGE_NX))
			note_wx(st);

		/*
		 * Now print the actual finished series
		 */
		if (!st->marker->max_lines ||
		    st->lines < st->marker->max_lines) {
			// pt_dump_seq_printf(m, st->to_dmesg,
			// 		   "0x%0*lx-0x%0*lx   ",
			// 		   width, st->start_address,
			// 		   width, st->current_address);

			delta = st->current_address - st->start_address;
			while (!(delta & 1023) && unit[1]) {
				delta >>= 10;
				unit++;
			}
			// pt_dump_cont_printf(m, st->to_dmesg, "%9lu%c ",
			// 		    delta, *unit);
			// printk_prot(m, st->current_prot, st->level,
			// 	    st->to_dmesg);
		}
		st->lines++;

		/*
		 * We print markers for special areas of address space,
		 * such as the start of vmalloc space etc.
		 * This helps in the interpretation.
		 */
		if (st->current_address >= st->marker[1].start_address) {
			if (st->marker->max_lines &&
			    st->lines > st->marker->max_lines) {
				unsigned long nskip =
					st->lines - st->marker->max_lines;
				// pt_dump_seq_printf(m, st->to_dmesg,
				// 		   "... %lu entr%s skipped ... \n",
				// 		   nskip,
				// 		   nskip == 1 ? "y" : "ies");
			}
			st->marker++;
			st->lines = 0;
			// pt_dump_seq_printf(m, st->to_dmesg, "---[ %s ]---\n",
			// 		   st->marker->name);
		}

		st->start_address = st->current_address;
		st->current_prot = new_prot;
		st->effective_prot = new_eff;
		st->level = level;
	}
}

static inline pgprotval_t effective_prot(pgprotval_t prot1, pgprotval_t prot2)
{
	return (prot1 & prot2 & (_PAGE_USER | _PAGE_RW)) |
	       ((prot1 | prot2) & _PAGE_NX);
}

static void walk_pte_level(struct seq_file *m, struct pg_state *st, pmd_t addr,
			   pgprotval_t eff_in, unsigned long P)
{
	int i;
	pte_t *pte;
	pgprotval_t prot, eff;
#ifdef CONFIG_PAGE_TABLE_PROTECTION_PTE
	pte_t *pte_tmp;
    pte_tmp=(pte_t *)pmd_page_vaddr(addr);
    check_sum++;
    if(!is_pgp_ro_page((unsigned long)pte_tmp))
        pgp_check_fail((unsigned long)pte_tmp, "pte");
#endif
	for (i = 0; i < PTRS_PER_PTE; i++) {
		st->current_address = normalize_addr(P + i * PTE_LEVEL_MULT);
		pte = pte_offset_map(&addr, st->current_address);
		prot = pte_flags(*pte);
		eff = effective_prot(eff_in, prot);
		note_page(m, st, __pgprot(prot), eff, 5);
		pte_unmap(pte);
	}
}
#ifdef CONFIG_KASAN

/*
 * This is an optimization for KASAN=y case. Since all kasan page tables
 * eventually point to the kasan_early_shadow_page we could call note_page()
 * right away without walking through lower level page tables. This saves
 * us dozens of seconds (minutes for 5-level config) while checking for
 * W+X mapping or reading kernel_page_tables debugfs file.
 */
static inline bool kasan_page_table(struct seq_file *m, struct pg_state *st,
				void *pt)
{
	if (__pa(pt) == __pa(kasan_early_shadow_pmd) ||
	    (pgtable_l5_enabled() &&
			__pa(pt) == __pa(kasan_early_shadow_p4d)) ||
	    __pa(pt) == __pa(kasan_early_shadow_pud)) {
		pgprotval_t prot = pte_flags(kasan_early_shadow_pte[0]);
		note_page(m, st, __pgprot(prot), 0, 5);
		return true;
	}
	return false;
}
#else
static inline bool kasan_page_table(struct seq_file *m, struct pg_state *st,
				void *pt)
{
	return false;
}
#endif

#if PTRS_PER_PMD > 1

static void walk_pmd_level(struct seq_file *m, struct pg_state *st, pud_t addr,
			   pgprotval_t eff_in, unsigned long P)
{
	int i;
	pmd_t *start, *pmd_start;
	pgprotval_t prot, eff;

	pmd_start = start = (pmd_t *)pud_page_vaddr(addr);
#ifdef CONFIG_PAGE_TABLE_PROTECTION_PMD
	check_sum++;
    if(!is_pgp_ro_page((unsigned long)start))
        pgp_check_fail((unsigned long)start, "pmd");
#endif
	for (i = 0; i < PTRS_PER_PMD; i++) {
		st->current_address = normalize_addr(P + i * PMD_LEVEL_MULT);
		if (!pmd_none(*start)) {
			prot = pmd_flags(*start);
			eff = effective_prot(eff_in, prot);
			if (pmd_large(*start) || !pmd_present(*start)) {
				note_page(m, st, __pgprot(prot), eff, 4);
			} else if (!kasan_page_table(m, st, pmd_start)) {
				walk_pte_level(m, st, *start, eff,
					       P + i * PMD_LEVEL_MULT);
			}
		} else
			note_page(m, st, __pgprot(0), 0, 4);
		start++;
	}
}

#else
#define walk_pmd_level(m,s,a,e,p) walk_pte_level(m,s,__pmd(pud_val(a)),e,p)
#define pud_large(a) pmd_large(__pmd(pud_val(a)))
#define pud_none(a)  pmd_none(__pmd(pud_val(a)))
#endif

#if PTRS_PER_PUD > 1

static void walk_pud_level(struct seq_file *m, struct pg_state *st, p4d_t addr,
			   pgprotval_t eff_in, unsigned long P)
{
	int i;
	pud_t *start, *pud_start;
	pgprotval_t prot, eff;

	pud_start = start = (pud_t *)p4d_page_vaddr(addr);
#ifdef CONFIG_PAGE_TABLE_PROTECTION_PUD	
	check_sum++;
    if(!is_pgp_ro_page((unsigned long)start))
        pgp_check_fail((unsigned long)start, "pud");
#endif
	for (i = 0; i < PTRS_PER_PUD; i++) {
		st->current_address = normalize_addr(P + i * PUD_LEVEL_MULT);
		if (!pud_none(*start)) {
			prot = pud_flags(*start);
			eff = effective_prot(eff_in, prot);
			if (pud_large(*start) || !pud_present(*start)) {
				note_page(m, st, __pgprot(prot), eff, 3);
			} else if (!kasan_page_table(m, st, pud_start)) {
				walk_pmd_level(m, st, *start, eff,
					       P + i * PUD_LEVEL_MULT);
			}
		} else
			note_page(m, st, __pgprot(0), 0, 3);

		start++;
	}
}

#else
#define walk_pud_level(m,s,a,e,p) walk_pmd_level(m,s,__pud(p4d_val(a)),e,p)
#define p4d_large(a) pud_large(__pud(p4d_val(a)))
#define p4d_none(a)  pud_none(__pud(p4d_val(a)))
#endif

static void walk_p4d_level(struct seq_file *m, struct pg_state *st, pgd_t addr,
			   pgprotval_t eff_in, unsigned long P)
{
	int i;
	p4d_t *start, *p4d_start;
	pgprotval_t prot, eff;

	if (PTRS_PER_P4D == 1)
		return walk_pud_level(m, st, __p4d(pgd_val(addr)), eff_in, P);

	p4d_start = start = (p4d_t *)pgd_page_vaddr(addr);
#ifdef CONFIG_PAGE_TABLE_PROTECTION_P4D
	check_sum++;
    if(!is_pgp_ro_page((unsigned long)start))
        pgp_check_fail((unsigned long)start, "p4d");
#endif
	for (i = 0; i < PTRS_PER_P4D; i++) {
		st->current_address = normalize_addr(P + i * P4D_LEVEL_MULT);
		if (!p4d_none(*start)) {
			prot = p4d_flags(*start);
			eff = effective_prot(eff_in, prot);
			if (p4d_large(*start) || !p4d_present(*start)) {
				note_page(m, st, __pgprot(prot), eff, 2);
			} else if (!kasan_page_table(m, st, p4d_start)) {
				walk_pud_level(m, st, *start, eff,
					       P + i * P4D_LEVEL_MULT);
			}
		} else
			note_page(m, st, __pgprot(0), 0, 2);

		start++;
	}
}

#define pgd_large(a) (pgtable_l5_enabled() ? pgd_large(a) : p4d_large(__p4d(pgd_val(a))))
#define pgd_none(a)  (pgtable_l5_enabled() ? pgd_none(a) : p4d_none(__p4d(pgd_val(a))))

static inline bool is_hypervisor_range(int idx)
{
#ifdef CONFIG_X86_64
	/*
	 * A hole in the beginning of kernel address space reserved
	 * for a hypervisor.
	 */
	return	(idx >= pgd_index(GUARD_HOLE_BASE_ADDR)) &&
		(idx <  pgd_index(GUARD_HOLE_END_ADDR));
#else
	return false;
#endif
}

static void ptdump_walk_pgd_level_core(struct seq_file *m, pgd_t *pgd,
				       bool checkwx, bool dmesg)
{
	pgd_t *start = INIT_PGD;
	pgprotval_t prot, eff;
	int i;
	struct pg_state st = {};

	if (pgd) {
		start = pgd;
		st.to_dmesg = dmesg;
	}

	st.check_wx = checkwx;
	if (checkwx)
		st.wx_pages = 0;
#ifdef CONFIG_PAGE_TABLE_PROTECTION_PGD	
	check_sum++;
    if(!is_pgp_ro_page((unsigned long)start))
        pgp_check_fail((unsigned long)start, "pgd");
#endif
	for (i = 0; i < PTRS_PER_PGD; i++) {
		st.current_address = normalize_addr(i * PGD_LEVEL_MULT);
		if (!pgd_none(*start) && !is_hypervisor_range(i)) {
			prot = pgd_flags(*start);
#ifdef CONFIG_X86_PAE
			eff = _PAGE_USER | _PAGE_RW;
#else
			eff = prot;
#endif
			if (pgd_large(*start) || !pgd_present(*start)) {
				note_page(m, &st, __pgprot(prot), eff, 1);
			} else {
				walk_p4d_level(m, &st, *start, eff,
					       i * PGD_LEVEL_MULT);
			}
		} else
			note_page(m, &st, __pgprot(0), 0, 1);

		cond_resched();
		start++;
	}

	/* Flush out the last page */
	st.current_address = normalize_addr(PTRS_PER_PGD*PGD_LEVEL_MULT);
	note_page(m, &st, __pgprot(0), 0, 0);
	if (!checkwx)
		return;
	if (st.wx_pages)
		pr_info("x86/mm: Checked W+X mappings: FAILED, %lu W+X pages found.\n",
			st.wx_pages);
	else
		pr_info("x86/mm: Checked W+X mappings: passed, no W+X pages found.\n");
}

void ptdump_walk_pgd_level_old(struct seq_file *m, pgd_t *pgd)
{
	ptdump_walk_pgd_level_core(m, pgd, false, true);
}





ssize_t proc_read(struct file *filp, char __user *buf, size_t count, loff_t *offp) 
{
    printk("============== module phys statics ==============\n");
    check_pgt_region();
    printk("[PGP INIT] PAGE_TABLE_PROTECTION: start_pa is 0x%016lx, start_va is 0x%016lx, size is 0x%016lx\n", PGP_RO_BUF_BASE, PGP_ROBUF_VA, PGP_ROBUF_SIZE);
    if(*offp > 0) return 0;
	return 0;
}

int pgp_set_memory_ro(unsigned long addr, int numpages)
{
	
}

int pgp_set_memory_rw(unsigned long addr, int numpages)
{
	
}
ssize_t proc_write(struct file *filp,const char *buf,size_t count,loff_t *offp)
{
    int remain, id;

	if (count > MAX_SIZE){
		count =  MAX_SIZE;
	}

    remain = count;
    while(remain != 0){
        remain = copy_from_user(msg+count-remain, buf+count-remain, remain);
    }
    
    sscanf(msg, "%d", &id);
    switch(id) {
        case SET_MEM_RO:
            pgp_set_memory_ro(PGP_ROBUF_VA, PGP_RO_PAGES);
            printk("[PGP] set PGP buffer ro\n");
            break;
        case SET_MEM_RW:
            pgp_set_memory_rw(PGP_ROBUF_VA, PGP_RO_PAGES);
            printk("[PGP] set PGP buffer rw\n");
            break;
        default:
            break;
    }
    
	return count;
}

static const struct proc_ops pgp_proc_ops = {
	/*.owner = THIS_MODULE,*/
	/*.open = pmp_module_open,*/
	.proc_read = proc_read,
	.proc_write = proc_write,
	/*.llseek = seq_lseek,*/
	/*.release = single_release,*/
};

static int __init pt_module_init(void) {
    proc_create("pt_module", 0666, NULL, &pgp_proc_ops);
	return 0;
}

static void __exit pt_module_exit(void) {
    struct pgp_fail_struct *p;
    while(p = list_first_entry_or_null(&pgp_fail_list, struct pgp_fail_struct, list)) {
        list_del(&(p->list));
        kfree(p);
    }
	remove_proc_entry("pt_module", NULL);
}

MODULE_LICENSE("GPL");
module_init(pt_module_init);
module_exit(pt_module_exit);
