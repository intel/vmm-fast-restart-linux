// SPDX-License-Identifier: GPL-2.0
#include <linux/bitops.h>
#include <asm/pgtable.h>
#include <linux/pkram.h>

#include "internal.h"

#define pgd_none(a)  (pgtable_l5_enabled() ? pgd_none(a) : p4d_none(__p4d(pgd_val(a))))

static int note_page_rev(struct pkram_pg_state *st, unsigned long curr_size, bool present)
{
	unsigned long curr_addr = st->curr_addr;
	bool track_page = present ^ st->find_holes;

	if (!st->tracking && track_page) {
		unsigned long end_addr = curr_addr + curr_size;

		if (end_addr <= st->min_addr)
			return 1;

		st->end_addr = min(end_addr, st->max_addr);
		st->tracking = true;
	} else if (st->tracking) {
		unsigned long base, size;

		/* Continue tracking if lower bound has not been reached */
		if (track_page && curr_addr && curr_addr >= st->min_addr)
			return 0;

		if (!track_page)
			base = max(curr_addr + curr_size, st->min_addr);
		else
			base = st->min_addr;

		size = st->end_addr - base;
		st->tracking = false;

		return st->range_cb(st, base, size);
	}

	return 0;
}

static int walk_pte_level_rev(struct pkram_pg_state *st, pmd_t addr, unsigned long P)
{
	unsigned long *bitmap;
	int present;
	int i, ret;

	bitmap = __va(pmd_val(addr));
	for (i = PTRS_PER_PTE - 1; i >= 0; i--) {
		unsigned long curr_addr = P + i * PAGE_SIZE;

		if (curr_addr >= st->max_addr)
			continue;
		st->curr_addr = curr_addr;

		present = test_bit(i, bitmap);
		ret = note_page_rev(st, PAGE_SIZE, present);
		if (ret)
			break;
	}

	return ret;
}

static int walk_pmd_level_rev(struct pkram_pg_state *st, pud_t addr, unsigned long P)
{
	pmd_t *start;
	int i, ret;

	start = (pmd_t *)pud_page_vaddr(addr) + PTRS_PER_PMD - 1;
	for (i = PTRS_PER_PMD - 1; i >= 0; i--, start--) {
		unsigned long curr_addr = P + i * PMD_SIZE;

		if (curr_addr >= st->max_addr)
			continue;
		st->curr_addr = curr_addr;

		if (!pmd_none(*start)) {
			if (pmd_large(*start))
				ret = note_page_rev(st, PMD_SIZE, true);
			else
				ret = walk_pte_level_rev(st, *start, curr_addr);
		} else
			ret = note_page_rev(st, PMD_SIZE, false);
		if (ret)
			break;
	}

	return ret;
}

static int walk_pud_level_rev(struct pkram_pg_state *st, p4d_t addr, unsigned long P)
{
	pud_t *start;
	int i, ret;

	start = (pud_t *)p4d_page_vaddr(addr) + PTRS_PER_PUD - 1;
	for (i = PTRS_PER_PUD - 1; i >= 0 ; i--, start--) {
		unsigned long curr_addr = P + i * PUD_SIZE;

		if (curr_addr >= st->max_addr)
			continue;
		st->curr_addr = curr_addr;

		if (!pud_none(*start)) {
			if (pud_large(*start))
				ret = note_page_rev(st, PUD_SIZE, true);
			else
				ret = walk_pmd_level_rev(st, *start, curr_addr);
		} else
			ret = note_page_rev(st, PUD_SIZE, false);
		if (ret)
			break;
	}

	return ret;
}

static int walk_p4d_level_rev(struct pkram_pg_state *st, pgd_t addr, unsigned long P)
{
	p4d_t *start;
	int i, ret;

	if (PTRS_PER_P4D == 1)
		return walk_pud_level_rev(st, __p4d(pgd_val(addr)), P);

	start = (p4d_t *)pgd_page_vaddr(addr) + PTRS_PER_P4D - 1;
	for (i = PTRS_PER_P4D - 1; i >= 0; i--, start--) {
		unsigned long curr_addr = P + i * P4D_SIZE;

		if (curr_addr >= st->max_addr)
			continue;
		st->curr_addr = curr_addr;

		if (!p4d_none(*start)) {
			if (p4d_large(*start))
				ret = note_page_rev(st, P4D_SIZE, true);
			else
				ret = walk_pud_level_rev(st, *start, curr_addr);
		} else
			ret = note_page_rev(st, P4D_SIZE, false);
		if (ret)
			break;
	}

	return ret;
}

void pkram_walk_pgt_rev(struct pkram_pg_state *st, pgd_t *pgd)
{
	pgd_t *start;
	int i, ret;

	start = pgd + PTRS_PER_PGD - 1;
	for (i = PTRS_PER_PGD - 1; i >= 0; i--, start--) {
		unsigned long curr_addr = i * PGDIR_SIZE;

		if (curr_addr >= st->max_addr)
			continue;
		st->curr_addr = curr_addr;

		if (!pgd_none(*start))
			ret = walk_p4d_level_rev(st, *start, curr_addr);
		else
			ret = note_page_rev(st, PGDIR_SIZE, false);
		if (ret)
			break;
	}
}

static void pkram_free_pgt_walk_pmd(pud_t addr)
{
	unsigned long bitmap_pa;
	struct page *page;
	pmd_t *start;
	int i;

	start = (pmd_t *)pud_page_vaddr(addr);
	for (i = 0; i < PTRS_PER_PMD; i++, start++) {
		if (!pmd_none(*start)) {
			bitmap_pa = pte_val(pte_clrhuge(*(pte_t *)start));
			if (pmd_large(*start) && !bitmap_pa)
				continue;
			page = virt_to_page(__va(bitmap_pa));
			__free_pages_core(page, 0);
		}
	}
}

static void pkram_free_pgt_walk_pud(p4d_t addr)
{
	struct page *page;
	pud_t *start;
	int i;

	start = (pud_t *)p4d_page_vaddr(addr);
	for (i = 0; i < PTRS_PER_PUD; i++, start++) {
		if (!pud_none(*start)) {
			if (pud_large(*start)) {
				WARN_ONCE(1, "PKRAM: unexpected pud hugepage\n");
				continue;
			}
			pkram_free_pgt_walk_pmd(*start);
			page = virt_to_page(__va(pud_val(*start)));
			__free_pages_core(page, 0);
		}
	}
}

static void pkram_free_pgt_walk_p4d(pgd_t addr)
{
	struct page *page;
	p4d_t *start;
	int i;

	if (PTRS_PER_P4D == 1)
		return pkram_free_pgt_walk_pud(__p4d(pgd_val(addr)));

	start = (p4d_t *)pgd_page_vaddr(addr);
	for (i = 0; i < PTRS_PER_P4D; i++, start++) {
		if (!p4d_none(*start)) {
			if (p4d_large(*start)) {
				WARN_ONCE(1, "PKRAM: unexpected p4d hugepage\n");
				continue;
			}
			pkram_free_pgt_walk_pud(*start);
			page = virt_to_page(__va(p4d_val(*start)));
			__free_pages_core(page, 0);
		}
	}
}

/*
 * Free the pagetable passed from the previous boot.
 */
void pkram_free_pgt_walk_pgd(pgd_t *pgd)
{
	pgd_t *start = pgd;
	struct page *page;
	int i;

	for (i = 0; i < PTRS_PER_PGD; i++, start++) {
		if (!pgd_none(*start)) {
			pkram_free_pgt_walk_p4d(*start);
			page = virt_to_page(__va(pgd_val(*start)));
			__free_pages_core(page, 0);
		}
	}
}
