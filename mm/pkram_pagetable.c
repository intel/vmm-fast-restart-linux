// SPDX-License-Identifier: GPL-2.0
#include <linux/bitops.h>
#include <asm/pgtable.h>
#include <linux/pkram.h>

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
