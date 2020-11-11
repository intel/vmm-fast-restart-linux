// SPDX-License-Identifier: GPL-2.0
#define __pa(x)  ((unsigned long)(x))
#define __va(x)  ((void *)((unsigned long)(x)))

#include "misc.h"
#include <asm/pgtable.h>

struct pkram_super_block {
	__u64   node_pfn;
	__u64   pgd_pfn;
};

static unsigned long long pkram_sb_pfn;
static struct pkram_super_block *pkram_sb;
static pgd_t *pkram_pgd;

struct pg_state {
	int (*range_cb)(struct pg_state *state, unsigned long base,
			unsigned long size);
	unsigned long curr_addr;
	unsigned long start_addr;
	unsigned long min_addr;
	unsigned long max_addr;
	unsigned long min_size;
	unsigned long minimum;
	bool tracking;
	bool find_holes;
};

int pkram_enabled(void)
{
	return pkram_pgd ? 1 : 0;
}

void pkram_init(void)
{
	char arg[32];

	if (cmdline_find_option("pkram", arg, sizeof(arg)) > 0) {
		if (kstrtoull(arg, 16, &pkram_sb_pfn) != 0)
			return;
	} else
		return;

	pkram_sb = (struct pkram_super_block *)(pkram_sb_pfn << PAGE_SHIFT);

	if (pkram_sb)
		pkram_pgd = (pgd_t *)(pkram_sb->pgd_pfn << PAGE_SHIFT);
}

static int note_page(struct pg_state *st, int present)
{
	unsigned long curr_addr = st->curr_addr;
	bool track_page = present ^ st->find_holes;

	if (!st->tracking && track_page) {
		if (curr_addr >= st->max_addr)
			return 1;
		/*
		 * curr_addr can be < min_addr if the page straddles the
		 * boundary
		 */
		st->start_addr = max(curr_addr, st->min_addr);
		st->tracking = true;
	} else if (st->tracking) {
		unsigned long base, size;
		int ret;

		/* Continue tracking if upper bound has not been reached */
		if (track_page && curr_addr < st->max_addr)
			return 0;

		curr_addr = min(curr_addr, st->max_addr);

		base = st->start_addr;
		size = curr_addr - st->start_addr;
		st->tracking = false;

		ret = st->range_cb(st, base, size);

		if (curr_addr == st->max_addr)
			return 1;
		else
			return ret;
	}

	return 0;
}

static int walk_pte_level(struct pg_state *st, pmd_t addr, unsigned long P)
{
	unsigned long *bitmap;
	int present;
	int i, ret;

	bitmap = __va(pmd_val(addr));
	for (i = 0; i < PTRS_PER_PTE; i++) {
		unsigned long curr_addr = P + i * PAGE_SIZE;

		if (curr_addr < st->min_addr)
			continue;
		st->curr_addr = curr_addr;
		present = test_bit(i, bitmap);
		ret = note_page(st, present);
		if (ret)
			break;
	}

	return ret;
}

static int walk_pmd_level(struct pg_state *st, pud_t addr, unsigned long P)
{
	pmd_t *start;
	int i, ret;

	start = (pmd_t *)pud_page_vaddr(addr);
	for (i = 0; i < PTRS_PER_PMD; i++, start++) {
		unsigned long curr_addr = P + i * PMD_SIZE;

		if (curr_addr + PMD_SIZE <= st->min_addr)
			continue;
		st->curr_addr = curr_addr;
		if (!pmd_none(*start)) {
			if (pmd_large(*start))
				ret = note_page(st, true);
			else
				ret = walk_pte_level(st, *start, curr_addr);
		} else
			ret = note_page(st, false);
		if (ret)
			break;
	}

	return ret;
}

static int walk_pud_level(struct pg_state *st, p4d_t addr, unsigned long P)
{
	pud_t *start;
	int i, ret;

	start = (pud_t *)p4d_page_vaddr(addr);
	for (i = 0; i < PTRS_PER_PUD; i++, start++) {
		unsigned long curr_addr = P + i * PUD_SIZE;

		if (curr_addr + PUD_SIZE <= st->min_addr)
			continue;
		st->curr_addr = curr_addr;
		if (!pud_none(*start)) {
			if (pud_large(*start))
				ret = note_page(st, true);
			else
				ret = walk_pmd_level(st, *start, curr_addr);
		} else
			ret = note_page(st, false);
		if (ret)
			break;
	}

	return ret;
}

static int walk_p4d_level(struct pg_state *st, pgd_t addr, unsigned long P)
{
	p4d_t *start;
	int i, ret;

	if (PTRS_PER_P4D == 1)
		return walk_pud_level(st, __p4d(pgd_val(addr)), P);

	start = (p4d_t *)pgd_page_vaddr(addr);
	for (i = 0; i < PTRS_PER_P4D; i++, start++) {
		unsigned long curr_addr = P + i * P4D_SIZE;

		if (curr_addr + P4D_SIZE <= st->min_addr)
			continue;
		st->curr_addr = curr_addr;
		if (!p4d_none(*start)) {
			if (p4d_large(*start))
				ret = note_page(st, true);
			else
				ret = walk_pud_level(st, *start, curr_addr);
		} else
			ret = note_page(st, false);
		if (ret)
			break;
	}

	return ret;
}

#define pgd_large(a) (pgtable_l5_enabled() ? pgd_large(a) : p4d_large(__p4d(pgd_val(a))))
#define pgd_none(a)  (pgtable_l5_enabled() ? pgd_none(a) : p4d_none(__p4d(pgd_val(a))))

static int walk_pgd_level(struct pg_state *st, pgd_t *pgd)
{
	pgd_t *start = pgd;
	int i, ret = 0;

	for (i = 0; i < PTRS_PER_PGD; i++, start++) {
		unsigned long curr_addr = i * PGDIR_SIZE;

		if (curr_addr + PGDIR_SIZE <= st->min_addr)
			continue;
		st->curr_addr = curr_addr;
		if (!pgd_none(*start))
			ret = walk_p4d_level(st, *start, curr_addr);
		else
			ret = note_page(st, false);
		if (ret)
			break;
	}

	return ret;
}

extern int slot_areas_full(void);

static int pkram_process_mem_region_cb(struct pg_state *st, unsigned long base, unsigned long size)
{
	struct mem_vector region = {
		.start = base,
		.size = size,
	};

	if (size < st->min_size)
		return 0;

	___process_mem_region(&region, st->minimum, st->min_size);

	if (slot_areas_full())
		return 1;

	return 0;
}

void pkram_process_mem_region(struct mem_vector *entry,
			     unsigned long minimum,
			     unsigned long image_size)
{
	struct pg_state st = {
		.range_cb = pkram_process_mem_region_cb,
		.min_addr = max((unsigned long)entry->start, minimum),
		.max_addr = entry->start + entry->size,
		.min_size = image_size,
		.minimum = minimum,
		.find_holes = true,
	};

	walk_pgd_level(&st, pkram_pgd);
}
