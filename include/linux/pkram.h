/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PKRAM_H
#define _LINUX_PKRAM_H

#include <linux/gfp.h>
#include <linux/types.h>
#include <linux/mm_types.h>

struct pkram_node;

struct pkram_stream {
	gfp_t gfp_mask;
	struct pkram_node *node;
	struct pkram_obj *obj;

	struct pkram_link *link;		/* current link */
	unsigned int entry_idx;		/* next entry in link */

	unsigned long next_index;

	/* byte data */
	struct page *data_page;
	unsigned int data_offset;
};

#define PKRAM_NAME_MAX		256	/* including nul */

struct pkram_pg_state {
	int (*range_cb)(struct pkram_pg_state *state, unsigned long base,
			unsigned long size);
	unsigned long curr_addr;
	unsigned long end_addr;
	unsigned long min_addr;
	unsigned long max_addr;
	unsigned long min_size;
	bool tracking;
	bool find_holes;
	unsigned long retval;
};

void pkram_walk_pgt_rev(struct pkram_pg_state *st, pgd_t *pgd);

int pkram_prepare_save(struct pkram_stream *ps, const char *name,
		       gfp_t gfp_mask);
int pkram_prepare_save_obj(struct pkram_stream *ps);
void pkram_finish_save(struct pkram_stream *ps);
void pkram_finish_save_obj(struct pkram_stream *ps);
void pkram_discard_save(struct pkram_stream *ps);

int pkram_prepare_load(struct pkram_stream *ps, const char *name);
int pkram_prepare_load_obj(struct pkram_stream *ps);
void pkram_finish_load(struct pkram_stream *ps);
void pkram_finish_load_obj(struct pkram_stream *ps);

#define PKRAM_PAGE_TRANS_HUGE	0x1	/* page is a transparent hugepage */

int pkram_save_page(struct pkram_stream *ps, struct page *page, short flags);
struct page *pkram_load_page(struct pkram_stream *ps, unsigned long *index,
			     short *flags);

ssize_t pkram_write(struct pkram_stream *ps, const void *buf, size_t count);
size_t pkram_read(struct pkram_stream *ps, void *buf, size_t count);

#ifdef CONFIG_PKRAM
extern unsigned long pkram_reserved_pages;
void pkram_reserve(void);
#else
#define pkram_reserved_pages 0UL
static inline void pkram_reserve(void) { }
#endif

#endif /* _LINUX_PKRAM_H */
