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
};

#define PKRAM_NAME_MAX		256	/* including nul */

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

int pkram_save_page(struct pkram_stream *ps, struct page *page, short flags);
struct page *pkram_load_page(struct pkram_stream *ps, unsigned long *index,
			     short *flags);

ssize_t pkram_write(struct pkram_stream *ps, const void *buf, size_t count);
size_t pkram_read(struct pkram_stream *ps, void *buf, size_t count);

#endif /* _LINUX_PKRAM_H */
